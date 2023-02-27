#![feature(let_chains)]

use std::ffi::CStr;

extern crate zydis;

use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use zydis::*;

pub type Pattern = [Option<u8>];

macro_rules! pattern {
    ($($elem:tt),+) => {
        &[$(pattern!(@el $elem)),+]
    };
    (@el $v:expr) => {
        Some($v)
    };
    (@el $v:tt) => {
        None
    };
}

#[inline(always)]
fn match_pattern(window: &[u8], pattern: &Pattern) -> bool {
    window.iter().zip(pattern.iter()).all(|(v, p)| match p {
        Some(x) => *v == *x,
        None => true,
    })
}

pub fn find_patterns(region: &[u8], pattern: &Pattern) -> Vec<usize> {
    region
        .windows(pattern.len())
        .enumerate()
        .filter(|(_, x)| match_pattern(x, pattern))
        .map(|(pos, _)| pos)
        .collect()
}

pub fn get_strings(file: &[u8]) -> Vec<(usize, String)> {
    let decoder = Decoder::new(MachineMode::LONG_COMPAT_32, AddressWidth::_32).unwrap();

    #[derive(Debug, PartialEq, Clone, Copy)]
    enum Location {
        Eax,
        Ebx,
        Ecx,
        Edx,
        Xmm10,
        Xmm11,
        Xmm12,
        Xmm13,
        // offset to esp
        Stack(i16),
        Immediate(u32),
    }

    #[derive(Debug, PartialEq, Clone, Copy)]
    enum Event {
        Xor(
            (Location, Location, Location, Location),
            (Location, Location, Location, Location),
        ),
        Move(Location, Location),
        AdjustEsp(i16),
    }

    // this is like maximum cringe, but zydis stops decoding instructions when it encounters literally anything
    let mut cur_idx = 0x0;
    let mut instrs: Vec<(usize, DecodedInstruction)> = Vec::new();

    while cur_idx != file.len() {
        if let Ok(Some(instr)) = decoder.decode(&file[cur_idx..]) {
            let len = instr.length as usize;
            instrs.push((cur_idx, instr));
            cur_idx += len;
        } else {
            cur_idx += 1;
        }
    }

    let mut events: Vec<(usize, Event)> = instrs
        .par_iter()
        .flat_map(|(ip, instr)| match instr.mnemonic {
            Mnemonic::PXOR => vec![(
                *ip as usize,
                Event::Xor(
                    (
                        Location::Xmm10,
                        Location::Xmm11,
                        Location::Xmm12,
                        Location::Xmm13,
                    ),
                    (
                        Location::Stack(instr.operands[1].mem.disp.displacement as i16),
                        Location::Stack(instr.operands[1].mem.disp.displacement as i16 + 4),
                        Location::Stack(instr.operands[1].mem.disp.displacement as i16 + 8),
                        Location::Stack(instr.operands[1].mem.disp.displacement as i16 + 12),
                    ),
                ),
            )],
            Mnemonic::PUSH => {
                vec![(
                    *ip as usize,
                    /*Event::AdjustEsp(instr.operands[0].size / 8)*/
                    Event::AdjustEsp(/*instr.operands[0].size as u16 / 8*/ 4),
                )]
            }
            Mnemonic::SUB => {
                let lhs = &instr.operands[0];
                let rhs = &instr.operands[1];
                if lhs.ty == OperandType::REGISTER
                    && lhs.reg == Register::ESP
                    && rhs.ty == OperandType::IMMEDIATE
                {
                    vec![(*ip as usize, Event::AdjustEsp(rhs.imm.value as i16))]
                } else {
                    vec![]
                }
            }
            Mnemonic::ADD => {
                let lhs = &instr.operands[0];
                let rhs = &instr.operands[1];
                if lhs.ty == OperandType::REGISTER
                    && lhs.reg == Register::ESP
                    && rhs.ty == OperandType::IMMEDIATE
                {
                    vec![(*ip as usize, Event::AdjustEsp(0 - rhs.imm.value as i16))]
                } else {
                    vec![]
                }
            }
            Mnemonic::MOVAPS => {
                let lhs = &instr.operands[0];
                let rhs = &instr.operands[1];

                enum MovApsOperand {
                    Xmm,
                    Stack(i16),
                }

                let lhs = match lhs.ty {
                    OperandType::REGISTER => match lhs.reg {
                        Register::XMM1 => MovApsOperand::Xmm,
                        _ => return vec![],
                    },
                    OperandType::MEMORY => MovApsOperand::Stack(lhs.mem.disp.displacement as i16),
                    _ => return vec![],
                };

                let rhs = match rhs.ty {
                    OperandType::REGISTER => match rhs.reg {
                        Register::XMM1 => MovApsOperand::Xmm,
                        _ => return vec![],
                    },
                    OperandType::MEMORY => MovApsOperand::Stack(rhs.mem.disp.displacement as i16),
                    _ => return vec![],
                };

                let lhs = match lhs {
                    MovApsOperand::Xmm => [
                        Location::Xmm10,
                        Location::Xmm11,
                        Location::Xmm12,
                        Location::Xmm13,
                    ],
                    MovApsOperand::Stack(x) => [
                        Location::Stack(x),
                        Location::Stack(x + 4),
                        Location::Stack(x + 8),
                        Location::Stack(x + 12),
                    ],
                };

                let rhs = match rhs {
                    MovApsOperand::Xmm => [
                        Location::Xmm10,
                        Location::Xmm11,
                        Location::Xmm12,
                        Location::Xmm13,
                    ],
                    MovApsOperand::Stack(x) => [
                        Location::Stack(x),
                        Location::Stack(x + 4),
                        Location::Stack(x + 8),
                        Location::Stack(x + 12),
                    ],
                };

                vec![
                    (*ip as usize, Event::Move(lhs[0], rhs[0])),
                    (*ip as usize, Event::Move(lhs[1], rhs[1])),
                    (*ip as usize, Event::Move(lhs[2], rhs[2])),
                    (*ip as usize, Event::Move(lhs[3], rhs[3])),
                ]
            }
            Mnemonic::MOV => {
                // only 32 bit writes are used in the obfuscation
                let lhs = &instr.operands[0];
                let rhs = &instr.operands[1];

                if instr.operand_width / 8 != 4 {
                    return vec![];
                }

                let lhs = match lhs.ty {
                    OperandType::REGISTER => match lhs.reg {
                        Register::EAX => Location::Eax,
                        Register::EBX => Location::Ebx,
                        Register::ECX => Location::Ecx,
                        Register::EDX => Location::Edx,
                        _ => return vec![],
                    },
                    OperandType::MEMORY => {
                        if lhs.mem.base != Register::RSP && lhs.mem.base != Register::ESP {
                            return vec![];
                        }
                        Location::Stack(lhs.mem.disp.displacement as i16)
                    }
                    _ => return vec![],
                };

                let rhs = match rhs.ty {
                    OperandType::IMMEDIATE => Location::Immediate(rhs.imm.value as u32),
                    OperandType::REGISTER => match rhs.reg {
                        Register::EAX => Location::Eax,
                        Register::EBX => Location::Ebx,
                        Register::ECX => Location::Ecx,
                        Register::EDX => Location::Edx,
                        _ => return vec![],
                    },
                    OperandType::MEMORY => {
                        if rhs.mem.base != Register::RSP && rhs.mem.base != Register::ESP {
                            return vec![];
                        }
                        Location::Stack(rhs.mem.disp.displacement as i16)
                    }
                    _ => return vec![],
                };

                vec![(*ip as usize, Event::Move(lhs, rhs))]
            }
            _ => vec![],
        })
        .collect();

    events.sort_by(|a, b| a.0.cmp(&b.0));

    let results = events
        .par_iter()
        .filter(|(_, event)| matches!(event, Event::Xor(_, _)))
        .flat_map(|(xor_ip, xor)| -> Option<(usize, String)> {
            {
                if let Event::Xor(lhs, rhs) = xor {
                    // found an xor.
                    fn resolve_chain(
                        events: impl Iterator<Item = Event>,
                        needle: Location,
                    ) -> Option<u32> {
                        let mut current_location = needle;
                        let mut current_stack_offset = 0i32;

                        for event in events {
                            if let Event::AdjustEsp(offset) = event {
                                current_stack_offset += offset as i32;
                                continue;
                            }

                            if let Event::Move(lhs, rhs) = event {
                                // if we came across a push while looking for an instruction that modifies our currently tracked location,
                                // we will adjust our current location to how the code before the push would access it
                                let adjusted_current_location =
                                    if let Location::Stack(x) = current_location {
                                        Location::Stack(x - current_stack_offset as i16)
                                    } else {
                                        current_location
                                    };

                                if lhs == adjusted_current_location {
                                    current_location = rhs;
                                    current_stack_offset = 0;

                                    if let Location::Immediate(x) = rhs {
                                        return Some(x);
                                    }
                                }
                            }
                        }

                        None
                    }

                    let preceding_events = events
                        .iter()
                        .filter(|(ip, _)| ip < xor_ip && *ip > *xor_ip - 0x1000)
                        .rev()
                        .map(|x| x.1);

                    let resolved_lhs: Vec<u32> = [
                        resolve_chain(preceding_events.clone(), lhs.0),
                        resolve_chain(preceding_events.clone(), lhs.1),
                        resolve_chain(preceding_events.clone(), lhs.2),
                        resolve_chain(preceding_events.clone(), lhs.3),
                    ]
                    .into_iter()
                    .flatten()
                    .collect();

                    let resolved_rhs: Vec<u32> = [
                        resolve_chain(preceding_events.clone(), rhs.0),
                        resolve_chain(preceding_events.clone(), rhs.1),
                        resolve_chain(preceding_events.clone(), rhs.2),
                        resolve_chain(preceding_events.clone(), rhs.3),
                    ]
                    .into_iter()
                    .flatten()
                    .collect();

                    if resolved_lhs.len() != 4 || resolved_rhs.len() != 4 {
                        eprintln!(
                            "could not recover xor at {:#04X}: could not walk dependency chain!",
                            xor_ip
                        );

                        return None;
                    }

                    let resolved_lhs: Vec<u8> = resolved_lhs
                        .into_iter()
                        .map(|val| unsafe { std::mem::transmute::<u32, [u8; 4]>(val) })
                        .flatten()
                        .collect();

                    let resolved_lhs = if let Ok(resolved_lhs) = <[u8; 16]>::try_from(resolved_lhs)
                    {
                        resolved_lhs
                    } else {
                        eprintln!(
                            "could not recover xor at {:#04X}: resolving final operand failed",
                            xor_ip
                        );
                        return None;
                    };

                    let resolved_rhs: Vec<u8> = resolved_rhs
                        .into_iter()
                        .map(|val| unsafe { std::mem::transmute::<u32, [u8; 4]>(val) })
                        .flatten()
                        .collect();

                    let resolved_rhs = if let Ok(resolved_rhs) = <[u8; 16]>::try_from(resolved_rhs)
                    {
                        resolved_rhs
                    } else {
                        eprintln!(
                            "could not recover xor at {:#04X}: resolving final operand failed",
                            xor_ip
                        );
                        return None;
                    };

                    let resolved_lhs = u128::from_ne_bytes(resolved_lhs);
                    let resolved_rhs = u128::from_ne_bytes(resolved_rhs);

                    fn try_get_string(data: u128) -> Option<String> {
                        unsafe {
                            // ensure we are null terminated even if the xor is bogus
                            let terminated_data = [data, 0x00];
                            let cstr = CStr::from_ptr(terminated_data.as_ptr() as *const i8);

                            if let Ok(cstr) = cstr.to_str() {
                                Some(cstr.to_owned())
                            } else {
                                // assume its an obfuscated number
                                // Some(format!("{:#04X}", data))

                                None
                            }
                        }
                    }

                    if let Some(result) = try_get_string(resolved_lhs ^ resolved_rhs) {
                        return Some((*xor_ip, result));
                    } else {
                        eprintln!("could not recover xor at {:#04X}: string invalid", xor_ip);
                        return None;
                    }
                }
            }
            None
        })
        .collect::<Vec<(usize, String)>>();

    results
}

#[test]
fn test_aw() {
    let dll_results = get_strings(&std::fs::read("csgo-x86.dll").unwrap());
    let ldr_results = get_strings(&std::fs::read("devldr.exe").unwrap());

    println!(
        "dll: {} entries, ldr: {} entries",
        dll_results.len(),
        ldr_results.len()
    );

    for result in dll_results {
        println!("dll:{:#10X}, \"{}\"", result.0, result.1)
    }

    for result in ldr_results {
        println!("loader:{:#10X}, \"{}\"", result.0, result.1)
    }
}

#[test]
fn export_aw() {
    let dll_results = get_strings(&std::fs::read("csgo-x86.dll").unwrap());
    let ldr_results = get_strings(&std::fs::read("devldr.exe").unwrap());

    #[derive(serde::Serialize)]
    struct Entry {
        pub rva: usize,
        pub string: String,
    }

    #[derive(serde::Serialize, Default)]
    struct File {
        pub entries: Vec<Entry>,
    }

    let mut dll_file: File = File::default();
    let mut ldr_file: File = File::default();

    for result in dll_results {
        dll_file.entries.push(Entry {
            rva: result.0,
            string: result.1,
        });
    }

    for result in ldr_results {
        ldr_file.entries.push(Entry {
            rva: result.0,
            string: result.1,
        });
    }

    std::fs::write("dll.cmt", serde_json::to_string(&dll_file).unwrap()).unwrap();
    std::fs::write("ldr.cmt", serde_json::to_string(&ldr_file).unwrap()).unwrap();
}
