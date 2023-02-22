use std::ffi::CStr;

pub type Pattern = Vec<Option<u8>>;

macro_rules! pattern {
    ($($elem:tt),+) => {
        vec![$(pattern!(@el $elem)),+]
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
    window.iter().zip(pattern).all(|(v, p)| match p {
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

pub fn decode_str(p0: (u64, u64), p1: (u64, u64)) -> Option<String> {
    unsafe {
        let p0 = p0.0 ^ p0.1;
        let p1 = p1.0 ^ p1.1;

        let data = std::mem::transmute::<[u64; 2], [u128; 1]>([p0, p1]);

        let cstr = CStr::from_ptr(data.as_ptr() as *const i8);

        Some(cstr.to_str().ok()?.to_owned())
    }
}

pub fn get_strings(file: &[u8]) -> Vec<(usize, String)> {
    let occurrences = find_patterns(file, &pattern!(0x66, 0x0F, 0xEF));

    let mut results = Vec::new();

    for occurrence in occurrences {
        // println!("found pxor at {:#04X}", occurrence);

        // we will try to get all 4 mov [esp+30h+var_xd], 0x00000000's
        // before the pxor. (C7 44 24 08) & (C7 44 24 0C)

        let movs = &file[std::cmp::max(0, occurrence - 0x200)..occurrence]
            .windows(8)
            .rev()
            .filter(|x| match_pattern(&x, &pattern!(0xC7, 0x44, 0x24)))
            .map(|x| {
                // extract constant
                u32::from_ne_bytes(<[u8; 4]>::try_from(&x[4..8]).unwrap())
            })
            .collect::<Vec<u32>>();

        if let Some(movs) = movs.get(..8) {
            fn join(lhs: u32, rhs: u32) -> u64 {
                unsafe { u64::from_ne_bytes(std::mem::transmute::<[u32; 2], [u8; 8]>([rhs, lhs])) }
            }

            let p0 = (join(movs[6], movs[7]), join(movs[2], movs[3]));
            let p1 = (join(movs[4], movs[5]), join(movs[0], movs[1]));

            // println!("p0.0: {:#04X}", p0.0);
            // println!("p0.1: {:#04X}", p0.1);
            // println!("p1.0: {:#04X}", p1.0);
            // println!("p1.1: {:#04X}", p1.1);

            if let Some(decoded_str) = decode_str(p0, p1) {
                results.push((occurrence, decoded_str));
            }
        } else {
            continue;
        }
    }

    results
}

#[test]
fn test_aw() {
    let dll_results = get_strings(&std::fs::read("csgo-x86.dll").unwrap());
    let ldr_results = get_strings(&std::fs::read("devldr.exe").unwrap());

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
