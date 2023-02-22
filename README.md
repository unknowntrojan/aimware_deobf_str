# aimware_deobf_str

a small script to help you find strings in the aimware loader and dll binaries.
it comments xored strings in the binary. !IT DOES NOT YET CATCH ALL OF THEM, JUST A SUBSET!

to use it, run `cargo test export_aw`, this will generate two files: `ldr.cmt` and `dll.cmt`, for the loader and dll, respectively.
now open your binary of choice in IDA, and run the ida_parse.py script file. select the correct cmt file and enjoy your newly added comments.

sadly i did not find a way to add these comments to the decompiler output. you will only see it in the disassembly view.

![Disassembly view](https://i.imgur.com/G3HP4FX.png)
![Decompiler view](https://i.imgur.com/sLM1vsC.png)
