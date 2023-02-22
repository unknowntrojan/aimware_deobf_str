import json

def add_comment(ea, cmt):
	ea = ida_loader.get_fileregion_ea(ea)
	print("adding comment at " + hex(ea) + ": " + cmt)
	idaapi.set_cmt(ea, cmt, False)

filename = ida_kernwin.ask_file(0, "*.cmt", "aimware_deobf_str exported file")
if filename:
	file = open(filename, "r")
	data = json.load(file)

	for entry in data["entries"]:
		add_comment(entry["rva"], entry["string"])
	
	print("generated comments, have fun!")
