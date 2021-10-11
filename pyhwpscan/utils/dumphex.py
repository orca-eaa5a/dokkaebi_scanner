import hexdump
import os
def print_hexdump(buf):
    hexdump.hexdump(buf)

def dump_as_physical_file(buf, file_name, dump_path=None):
    if dump_path:
        f = open(dump_path + "/" + file_name, "wb")
        f.write(buf)
        f.close()
    else:
        cur_dirs = os.listdir()
        if "dump" not in cur_dirs:
            os.mkdir("./dump")
        f = open("./dump/"+file_name, "wb")
        f.write(buf)
        f.close()
    print("*** ["+file_name+"] dumped")