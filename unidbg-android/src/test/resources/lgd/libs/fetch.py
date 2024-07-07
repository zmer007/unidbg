import subprocess
import os

log = '''
[11:02:00 746]  INFO [com.github.unidbg.linux.AndroidElfLoader] (AndroidElfLoader:481) - libhelloollvm.so load dependency libandroid.so failed
[11:02:00 747]  INFO [com.github.unidbg.linux.AndroidElfLoader] (AndroidElfLoader:481) - libhelloollvm.so load dependency liblog.so failed
[11:02:00 747]  INFO [com.github.unidbg.linux.AndroidElfLoader] (AndroidElfLoader:481) - libhelloollvm.so load dependency libm.so failed
[11:02:00 748]  INFO [com.github.unidbg.linux.AndroidElfLoader] (AndroidElfLoader:481) - libhelloollvm.so load dependency libdl.so failed
[11:02:00 748]  INFO [com.github.unidbg.linux.AndroidElfLoader] (AndroidElfLoader:481) - libhelloollvm.so load dependency libc.so failed
'''

with open('maps.txt') as f:
    maps_lines = [l.strip() for l in f.readlines()]

lines = log.split("\n")

cur_dir = os.getcwd()

cur_libs = [f for f in os.listdir(cur_dir) if f.endswith(".so")]
append_libs = []

for l in lines:
    if len(l) < 1:
        continue
    so_name = l.split(' ')[-2]
    if so_name in cur_libs:
        continue
    for maps_l in maps_lines:
        if not maps_l.endswith(so_name):
            continue
        so_path = maps_l.split(" ")[-1]
        subprocess.run("adb pull {}".format(so_path), shell=True)
        append_libs.append(so_name)
        break

for sn in append_libs:
    print("vm.loadLibrary(new File(SO_LIB_DIR + \"/{}\"), false);".format(sn))
