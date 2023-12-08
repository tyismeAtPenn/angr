import angr
import time
import os

directory_path = './crackme'
print("concac")
print(os.listdir(directory_path))

# Get all file names in the directory
file_names = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]
print(file_names)



proj0 = angr.Project('./crackme/crackme0x00', auto_load_libs = False)
proj1 = angr.Project('./crackme/crackme0x01', auto_load_libs = False)
proj2 = angr.Project('./crackme/crackme0x02', auto_load_libs = False)
