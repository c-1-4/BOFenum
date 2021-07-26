# BOFenum
Complete enumeration tool for win32 binaries vulnerable to stack based buffer overflows. Written in python.

# Features
This tool will perform dymanic analysis of a win32 binary. It can, without interaction, go from fuzzing to badchar detection to shellcode generation. 
- Uses wine. No windows host needed - only the binary and its custom .DLL dependencies (windows DLLs are linked automatically though)
- Automatic fuzzing
- Automatic pattern generation and offset identification
- Automatic badchar detection
- Automatic module identification and selection
- ALSR/NX/Safe SEH detection: BOFenum only searches for gadgets (jmp esp) in modules without exploit mitigations turned on.
- Automatic gadget identification, will find jmp esp (ff e4) and push esp; ret (54 c3)
- Automatic shellcode generation
- 100% local - this is only an enumeration tool for binary analysis. No actual exploitation is performed on any remote host.

# Install
You need the following tools to use this: wine (for wine and winedbg), pev (to read the binary headers) and msfvenom (to generate shellcode).
Tested with wine 6.0 and pev 0.80

sudo apt-get install pev
sudo apt install wine64
sudo apt-get install metaploit-framework

# Disclaimer
Used with success on the OSCP exam, but I make no guarantees as to whether or not it is allowed. No guarantees of it working on the exam either - make sure you  understand the course material and are able to do buffer overflows manually.

