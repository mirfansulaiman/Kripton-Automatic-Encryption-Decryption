#!/usr/bin/env python
# Name : Kripton Automatic Encryption & Decryption Tools v.0.2
# Author: mirfansulaiman
# Indonesian Backtrack Team | Kurawa In Disorder | Thermost.id | HIMTIF ISTN
# http://indonesianbacktrack.or.id
# http://mirfansulaiman.com/
# http://ctfs.me/
# 
# Thx to : zico_eichel, aralmelintang, cyberking, ares, abdilahrf, Ipin.
#
# have a bug? report to doctorgombal@gmail.com or PM at http://indonesianbacktrack.or.id/forum/user-10440.html
# For Example , Use secretkey : in_your_minds_ur
#
# Note : Dont change author name ! Fuck Plagiarism !
import string, time, re, commands
import base64,sys,os
from Crypto import Random
from Crypto.Cipher import AES
##########################################################################################################
# 
# Replace with your the best encryption
# 
# This encryption use AES 256 code from here :
# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
##########################################################################################################
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]
class AESCipher:
	def __init__( self, key ):
		self.key = key
	def encrypt( self, raw ): #Dont Remove
		raw = pad(raw)
		iv = Random.new().read( AES.block_size )
		cipher = AES.new( self.key, AES.MODE_CBC, iv )
		return base64.b64encode( iv + cipher.encrypt( raw ) )
	def decrypt( self, enc ):  #Dont Remove
		enc = enc.rstrip()
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv )
		dec = unpad(cipher.decrypt( enc[16:] ))
		if dec:
			print GREEN+'[!]'+TAG+WHITE+' Match key !'+TAG
		else:
			print RED+'[!]'+TAG+WHITE+' Wrong key !'+TAG
			try:
				sys.exit(0)
			except SystemExit:
				os._exit(0)
		return dec

def keychip(key):  #Dont Remove, use this variable for secretkey .
	if len(key) <> 16:
		print RED+"[!] Character length should be 16 !"+TAG
		sys.exit(0)
	aes = AESCipher(key)
	return aes
	
##########################################################################################################
# END ENCRYPTION AES 246
##########################################################################################################

#COLOR
RED = "\033[1;31;40m"
WHITE = "\033[1;37;40m"
GREEN = "\033[1;32;40m"
CYAN = "\033[1;36;40m"
PURPLE= "\033[1;35;40m"
TAG = "\033[0m"
def banner():
	bersih()
	info = '''
_________________________________________
 _         _       _              
| |       (_)     | |             
| | ___ __ _ _ __ | |_ ___  _ __  
| |/ / '__| | '_ \| __/ _ \| '_ \ 
|   <| |  | | |_) | || (_) | | | |
|_|\_\_|  |_| .__/ \__\___/|_| |_|
            | |                   
            |_| 
_________________________________________

Kripton Automatic Encryption & Decryption Tools v.0.2
        '''
	for i in info:
		print '\b'+RED+'%s' %(i),
		sys.stdout.flush()
		time.sleep(0.005)
	
def bersih():
	if os.name == "posix":
		os.system("clear")
	else:
		os.system("cls")

def encrot():
	bersih()
	print """%s
    _______   ______________  ______  ______________  _   __
   / ____/ | / / ____/ __ \ \/ / __ \/_  __/  _/ __ \/ | / /
  / __/ /  |/ / /   / /_/ /\  / /_/ / / /  / // / / /  |/ / 
 / /___/ /|  / /___/ _, _/ / / ____/ / / _/ // /_/ / /|  /  
/_____/_/ |_/\____/_/ |_| /_/_/     /_/ /___/\____/_/ |_/                                                
____________________________________________________________                                                      
          %s""" %(RED,TAG)
	print '\n'+RED+'[#] MENU'+TAG
	print WHITE+"[1] Single File"
	print "[2] All File" #Feel like ransomware
	print "[3] With File Extension"
	print "[4] back to menu"+TAG
	e = raw_input(CYAN+'[+] Enter your choice ! 1 | 2 | 3 | 4 ? '+TAG)
	if e == '1':
		Objek  = raw_input(CYAN+'[++++] Input filename = '+TAG)
		try:
			fObjek = open(Objek, "r")
			print(GREEN+"[INFO] File opened. "+TAG)
		except:
			print RED+"[!] File can not be opened."+TAG
		content = fObjek.read()
		key = raw_input(CYAN+"[++++] Input secretkey : "+TAG)
		key = keychip(key)
		encrypted = key.encrypt(content)
		fObjek.close();
		fObjek = open(Objek, "w")
		try:
			fObjek.truncate(0)
		except:
			print RED+"[!] File cannot be truncated."+TAG
			print RED+"[!] File can not be writing"+TAG
		fObjek.write(encrypted)
		fObjek.close()
		print '{0}[INFO] Encryption file{1}{2} {3} {4}{5}success !{6}'.format(GREEN,TAG,PURPLE,Objek,TAG,GREEN,TAG)
	elif e == '2':
		a = raw_input(CYAN+'[++++] Are you sure want to encrypt all files ? Y/N '+TAG)
		if a == 'Y' or a == 'y':
			lFile = commands.getoutput("find . -type f ")
			arFile = string.split(lFile,"\n./")
			whitelist = ['kripton.py'] #WHITELIST FILES
			arFile = [item for item in arFile if item not in whitelist]
			count = 0
			if len(arFile) == '0':
				print "{0}[INFO] No files in directory !{1}".format(RED,TAG)
			else:	
				print GREEN+"[INFO] Found"+TAG+PURPLE ,len(arFile), TAG+GREEN+"files with all extension."+TAG
				array_file = arFile
				key = raw_input(CYAN+"[++++] Input secretkey : "+TAG)
				key = keychip(key)
				for list_file in array_file:
					count = count + 1
					try:
						fObjek = open(list_file, "r")
						print "{0}[INFO] File{1} {2}{3}{4} {5} opened.{6}".format(GREEN,TAG,PURPLE,list_file,TAG,GREEN,TAG)
					except:
						print RED+"[!] File can not be opened"+TAG
					content = fObjek.read()
					fObjek.close()
					encrypted = key.encrypt(content)
					try:
						fObjek = open(list_file, "w")
						try:
							fObjek.truncate(0)
						except:
							print RED+"[!] File can not be truncated"+TAG
						fObjek.write(encrypted)
						fObjek.close()
						print "{0}[INFO] Encryption success file - {1}{2}{3}{4} {5}{6}{7}".format(GREEN,TAG,CYAN,count,TAG,PURPLE,list_file,TAG)
					except:
						print RED+"[!] File can not be writing"+TAG
				print "{0}[SUCCESS] Total{1} {2}{3}{4} {5}files has been encrypted.{6}".format(GREEN,TAG,CYAN,len(arFile),TAG,GREEN,TAG)
		elif a == 'N' or a == 'n':
			encrot()
		else:
			main()
	elif e == '3':
		Objek  = raw_input(CYAN+'[++++] Input file extension name without (dot) = '+TAG)
		File = commands.getoutput("find . -type f | grep ."+Objek +" | wc -l")
		lFile = commands.getoutput("find . -type f | grep ."+Objek )
		arFile = string.split(lFile,"\n./")
		count = 0
		if File == '0':
			print "{0}[INFO] File not found !{1}{2} files with extension : {3}{4}{5}{6}".format(GREEN,TAG,GREEN,TAG,PURPLE,Objek,TAG)
		else:
			print "{0}[INFO] Found{1}{2} {3} {4}{5}files with extension : {6}{7}{8}{9}".format(GREEN,TAG,CYAN,File,TAG,GREEN,TAG,PURPLE,Objek,TAG)
			array_file = arFile
			key = raw_input(CYAN+"[++++] Input secretkey : "+TAG)
			key = keychip(key)
			for list_file in array_file:
				count = count + 1
				try:
					fObjek = open(list_file, "r")
					print "{0}[INFO] File{1} {2}{3}{4} {5} opened.{6}".format(GREEN,TAG,PURPLE,list_file,TAG,GREEN,TAG)
				except:
					print RED+"[!] File can not be opened"+TAG
				content = fObjek.read()
				fObjek.close()
				encrypted = key.encrypt(content)
				try:
					fObjek = open(list_file, "w")
					try:
						fObjek.truncate(0)
					except:
						print RED+"[!] File can not be truncated"+TAG
					fObjek.write(encrypted)
					fObjek.close()
					print "{0}[INFO] Encryption success file - {1}{2}{3}{4} {5}{6}{7}".format(GREEN,TAG,CYAN,count,TAG,PURPLE,list_file,TAG)
				except:
					print RED+"[!] File can not be writing"+TAG
			print "{0}[SUCCESS] Total{1} {2}{3}{4} {5}files has been encrypted.{6}".format(GREEN,TAG,CYAN,len(arFile),TAG,GREEN,TAG)
	elif e == '4':
		main()
	else:
		print RED+'[!] Wrong Choice ! Please just enter number 1, 2, 3, or 4 !'+TAG
def decrot():
	bersih()
	print """%s
    ____  __________________  ______  ______________  _   __
   / __ \/ ____/ ____/ __ \ \/ / __ \/_  __/  _/ __ \/ | / /
  / / / / __/ / /   / /_/ /\  / /_/ / / /  / // / / /  |/ / 
 / /_/ / /___/ /___/ _, _/ / / ____/ / / _/ // /_/ / /|  /  
/_____/_____/\____/_/ |_| /_/_/     /_/ /___/\____/_/ |_/  
____________________________________________________________ 
		%s""" %(RED,TAG)
	print '\n'+RED+'[#] MENU'+TAG
	print WHITE+"[1] Single File"
	print "[2] All File" 
	print "[3] With File Extension"
	print "[4] back to menu"+TAG
	d = raw_input(CYAN+'[+] Enter your choice ! 1 | 2 | 3 | 4 ? '+TAG)
	if d == '1':
		Objek  = raw_input(CYAN+'[++++] Input filename = '+TAG)
		try:
			fObjek = open(Objek, "r")
			print(GREEN+"INFO] File opened ."+TAG)
		except:
			print RED+"[!] File can not be opened"+TAG
		content = fObjek.read()
		key = raw_input(CYAN+"[++++] Input secretkey : "+TAG)
		key = keychip(key)
		decrypted = key.decrypt(content)
		fObjek.close()
		try:
			fObjek = open(Objek, "w")
			try:
				fObjek.truncate(0)
			except:
				print RED+"[!] File can not be truncated"+TAG
			fObjek.write(decrypted)
			fObjek.close()
			print '{0}[INFO] Decryption file{1}{2} {3} {4}{5}success !{6}'.format(GREEN,TAG,PURPLE,Objek,TAG,GREEN,TAG)
		except:
			print RED+"[!] File can not be writing"+TAG
	elif d == '2':
		a = raw_input(CYAN+'[++++] Are you sure want to decrypt all files ? Y/N '+TAG)
		if a == 'Y' or a == 'y':
			whitelist = ['kripton.py'] #whitelist master file
			lFile = commands.getoutput("find . -type f")
			arFile = string.split(lFile,"\n./")
			arFile = [item for item in arFile if item not in whitelist]
			count = 0
			if len(arFile) == '0':
				print "{0}[INFO] No files in directory !{1}".format(RED,TAG)
			else:	
				print GREEN+"[INFO] Found"+TAG+PURPLE ,len(arFile), TAG+GREEN+"files with all extension."+TAG
				array_file = arFile
				key = raw_input(GREEN+"[++++] Input secretkey : "+TAG)
				key = keychip(key)
				for list_file in array_file:
					count = count + 1
					try:
						fObjek = open(list_file, "r")
						print "{0}[INFO] File{1} {2}{3}{4} {5} opened.{6}".format(GREEN,TAG,PURPLE,list_file,TAG,GREEN,TAG)
					except:
						print RED+"[!] File can not be opened"+TAG
					content = fObjek.read()
					fObjek.close()
					decrypted = key.decrypt(content)
					try:
						fObjek = open(list_file, "w")
						try:
							fObjek.truncate(0)
						except:
							print RED+"[!] File can not be truncated"+TAG
						fObjek.write(decrypted)
						fObjek.close()
						print "{0}[INFO] Decryption success file - {1}{2}{3}{4} {5}{6}{7}".format(GREEN,TAG,CYAN,count,TAG,PURPLE,list_file,TAG)
					except:
						print RED+"[!] File can not be writing"+TAG
				print "{0}[SUCCESS] Total{1} {2}{3}{4} {5}files has been decrypted.{6}".format(GREEN,TAG,CYAN,len(arFile),TAG,GREEN,TAG)
		elif a == 'N' or a == 'n':
			decrot()
		else:
			main()
	elif d == '3':
		Objek  = raw_input(CYAN+'[++++] Input file extension name without (dot) = '+TAG)
		File = commands.getoutput("find . -type f | grep ." + Objek + " | wc -l")
		lFile = commands.getoutput("find . -type f | grep ." + Objek )
		arFile = string.split(lFile,"\n./")
		count = 0
		if File == '0':
			print "{0}[INFO] File not found !{1}{2} files with extension : {3}{4}{5}{6}".format(GREEN,TAG,GREEN,TAG,PURPLE,Objek,TAG)
		else:	
			print "{0}[INFO] Found{1}{2} {3} {4}{5} files with extension : {6}{7}{8}{9}".format(GREEN,TAG,CYAN,File,TAG,GREEN,TAG,PURPLE,Objek,TAG)
			array_file = arFile
			key = raw_input(CYAN+"[++++] Input secretkey : "+TAG)
			key = keychip(key)
			for list_file in array_file:
				count = count + 1
				try:
					fObjek = open(list_file, "r")
					print "{0}[INFO] File{1} {2}{3}{4} {5} opened.{6}".format(GREEN,TAG,PURPLE,list_file,TAG,GREEN,TAG)
				except:
					print RED+"[!] File can not be opened"+TAG
				content = fObjek.read()
				fObjek.close()
				decrypted = key.decrypt(content)
				try:
					fObjek = open(list_file, "w")
					try:
						fObjek.truncate(0)
					except:
						print RED+"[!] File can not be truncated"+TAG
					fObjek.write(decrypted)
					fObjek.close()
					print "{0}[INFO] Decryption success file - {1}{2}{3}{4} {5}{6}{7}".format(GREEN,TAG,CYAN,count,TAG,PURPLE,list_file,TAG)
				except:
					print RED+"[!] File can not be writing"+TAG
			print "{0}[SUCCESS] Total{1} {2}{3}{4} {5}files has been decrypted.{6}".format(GREEN,TAG,CYAN,int(File),TAG,GREEN,TAG)
	elif d == '4':
		main()
	else:
		print RED+'[!] Wrong Choice ! Please just enter number 1, 2, 3, or 4 !'+TAG
								
def main():
		banner()
		print '\n'+RED+'[#] MENU'+TAG
		print WHITE+'[1] Encrypt'
		print '[2] Decrypt'+TAG
		choice = raw_input(CYAN+'[+] Enter your choice ! 1 or 2 ? '+TAG)
		if choice == '1':
			encrot()
		elif choice == '2':
			decrot()
		else:
			print RED+'[!] Wrong Choice ! Please just enter number 1, 2, 3, or 4 !'+TAG

if __name__ == '__main__':
			try:
				main()
			except KeyboardInterrupt:
				print ' [Exit] Bye! '
				try:
					sys.exit(0)
				except SystemExit:
					os._exit(0)
