#!/usr/bin/env python
# Name : Kripton Automatic Encryption & Decryption Tools v.0.1
# Author: mirfansulaiman
# Indonesian Backtrack Team | Kurawa In Disorder | Thermost.id
# http://indonesianbacktrack.or.id
# http://mirfansulaiman.com/
# http://ctfs.me/
# 
# Thx to : zico_eichel, aralmelintang, cyberking, ares, abdilahrf, Ipin.
#
# have a bug? report to doctorgombal@gmail.com or PM at http://indonesianbacktrack.or.id/forum/user-10440.html
# This encryption use AES256 . If you have the best your encryption, just replace into file encaes.py
# For Example , Use secretkey : in_your_minds_ur
#
# Note : Dont change author name ! Fuck Plagiarism !
from encaes import *
from time import sleep
import string, sys, os, re, commands

def keychip(key):  #Dont Remove
	if len(key) <> 16:
		print "\033[1;31;40m[!] Character length should be 16\033[0m"
		sys.exit('\033[1;31;40m[!] Exit\033[0m')
	return AESCipher(key)
	
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

Kripton Automatic Encryption & Decryption Tools v.0.1
        '''
	for i in info:
		print '\b\033[1;31;40m%s\033[0m' %(i),
		sys.stdout.flush()
		time.sleep(0.005)
	
def bersih():
	if os.name == "posix":
		os.system("clear")
	else:
		os.system("cls")
	
def encrot():
	bersih()
	print """\033[1;31;40m
    _______   ____________  ______  ________________  _   __
   / ____/ | / / ____/ __ \/ __ \ \/ /_  __/  _/ __ \/ | / /
  / __/ /  |/ / /   / /_/ / /_/ /\  / / /  / // / / /  |/ / 
 / /___/ /|  / /___/ _, _/ ____/ / / / / _/ // /_/ / /|  /  
/_____/_/ |_/\____/_/ |_/_/     /_/ /_/ /___/\____/_/ |_/   
____________________________________________________________                                                      
          \033[0m"""
	print '\n\033[1;31;40m[#] MENU\033[0m'
	print "\033[1;37;40m[1] Single File"
	print "[2] All File" #Feel like ransomware
	print "[3] With File Extension"
	print "[4] back to menu\033[0m"
	e = raw_input('\033[1;36;40m[+] Enter your choice ! 1 | 2 | 3 | 4 ? \033[0m')
	if e == '1':
		Objek  = raw_input('\033[1;36;40m[++++] Input filename = \033[0m')
		try:
			fObjek = open(Objek, "r")
			print("\033[1;32;40m[INFO] File opened. \033[0m")
		except:
			print "\033[1;31;40m[!] File can not be opened.\033[0m"
		content = fObjek.read()
		key = raw_input("\033[1;36;40m[++++] Input secretkey : \033[0m")
		key = keychip(key)
		encrypted = key.encrypt(content)
		fObjek.close();
		try:
			fObjek = open(Objek, "w")
			try:
				fObjek.truncate(0)
			except:
				print "\033[1;31;40m[!] File cannot be truncated.\033[0m"
			fObjek.write(encrypted)
			fObjek.close()
			print "\033[1;32;40m[INFO] Encryption file\033[0m \033[1;35;40m%s\033[0m \033[1;32;40msuccess ! \033[0m" % (Objek)
		except:
			print "\033[1;31;40m[!] File can not be writing\033[0m"
	elif e == '2':
		a = raw_input('\033[1;36;40m[++++] Are you sure want to encrypt all files ? Y/N \033[0m')
		if a == 'Y' or a == 'y':
			whitelist = ['kripton.py', 'encaes.py','./encaes.pyc'] #whitelist master file
			lFile = commands.getoutput("find . -type f ")
			arFile = string.split(lFile,"\n./")
			arFile = [item for item in arFile if item not in whitelist]
			count = 0
			print "\033[1;32;40m[INFO] Found\033[0m \033[1;36;40m" ,len(arFile), "\033[0m \033[1;32;40mfiles with all extension.\033[0m"
			array_file = arFile
			key = raw_input("\033[1;36;40m[++++] Input secretkey : \033[0m")
			key = keychip(key)
			for list_file in array_file:
				count = count + 1
				try:
					fObjek = open(list_file, "r")
					print("\033[1;32;40m[INFO] File \033[1;35;40m%s\033[0m \033[1;32;40mopened . \033[0m") % (list_file)
				except:
					print "\033[1;31;40m[!] File can not be opened\033[0m"
				content = fObjek.read()
				fObjek.close()
				encrypted = key.encrypt(content)
				try:
					fObjek = open(list_file, "w")
					try:
						fObjek.truncate(0)
					except:
						print "\033[1;31;40m[!] File can not be truncated\033[0m"
					fObjek.write(encrypted)
					fObjek.close()
					print "\033[1;32;40m[INFO] Encryption success file -\033[0m \033[1;36;40m%d\033[0m \033[1;35;40m%s\033[0m" % (count,list_file)
				except:
					print "\033[1;31;40m[!] File can not be writing\033[0m"
			print "\033[1;32;40m[SUCCESS] Total\033[0m \033[1;36;40m%d\033[0m \033[1;32;40mfiles has been encrypted.\033[0m" % (len(arFile))
		elif a == 'N' or a == 'n':
			encrot()
		else:
			main()
	elif e == '3':
		Objek  = raw_input('\033[1;36;40m[++++] Input file extension name without (dot) = \033[0m')
		File = commands.getoutput("find . -type f | grep ." + Objek + " | wc -l")
		lFile = commands.getoutput("find . -type f | grep ." + Objek )
		arFile = string.split(lFile,"\n./")
		count = 0
		print "\033[1;32;40m[INFO] Found\033[0m \033[1;36;40m" + File + "\033[0m \033[1;32;40mfiles with extension :\033[0m \033[1;35;40m%s\033[0m" % (Objek)
		array_file = arFile
		key = raw_input("\033[1;36;40m[++++] Input secretkey : \033[0m")
		key = keychip(key)
		for list_file in array_file:
			count = count + 1
			try:
				fObjek = open(list_file, "r")
				print("\033[1;32;40m[INFO] File\033[0m \033[1;35;40m%s\033[0m \033[1;32;40mopened . \033[0m") % (list_file)
			except:
				print "\033[1;31;40m[!] File can not be opened\033[0m"
			content = fObjek.read()
			fObjek.close()
			encrypted = key.encrypt(content)
			try:
				fObjek = open(list_file, "w")
				try:
					fObjek.truncate(0)
				except:
					print "\033[1;31;40m[!] File can not be truncated\033[0m"
				fObjek.write(encrypted)
				fObjek.close()
				print "\033[1;32;40m[INFO] Encryption success file -\033[0m \033[1;36;40m%d\033[0m \033[1;35;40m%s\033[0m" % (count,list_file)
			except:
				print "\033[1;31;40m[!] File can not be writing\033[0m"
		print "\033[1;32;40m[SUCCESS] Total\033[0m \033[1;36;40m%d\033[0m \033[1;32;40mfiles has been encrypted.\033[0m" % (int(File))
	elif e == '4':
		main()
	else:
		print '\033[1;31;40m[!] Wrong Choice ! Please just enter number 1, 2, 3, or 4 !\033[0m'
	
def decrot():
	bersih()
	print """\033[1;31;40m
    ____  __________________  ______  ______________  _   __
   / __ \/ ____/ ____/ __ \ \/ / __ \/_  __/  _/ __ \/ | / /
  / / / / __/ / /   / /_/ /\  / /_/ / / /  / // / / /  |/ / 
 / /_/ / /___/ /___/ _, _/ / / ____/ / / _/ // /_/ / /|  /  
/_____/_____/\____/_/ |_| /_/_/     /_/ /___/\____/_/ |_/  
____________________________________________________________ 
			\033[0m"""
	print '\n\033[1;31;40m[#] MENU\033[0m'
	print "\033[1;37;40m[1] Single File"
	print "[2] All File"
	print "[3] With File Extension"
	print "[4] back to menu\033[0m"
	d = raw_input('\033[1;36;40m[+] Enter your choice ! 1 | 2 | 3 | 4 ? \033[0m')
	if d == '1':
		Objek  = raw_input('\033[1;36;40m[++++] Input filename = \033[0m')
		try:
			fObjek = open(Objek, "r")
			print("\033[1;32;40m[INFO] File opened .\033[0m")
		except:
			print "\033[1;31;40m[!] File can not be opened\033[0m"
		content = fObjek.read()
		key = raw_input("\033[1;36;40m[++++] Input secretkey : \033[0m")
		key = keychip(key)
		decrypted = key.decrypt(content)
		fObjek.close()
		try:
			fObjek = open(Objek, "w")
			try:
				fObjek.truncate(0)
			except:
				print "\033[1;31;40m[!] File can not be truncated\033[0m"
			fObjek.write(decrypted)
			fObjek.close()
			print "\033[1;32;40m[INFO] Decryption file\033[0m \033[1;35;40m%s\033[0m \033[1;32;40msuccess ! \033[0m" % (Objek)
		except:
			print "\033[1;31;40m[!] File can not be writing\033[0m"
	elif d == '2':
		a = raw_input('\033[1;36;40m[++++] Are you sure want to decrypt all files ? Y/N \033[0m')
		if a == 'Y' or a == 'y':
			whitelist = ['kripton.py', 'encaes.py', './encaes.pyc'] #whitelist master file
			lFile = commands.getoutput("find . -type f")
			arFile = string.split(lFile,"\n./")
			arFile = [item for item in arFile if item not in whitelist]
			count = 0
			print "\033[1;32;40m[INFO] Found \033[0m \033[1;36;40m" ,len(arFile), "\033[0m \033[1;32;40mfiles with all extension.\033[0m"
			array_file = arFile
			key = raw_input("\033[1;36;40m[++++] Input secretkey : \033[0m")
			key = keychip(key)
			for list_file in array_file:
				count = count + 1
				try:
					fObjek = open(list_file, "r")
					print("\033[1;32;40m[INFO] File\033[0m \033[1;35;40m%s\033[0m \033[1;32;40mopened . \033[0m") % (list_file)
				except:
					print "\033[1;31;40m[!] File can not be opened\033[0m"
				content = fObjek.read()
				fObjek.close()
				decrypted = key.decrypt(content)
				try:
					fObjek = open(list_file, "w")
					try:
						fObjek.truncate(0)
					except:
						print "\033[1;31;40m[!] File can not be truncated\033[0m"
					fObjek.write(decrypted)
					fObjek.close()
					print "\033[1;32;40m[INFO] Decryption success file -\033[0m \033[1;36;40m%d\033[0m \033[1;35;40m%s\033[0m " % (count,list_file)
				except:
					print "\033[1;31;40m[!] File can not be writing\033[0m"
			print "\033[1;32;40m[SUCCESS] Total\033[0m \033[1;36;40m%d\033[0m \033[1;32;40mfiles has been decrypted.\033[0m" % (len(arFile))
		elif a == 'N' or a == 'n':
			decrot()
		else:
			main()
	elif d == '3':
		Objek  = raw_input('\033[1;36;40m[++++] Input file extension name without (dot) = \033[0m')
		File = commands.getoutput("find . -type f | grep ." + Objek + " | wc -l")
		lFile = commands.getoutput("find . -type f | grep ." + Objek )
		arFile = string.split(lFile,"\n./")
		count = 0
		print "\033[1;32;40m[INFO] Found\033[0m \033[1;36;40m" + File + "\033[0m \033[1;32;40mfiles with extension :\033[0m \033[1;35;40m%s\033[0m" % (Objek)
		array_file = arFile
		key = raw_input("\033[1;36;40m[++++] Input secretkey : \033[0m")
		key = keychip(key)
		for list_file in array_file:
			count = count + 1
			try:
				fObjek = open(list_file, "r")
				print("\033[1;32;40m[INFO] File\033[0m \033[1;35;40m%s\033[0m \033[1;32;40mopened . \033[0m") % (list_file)
			except:
				print "\033[1;31;40m[!] File can not be opened\033[0m"
			content = fObjek.read()
			fObjek.close()
			decrypted = key.decrypt(content)
			try:
				fObjek = open(list_file, "w")
				try:
					fObjek.truncate(0)
				except:
					print "\033[1;31;40m[!] File can not be truncated\033[0m"
				fObjek.write(decrypted)
				fObjek.close()
				print "\033[1;32;40m[INFO] Decryption success file -\033[0m \033[1;36;40m%d\033[0m \033[1;35;40m%s\033[0m " % (count,list_file)
			except:
				print "\033[1;31;40m[!] File can not be writing\033[0m"
		print "\033[1;32;40m[SUCCESS] Total\033[0m \033[1;36;40m%d\033[0m \033[1;32;40mfiles has been decrypted.\033[0m" % (int(File))
	elif d == '4':
		main()
	else:
		print '\033[1;31;40m[!] Wrong Choice ! Please just enter number 1, 2, 3, or 4 !\033[0m'
				
def main():
		banner()
		print '\n\033[1;31;40m[#] MENU\033[0m'
		print '\033[1;37;40m[1] Encrypt'
		print '[2] Decrypt\033[0m'
		choice = raw_input('\033[1;36;40m[+] Enter your choice ! 1 or 2 ? \033[0m')
		if choice == '1':
			encrot()
		elif choice == '2':
			decrot()
		else:
			print '\033[1;31;40m[!] Wrong Choice ! Please just enter number 1, 2, 3, or 4 !\033[0m'

if __name__ == '__main__':
			try:
				main()
			except KeyboardInterrupt:
				print ' [Exit]'
				try:
					sys.exit(0)
				except SystemExit:
					os._exit(0)
