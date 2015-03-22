import logging
import time
from colorama import init, Fore, Back, Style
logger = logging.getLogger()
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
console.setFormatter(formatter)
logger.addHandler(console)
init()
def printJuicyCookie(msg):
	print(Fore.RESET + "#################")
	timestr = time.strftime('%Y-%m-%d %H:%M:%S')
	print(Fore.RED + timestr + msg)
	print(Fore.RESET + "#################")

def printJuicyForm(msg):
	print(Fore.RESET + "#################")
	timestr = time.strftime('%Y-%m-%d %H:%M:%S')
	print(Fore.BLUE + timestr + msg)
	print(Fore.RESET + "#################")

def storeCookie(ua,host, uri, juicyInfo,filename = "monsterCookie.log"):
	msg = "ua: %s\nhost: %s\nuri: %s\n password: %s \n" % (ua, host, uri, juicyInfo)
	storeToFile(msg, filename)
def storeForm(ua, host, uri, rawcookie,filename = "monsterCookie.log"):
	msg = "ua: %s\nhost: %s\nuri: %s\n rawcookie: %s \n" % (ua, host, uri, rawcookie)
	storeToFile(msg, filename)
	
def storeToFile(msg,filename):
	f = open(filename, "a+")
	timestr = time.strftime('%Y-%m-%d %H:%M:%S')
	f.write(timestr + "\n" +msg)
	f.close()