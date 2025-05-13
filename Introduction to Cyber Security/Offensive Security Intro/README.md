# TryHackMe - Offensive Security
## Overview
In this room, I learned the basics of Offensive Security, which involves thinking like a hacker to identify and exploit vulnerabilities in a system. The goal is to improve system defenses by understanding the hacker’s tactics.

This room walked me through using tools like Gobuster to discover hidden pages and perform a simple attack on a mock bank site.

# Tools Used
Gobuster (for brute-forcing hidden directories on websites)

Terminal (for running Gobuster and interacting with the command line)

# Task 1: What is Offensive Security?
Offensive Security refers to simulating a hacker's actions to find vulnerabilities in a system. The focus is on identifying flaws that could be exploited by cybercriminals.

Question: Which of the following options better represents the process where you simulate a hacker's actions to find vulnerabilities in a system?

Answer: Offensive Security

# Task 2: Hacking your First Machine
Your First Hack
In this task, I used Gobuster to brute-force FakeBank's website and find hidden directories. This helped me identify potentially sensitive pages, such as admin portals.

# Step 1: Open A Terminal
The terminal (command line) allows interaction with a computer via text commands. I accessed it through the icon on the right of the screen.

## Step 2: Use Gobuster to Find Hidden Website Pages
Gobuster was used to perform a directory brute-force on the website. The command used was:

```gobuster -u http://fakebank.thm -w wordlist.txt dir```

Here’s the output from Gobuster:

```
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://fakebank.thm/
[+] Threads      : 10
[+] Wordlist     : wordlist.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2024/05/21 10:04:38 Starting gobuster
=====================================================
/images (Status: 301)
/bank-transfer (Status: 200)
=====================================================
2024/05/21 10:04:44 Finished
=====================================================
```
As you can see, Gobuster successfully found the /bank-transfer page, which had status code 200 (meaning it existed on the site).

## Step 3: Hack the Bank
After finding the hidden page, I accessed /bank-transfer using the browser’s address bar and performed the transfer of $2000 from account 2276 to my account 8881.

If successful, my account balance would reflect the transfer, and the page showed a message:

### Answer: BANK-HACKED

This demonstrated how an attacker could exploit a hidden page for unauthorized transactions.

# Task 3: Careers in Cybersecurity
### How Can I Start Learning?
The best way to start learning cybersecurity is through hands-on practice. Platforms like TryHackMe offer practical, step-by-step challenges that help build your knowledge and skills in a safe environment.

Career Paths in Cybersecurity
Some common roles in cybersecurity include:

Penetration Tester: Focuses on finding exploitable vulnerabilities in systems.

Red Teamer: Simulates attacks against an organization to find weaknesses.

Security Engineer: Designs, monitors, and maintains security measures for networks and systems.

Lessons Learned
I now understand the basic principles of Offensive Security and how hackers exploit weaknesses.

The first use of Gobuster taught me how attackers find hidden pages on websites, which could lead to sensitive data or unauthorized actions.

I gained insight into the role of Penetration Testers and how important hands-on learning is for success in this field.
