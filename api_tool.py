import os, requests, hashlib
from bs4 import BeautifulSoup
from colorama import Fore, Style

def clear(): os.system('cls' if os.name == 'nt' else 'clear')

def get_pwned_count(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        raise Exception(f"Error checking HIBP: {response.status_code}")

    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0

def check_passwords(passwords):
    for pwd in passwords:
        count = get_pwned_count(pwd)
        if count:
            print(f"⚠️ The password '{pwd}' have been pwned {count} times")
        else:
            print(f"✅ The password '{pwd}' not found in leaks")

def ip_lookup(target):
    print("\n[ + ] IP Lookup (ip-api.com)")
    r = requests.get(f"http://ip-api.com/json/{target}")
    print(r.json())

def crtsh_lookup(target):
    print("\n[ + ] SSL Certs (crt.sh)")
    r = requests.get(f"https://crt.sh/?q={target}&output=json")
    if r.status_code == 200:
        for cert in r.json():
            with open('results.txt', 'a') as file:
                file.write(cert.get('name_value'))
            
        print('Results saved to results.txt')

    else:
        print("Error fetching data")

def subdomain_lookup(target):
    print("\n[ + ] Subdomains (hackertarget.com)")
    r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}")
    print(r.text if r.status_code == 200 else "Error fetching data.")

def ipwhois_lookup(target):
    print("\n[ + ] IP Whois (ipwho.is)")
    r = requests.get(f"https://ipwho.is/{target}")
    print(r.json())

def check_breach(target):
    print("\n[ + ] Breach Lookup (haveibeenpwned.com)")
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        r = requests.get(f"https://haveibeenpwned.com/unifiedsearch/{target}", headers=headers)
        soup = BeautifulSoup(r.text, 'html.parser')
        print(soup.get_text())
    except Exception as e:
        print(f"Error or blocked: {e}")

def password():
    clear()
    print("Enter passwords to verify (one per line, empty to finish): ")
    inputs = []
    while True:
        line = input()
        if not line.strip():
            break
        inputs.append(line.strip())
    check_passwords(inputs)
    print('\n')

def lookup():
    target = input("Enter the target (IP addres or domain): ").strip()

    ip_lookup(target)
    crtsh_lookup(target)
    subdomain_lookup(target)
    ipwhois_lookup(target)
    if "@" in target:
        check_breach(target)
    else:
        pass

    print('\n')

def main():
    clear()
    text = '''
* * * * * * * * * * * * * * *
* 1. Password Breach Check  *
* 2. IP or domain lookup    *
* * * * * * * * * * * * * * *
'''

    print(text)
    choice = int(input('Enter your choice: '))

    if choice == 1: password()
    elif choice == 2: lookup()
    else: print('\nError, invalid option')

if __name__ == "__main__":
    main()
