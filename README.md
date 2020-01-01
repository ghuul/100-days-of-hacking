# 100 Days of Boxes
You've heard of 100 days of code, but have you heard of 100 days of boxes? That's right, hacking
one box a day - in addition to doing a writeup of dubious quality.

"Wow, this challenge sounds awesome!" you say. It certainly does. It is important to keep in mind,
however, that I'm currently a computer science student at university, and this sort of challenge
isn't the most feasible for people without a lot of time on their hands. 

## Box Sources
 * [HackTheBox](https://hackthebox.eu)
 * [VulnHub](https://vulnhub.com)

## Decrypting HackTheBox Writeups
Active HackTheBox writeups can be decrypted using their root flag as the password.
```bash
openssl enc -aes-256-cbc -d -in htb-<name>.tar.gz.enc -pbkdf2 | tar xz
```
