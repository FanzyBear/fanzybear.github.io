---
title: "First Bounty"
date: 2026-05-07 11:14:00 +0800
categories: [Bug Bounty, Penetration Testing]
tags: [xss, sql-injection, access-control, authentication-bypass, password-cracking, weak-crypto, des-encryption, excel-injection, web-hacking, pii-leak]
image:
  path: assets/Preview/first-bounty.png
---

## Chaining XSS, Massive PII Leaks, Custom Crypto Bypass and excel injection via unsanitized spreadsheet export

I finally got my hands on my first real web pentest recently (let's call the target Company A). I’m still fairly new to web hacking, but I ended up finding some pretty weird edge cases and chaining together a few fun bugs. Here’s a quick dump of how it went down.

### 1. The SQL error that turned into XSS

First thing I looked at was a data table with a filter feature. The app was passing JSON arrays directly in the URL parameters:

```
/index.php?hdl=REDACTED&action=REDACTED&partnercode=REDACTED...&filter=[{"property":"test","value":"test","type":"REDACTED"}]
```

I started messing with the JSON. I changed the `property` and `value` to garbage data (`oceanwarranty`) that I knew wasn't in the database. The backend threw a raw MySQL error, but the behavior was super weird.

If I sent the request with the `partnercode` parameter, it threw a generic syntax error. But if I dropped the `partnercode` parameter entirely, the error changed to: `SQLSTATE [42S22] : Column not found: 1054 Unknown column 'oceanwarranty' in 'where clause` 

It was reflecting my input directly in the error. I spent way too long trying to break out of the query to get a working SQLi, but I kept hitting a wall. Since it was reflecting raw text into the DOM anyway, I gave up on the SQLi and just tried for XSS.

I swapped the property name for a basic payload:

```json
{"property":"<script>alert()</script>","value":"REDACTED"}
```

It popped. Easy reflected XSS.

### 2. Dropping parameters led to a massive PII leak

Later on, I was looking at the `changepassword` action. There were no CSRF tokens, so I was dropping parameters one by one in Burp just to see how the backend handled broken requests.

Somewhere in that process, I stumbled onto an API endpoint with completely broken access control. No auth checks at all. It just dumped a massive JSON response containing other users' data: IDs, usernames, emails, phone numbers, last login IPs, and active password reset tokens.

It also leaked hashed passwords and old hashed passwords. I threw a few of them against a rainbow table and cracked them instantly.

### 3. Locking myself out and bypassing the frontend crypto

I wanted to check if there was any rate limiting in place, so I targeted the `changepassword` endpoint. A standard request looked like this:

```
hld=user&action=changepassword&user_name=admin&oldpassword=redacted&newpassword=redacted&confirmpassword=redacted
```

I started stripping parameters and realized I could use this endpoint as an oracle to brute-force accounts. If I just sent the `oldpassword` parameter via Burp Intruder:

```
hld=user&action=changepassword&user_name=admin&oldpassword=[FUZZ]
``` 

The server gave me distinct responses.
If the password was wrong, it threw:

```json
{"success": false, "errmsg": "Unable to validate current passvord", "field":"oldpassvord"}
```

But if the password was correct, the error changed to:

```json
{"success": false, "id":0, "field":"", "errmsg":"The value chosen for field (username) already exists. Please choose another one"}
```

This created an authentication oracle vulnerability—I could brute-force valid passwords based on distinct error messages.

So, I started tweaking the parameters in Intruder to test the limits. Somewhere in that mess of fuzzing, my account suddenly stopped letting another log in. I thought I had finally hit a rate limit or triggered a lockout.

Since my session was actually still alive on that leaky API endpoint from the second bug, I pulled my own user record to see what happened. Turns out I wasn't locked out and one of my malformed requests had accidentally changed my account's password to a blank string.

I went back to the login page and tried to log in with an empty password, but the UI blocked it. I tried intercepting a normal login request to just clear out the password field in Burp, but the password payload was encrypted hex.

I checked the client-side JS and found this:

```jsx
function doLogin() { 
  result = stringToHex( des( document.getElementById('salt').value, document.getElementById('pass').value, 1, 0 ) ); 
  document.getElementById('pass').value = result; 
  document.getElementById('tzoffset').value = new Date().getTimezoneOffset(); 
}
```

They were taking the plaintext password, encrypting it with DES using a hardcoded salt/key, converting it to hex, and sending it.

To get back into my account, I just needed to generate the encrypted hex value for a blank password. I wrote a quick Python script to mimic their setup using the hardcoded key (`468E34yP80J7500dFKj0bWjf`):

```python
from Crypto.Cipher import DES3

def encrypt(password):
    key = b"468E34yP80J7500dFKj0bWjf"  
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded = password.encode().ljust(8, b'\x00')
    encrypted = cipher.encrypt(padded)
    return encrypted.hex()

print(encrypt(""))
```

I grabbed the hex output, pasted it into my intercepted login request in Burp, and got straight in. Changed my password back to normal immediately.

### 4. Excel Formula Injection via URL headers

Last finding of the run. The app had a feature to export table data to an Excel file. I noticed the column headers were being passed as a JSON array right in the URL:

```json
[{"text":"Product", "index":"redacted"}, {"text":"Price", "index":"redacted"}]
```

I wanted to see if they were sanitizing this before dropping it into the `.xlsx` file, so I injected a basic formula:

```json
{"text":"=HYPERLINK(\"http://example.com\", \"Click\")", "index":"redacted"}
```

When I downloaded and opened the spreadsheet, the raw payload was gone. Instead, it rendered as a functional "Click" hyperlink that redirected straight to my external domain. Since the file is generated and downloaded from the company's legitimate domain, it would be incredibly easy to social engineer an employee into clicking it.

There are probably more bugs hiding in this app, but I’m pretty happy with this haul.