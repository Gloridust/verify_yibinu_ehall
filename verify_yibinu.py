import requests
from bs4 import BeautifulSoup
import re
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import ssl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TLSAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

def get_random_string(length):
    chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    return ''.join(random.choice(chars) for _ in range(length))

def encrypt_password(password, salt):
    # The logic from encrypt.wisedu.js:
    # var encrypted = getAesString(randomString(64) + data, aesKey, randomString(16));
    
    data = get_random_string(64) + password
    key = salt.encode('utf-8')
    iv = get_random_string(16).encode('utf-8')
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

def verify_login(username, password):
    login_url = "https://authserver.yibinu.edu.cn/authserver/login?service=https%3A%2F%2Fehall.yibinu.edu.cn%3A443%2Flogin%3Fservice%3Dhttps%3A%2F%2Fehall.yibinu.edu.cn%2Fnew%2Findex.html"
    
    session = requests.Session()
    session.mount('https://', TLSAdapter())
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })
    
    # 1. Get login page
    response = session.get(login_url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extract hidden fields
    lt = soup.find('input', {'name': 'lt'})['value']
    execution = soup.find('input', {'name': 'execution'})['value']
    dllt = soup.find('input', {'name': 'dllt'})['value']
    _event_id = soup.find('input', {'name': '_eventId'})['value']
    rm_shown = soup.find('input', {'name': 'rmShown'})['value']
    
    # Extract salt
    salt_match = re.search(r'var pwdDefaultEncryptSalt = "(.*?)";', response.text)
    salt = salt_match.group(1) if salt_match else "E5b2IYX5TT1D79TA"
    
    # 2. Check if captcha is needed and potentially get a new salt
    need_captcha_url = "https://authserver.yibinu.edu.cn/authserver/needCaptcha.html"
    captcha_res = session.get(need_captcha_url, params={'username': username, 'pwdEncrypt2': 'pwdEncryptSalt'}, verify=False)
    if "::::" in captcha_res.text:
        salt = captcha_res.text.split("::::")[1]
    
    # 3. Encrypt password
    encrypted_pwd = encrypt_password(password, salt)
    
    # 4. Post login data
    data = {
        'username': username,
        'password': encrypted_pwd,
        'lt': lt,
        'dllt': dllt,
        'execution': execution,
        '_eventId': _event_id,
        'rmShown': rm_shown
    }
    
    # The form submits to the same URL
    post_response = session.post(login_url, data=data, allow_redirects=False, verify=False)
    
    # 5. Check result
    # If successful, it usually redirects to the service URL (302)
    if post_response.status_code == 302:
        return True, "Login successful"
    else:
        # Check for error message in the response
        error_soup = BeautifulSoup(post_response.text, 'html.parser')
        error_msg = error_soup.find('span', {'id': 'errorMsg'})
        msg = error_msg.text.strip() if error_msg else "Login failed"
        return False, msg

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python verify_yibinu.py <username> <password>")
    else:
        user = sys.argv[1]
        pwd = sys.argv[2]
        success, message = verify_login(user, pwd)
        print(f"Result: {'Success' if success else 'Failed'}")
        print(f"Message: {message}")
