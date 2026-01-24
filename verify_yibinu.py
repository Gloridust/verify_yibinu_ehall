import requests
from bs4 import BeautifulSoup
import re
import random
import base64
import logging
import sys
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TLSAdapter(requests.adapters.HTTPAdapter):
    """
    Custom TLS adapter to handle legacy SSL/TLS versions and ciphers.
    """
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        # Set security level to 1 to allow legacy ciphers if needed
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

def get_random_string(length: int) -> str:
    """Generate a random string of fixed length."""
    chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    return ''.join(random.choice(chars) for _ in range(length))

def encrypt_password(password: str, salt: str) -> str:
    """
    Encrypt the password using AES-CBC, following the logic in encrypt.wisedu.js.
    """
    data = get_random_string(64) + password
    key = salt.encode('utf-8')
    iv = get_random_string(16).encode('utf-8')
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

def verify_login(username: str, password: str, timeout: int = 10) -> Tuple[bool, str]:
    """
    Verify login credentials for Yibin University auth server.
    """
    login_url = (
        "https://authserver.yibinu.edu.cn/authserver/login"
        "?service=https%3A%2F%2Fehall.yibinu.edu.cn%3A443%2Flogin"
        "%3Fservice%3Dhttps%3A%2F%2Fehall.yibinu.edu.cn%2Fnew%2Findex.html"
    )
    
    session = requests.Session()
    session.mount('https://', TLSAdapter())
    session.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )
    })
    
    try:
        # 1. Get login page
        logger.debug("Fetching login page...")
        response = session.get(login_url, verify=False, timeout=timeout)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract hidden fields
        hidden_fields = {}
        for name in ['lt', 'execution', 'dllt', '_eventId', 'rmShown']:
            field = soup.find('input', {'name': name})
            if field:
                hidden_fields[name] = field.get('value', '')
            else:
                logger.warning(f"Hidden field '{name}' not found.")
                hidden_fields[name] = ''

        # Extract salt from script
        salt_match = re.search(r'var pwdDefaultEncryptSalt = "(.*?)";', response.text)
        salt = salt_match.group(1) if salt_match else "E5b2IYX5TT1D79TA"
        
        # 2. Check if captcha is needed and potentially get a new salt
        need_captcha_url = "https://authserver.yibinu.edu.cn/authserver/needCaptcha.html"
        captcha_res = session.get(
            need_captcha_url, 
            params={'username': username, 'pwdEncrypt2': 'pwdEncryptSalt'}, 
            verify=False,
            timeout=timeout
        )
        if "::::" in captcha_res.text:
            salt = captcha_res.text.split("::::")[1]
            logger.debug(f"Salt updated from captcha check: {salt}")
        
        # 3. Encrypt password
        encrypted_pwd = encrypt_password(password, salt)
        
        # 4. Post login data
        data = {
            'username': username,
            'password': encrypted_pwd,
            **hidden_fields
        }
        
        logger.debug("Submitting login form...")
        post_response = session.post(
            login_url, 
            data=data, 
            allow_redirects=False, 
            verify=False,
            timeout=timeout
        )
        
        # 5. Check result
        # If successful, it usually redirects to the service URL (302)
        if post_response.status_code == 302:
            return True, "Login successful"
        else:
            # Check for error message in the response
            error_soup = BeautifulSoup(post_response.text, 'html.parser')
            error_msg = error_soup.find('span', {'id': 'errorMsg'})
            msg = error_msg.text.strip() if error_msg else "Login failed: Invalid credentials or session timeout"
            return False, msg

    except requests.exceptions.SSLError as e:
        return False, f"SSL Error: {str(e)}"
    except requests.exceptions.Timeout:
        return False, "Request timed out. Please check your network connection."
    except requests.exceptions.RequestException as e:
        return False, f"Network error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verify_yibinu.py <username> '<password>'")
        print("Note: If your password contains special characters like '!', wrap it in single quotes.")
    else:
        user = sys.argv[1]
        pwd = sys.argv[2]
        
        # You can change level to logging.DEBUG to see more details
        # logger.setLevel(logging.DEBUG)
        
        success, message = verify_login(user, pwd)
        print(f"\nResult: {'Success' if success else 'Failed'}")
        print(f"Message: {message}")
