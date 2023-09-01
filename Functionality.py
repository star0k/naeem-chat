import socket
import bcrypt
import smtplib
import jwt
import re
import random
from email.message import EmailMessage

class Configs:
    def __init__(self,host='',port='',secret='',email='',password=''):
        self.SECRET = secret
        self.HOST = host
        self.PORT = port
        self.online_users = {}
        self.SMTP_SERVER = "smtp.gmail.com"
        self.SMTP_PORT = 465
        self.GMAIL_ADDRESS = email
        self.GMAIL_PASSWORD = password

    def is_valid_email(self, email: str) -> bool:
        """Check if the given string is a valid email format."""
        return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

    def generate_verification_code(self) -> str:
        """Generate a random 6-digit verification code."""
        return ''.join(random.choices('0123456789', k=6))

    def generate_token(self, username):

        return jwt.encode( {'user': username}, self.SECRET, algorithm='HS256')

    def is_authenticated(self, sid, token, username):
        dic = self.online_users
        user_data = dic.get(username, {})
        return sid == user_data.get('sid') and token == user_data.get('token') and username == self.decode_token(token)

    def decode_token(self, token):
        try:
            decoded = jwt.decode(token, self.SECRET, algorithms=['HS256'])
            return decoded['user']
        except jwt.DecodeError:
            return None

    def send_email_verification(self,email, code):
        # Gmail SMTP server configuration
          # If using 2-Step Verification, use the App Password here

        # Create server object with SSL option

        msg = EmailMessage()
        msg['Subject'] = "Verify your email"
        msg['From'] = self.GMAIL_ADDRESS
        msg['To'] = email
        msg.set_content(f"your verification code is : {code}")
        try:
            with smtplib.SMTP_SSL(self.SMTP_SERVER, self.SMTP_PORT) as server:
                server.login(self.GMAIL_ADDRESS, self.GMAIL_PASSWORD)
                server.send_message(msg)

            print("Email sent successfully!")
        except Exception as e:
            print(f"Error while sending email: {e}")

    def hash_password(self,password: str) -> bytes:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt)

    def check_password(self,password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(password.encode(), hashed)
def get_wlan_ip():
    try:
        # Getting the hostname
        hostname = socket.gethostname()
        # Getting the IP address using the hostname
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        print(f"Could not get IP: {e}")
        return "127.0.0.1"  # Fallback to localhost
