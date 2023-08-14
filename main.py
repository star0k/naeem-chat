import datetime
import os
import sqlite3
from cryptography.fernet import Fernet
import bcrypt
import smtplib
import jwt
import re
import random
import socketio
from email.message import EmailMessage

from aiohttp import web
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    username = Column(String, primary_key=True)
    fullname = Column(String)
    email = Column(String)
    password = Column(String)
    bio = Column(String)
    profile_image = Column(String)
    verification_code = Column(String)
    isverified = Column(Boolean)
    iscompleted = Column(Boolean)
    native_language = Column(String)
    interest_language = Column(String)


class Message(Base):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True, autoincrement=True)
    sender = Column(String, ForeignKey('users.username'))
    recipient = Column(String, ForeignKey('users.username'))
    message = Column(String)
    isread = Column(Integer)
    isnotify = Column(Integer)
    timestamp = Column(DateTime, default=func.now())


class Database:
    def __init__(self, db_name="sqlite:///chat.db"):
        self.engine = create_engine(db_name, echo=True)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)

    def authenticate_user(self, username, password):
        user = self.session.query(User).filter_by(username=username).one_or_none()
        return user and check_password(password, user.password)


    def store_message(self, sender, recipient, message, isread):
        new_message = Message(sender=sender, recipient=recipient, message=message, isread=isread)
        self.session.add(new_message)
        self.session.commit()

    # You would continue in this fashion for all methods...


def is_valid_email(email: str) -> bool:
    """Check if the given string is a valid email format."""
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

def email_exists(email: str, cursor) -> bool:
    """Check if the email is already registered."""
    cursor.execute("SELECT email FROM users WHERE email=?", (email,))
    return bool(cursor.fetchone())

def username_exists(username: str, cursor) -> bool:
    """Check if the username is already registered."""
    cursor.execute("SELECT username FROM users WHERE username=?", (username,))
    return bool(cursor.fetchone())

def generate_verification_code() -> str:
    """Generate a random 6-digit verification code."""
    return ''.join(random.choices('0123456789', k=6))

SECRET  = 'K8^mZ7!bQ4@Tz&2lO#3cX$6u%5iP1*yV0e+J9s~A-|dH_W:G;f<R>F{S}p[=]'  # Should be a long, random string
def generate_token(username):

    return jwt.encode({'user': username}, SECRET, algorithm='HS256')
def is_authenticated(sid, token, username):
    user_data = users_sockets.get(username, {})
    return sid == user_data.get('sid') and token == user_data.get('token') and username == decode_token(token)

def decode_token(token):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
        return decoded['user']
    except jwt.DecodeError:
        return None




def send_email_verification(email, code):
        # Gmail SMTP server configuration
        SMTP_SERVER = "smtp.gmail.com"
        SMTP_PORT = 465
        GMAIL_ADDRESS = "samerhabbal89@gmail.com"
        GMAIL_PASSWORD = "uwoletedyumokjxa"  # If using 2-Step Verification, use the App Password here

        # Create server object with SSL option

        msg = EmailMessage()
        msg['Subject'] = "Verify your email"
        msg['From'] = GMAIL_ADDRESS
        msg['To'] = email
        msg.set_content(f"your verification code is : {code}")
        try:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
                server.send_message(msg)

            print("Email sent successfully!")
        except Exception as e:
            print(f"Error while sending email: {e}")


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


# Encryption
class Encryption:
    @staticmethod
    def generate_key():
        return Fernet.generate_key()

    @staticmethod
    def encrypt_message(key, message):
        f = Fernet(key)
        return f.encrypt(message.encode())

    @staticmethod
    def decrypt_message(key, encrypted_message):
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode()


# Database
class Database:
    def __init__(self, db_name="sqlite:///chat.db"):
        self.engine = create_engine(db_name)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)

    def authenticate_user(self, username, password):
        user = self.session.query(User).filter_by(username=username).one_or_none()
        return user and check_password(password, user.password)

    def fetch_chat_partners(self, username):
        """Fetch distinct chat partners for a given username."""
        self.cursor.execute("""
            SELECT DISTINCT sender, recipient 
            FROM messages 
            WHERE sender=? OR recipient=?
        """, (username, username))
        results = self.cursor.fetchall()

        chat_partners = set()
        for row in results:
            sender, recipient = row
            partner = recipient if sender == username else sender
            chat_partners.add(partner)

        return chat_partners

    def store_message(self, sender, recipient, message, isread):
        new_message = Message(sender=sender, recipient=recipient, message=message, isread=isread)
        self.session.add(new_message)
        self.session.commit()

    def fetch_messages(self, username, date):
        messages = self.session.query(Message).filter(
            (Message.recipient == username) | (Message.sender == username), Message.timestamp >= date
        ).all()
        return [msg.__dict__ for msg in messages]

    def mark_message_delivered(self, message_id):
        message = self.session.query(Message).filter_by(id=message_id).one_or_none()
        if message:
            message.isread = 1
            self.session.commit()

    def mark_message_read(self, message_id):
        message = self.session.query(Message).filter_by(id=message_id).one_or_none()
        if message:
            message.isread = 2
            self.session.commit()

    def register_user(self, username, hashed_password, email):
        new_user = User(username=username, password=hashed_password, email=email, isverified=False)
        self.session.add(new_user)
        self.session.commit()

    def user_data(self, username):
        user = self.session.query(User).filter_by(username=username).one_or_none()
        return user.__dict__ if user else None

    def verify_email(self, username, verification_code):
        user = self.session.query(User).filter_by(username=username).one_or_none()
        if user and user.verification_code == verification_code:
            user.isverified = True
            self.session.commit()
            return True
        return False

    def is_verified(self, username):
        user = self.session.query(User).filter_by(username=username).one_or_none()
        return user.isverified if user else False

    def change_password(self, username, new_password, old_password=None, verification_code=None):
        user = self.session.query(User).filter_by(username=username).one_or_none()
        if not user:
            return False

        # If old password is provided, check it.
        if old_password and not self.authenticate_user(username, old_password):
            return False

        # If verification code is provided, check it.
        if verification_code and user.verification_code != verification_code:
            return False

        user.password = hash_password(new_password)
        self.session.commit()
        return True

    # This is an internal method, no direct ORM equivalent so we'll use the already created methods
    def _get_user_verification_code(self, username):
        user = self.user_data(username)
        return user['verification_code'] if user else None

    def email_exists(self, email):
        """Checks if an email exists in the database."""
        user = self.session.query(User).filter_by(email=email).one_or_none()
        return user is not None

    def username_exists(self, username):
        """Checks if a username exists in the database."""
        user = self.session.query(User).filter_by(username=username).one_or_none()
        return user is not None

    def insert_user(self, username, hashed_password, email, fullname, verification_code):
        """Inserts a new user into the database."""
        new_user = User(username=username, password=hashed_password, email=email,
                        fullname=fullname, verification_code=verification_code,
                        isverified=False, iscompleted=False)
        self.session.add(new_user)
        self.session.commit()
    def fetch_messages_with_status_differences(self, username, date):
        """Fetches messages where isread and isnotify statuses differ."""
        messages = self.session.query(Message).filter(
            Message.sender == username,
            Message.timestamp > date,
            Message.isread != Message.isnotify
        ).all()
        return [msg.__dict__ for msg in messages]

    def update_message_notification_status(self, message_id, status):
        """Updates the isnotify status for a message."""
        message = self.session.query(Message).filter_by(id=message_id).one_or_none()
        if message:
            message.isnotify = status
            self.session.commit()
# Server
HOST = '172.20.10.2'
HOST = '192.168.1.11'
PORT = 65432
sio = socketio.AsyncServer(cors_allowed_origins="*")
app = web.Application()
app.router.add_static('/user_images/', path='user_images', name='user_images')
sio.attach(app)

users_sockets = {}  # Dictionary to map username to socket ID

@sio.event
async def connect(sid, environ):
    username = next((user for user, details in users_sockets.items() if details['sid'] == sid), None)
    print(f"Connection Established with: {sid} user : {username if username else 'not auth yet'}")
    print(f'online users : {users_sockets}')

@sio.event
async def disconnect(sid):
    # Identify the username associated with the sid
    user_to_remove = None
    for username, details in users_sockets.items():
        if details['sid'] == sid:
            user_to_remove = username
            break

    # Remove the identified user from the dictionary
    username = next((user for user, details in users_sockets.items() if details['sid'] == sid), None)
    print(f"Connection closed with: {sid} user : {username if username else 'not auth yet'}")
    if user_to_remove:
        del users_sockets[user_to_remove]

    print(f'online users : {list(users_sockets.keys())}')

@sio.on("signin")
async def signin(sid, data):

    try:

        print('insignin')
        username = data.get('username')
        password = data.get('password')
        db = Database()

        if db.authenticate_user(username, password):  # Assuming `authenticate_user` checks the hashed password
            token = generate_token(username)
            users_sockets[username] = {'sid': sid, 'token': token}
            print('send data')

            user_data_result = db.user_data(username)
            print(user_data_result)
            await sio.emit("signin-response", {'retcode': 0, 'token': token, "data": user_data_result}, to=sid)

            print('data sent')

        else:
            print('invalid sent')
            await sio.emit("signin-response", {'retcode': 1, "message": "Invalid credentials."}, to=sid)
    except Exception as n:
        print(f'error {n}')
        await sio.emit("signin-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
    print(f'online users : {list(users_sockets.keys())}')


@sio.on("fetch-chats")
async def fetch_chats(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        db = Database()

        if is_authenticated(sid, token, username):

            # Use the new fetch_chat_partners method
            chat_partners = db.fetch_chat_partners(username)

            # Fetch chat partners data
            chat_data_list = []
            base_url = f"http://{HOST}:{PORT}/user_images"  # Make sure HOST and PORT are defined

            for partner in chat_partners:
                partner_data = db.user_data(partner)
                if not partner_data['profile_image']:
                    first_letter = partner_data['fullname'][0].upper() if partner_data and 'fullname' in partner_data and \
                                                                          partner_data['fullname'] else None

                    # If we have an image for this letter, set it as profile image
                    if first_letter and os.path.exists(f"user_images/{first_letter}.png"):
                        partner_data['profile_image'] = f"{base_url}/{first_letter}.png"
                    else:
                        # Default image if something goes wrong
                        partner_data['profile_image'] = 'https://cdn-icons-png.flaticon.com/512/6646/6646479.png'

                partner_data['bio'] = 'mmm'
                partner_data['interest_language'] = 'en'
                partner_data['native_language'] = 'ar'
                chat_data_list.append(partner_data)

            # Emit the chat data list back to the user
            await sio.emit("chats-response", {'retcode': 0, "data": chat_data_list}, to=sid)
            print(chat_data_list)

        else:
            await sio.emit("chats-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)

    except Exception as e:
        print(f"Error: {e}")
        await sio.emit("chats-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)

@sio.on("user-online")
async def user_online(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        partner= data.get('partner')
        db = Database()

        if is_authenticated(sid, token, username):
            if partner in users_sockets :
                await sio.emit("online-response", {'retcode': 0, "messages": 'online'}, to=sid)
        else:
            await sio.emit("online-response", {'retcode': 1, "messages": 'offline'}, to=sid)

    except Exception as e:
        print(f"Error: {e}")
        await sio.emit("chats-response", {'retcode': 999, "message": e}, to=sid)
@sio.on("fetch-messages")
async def fetch_messages(sid, data):
    print('asked for messages')
    try:
        username = data.get('username')
        token = data.get('token')
        date = data.get('date') if data.get('date') else "1970-01-01 00:00:00"
        db = Database()

        user_data = users_sockets.get(username, {})
        if is_authenticated(sid, token, username):
            messages = db.fetch_messages(username, date)
            for message in messages:
                db.cursor.execute("""
                    UPDATE messages 
                    SET isnotify = isread
                    WHERE id = ?
                """, (int(message['id']),))
                db.conn.commit()
            # List to keep track of senders whose messages were marked as delivered
            senders_notified = set()

            # Mark these messages as delivered (isread = 1) only if the recipient is the user
            for message in messages:
                if message["recipient"] == username and message["isread"] == 0:
                    db.update_message_as_read(message["id"])  # Assuming you've added this method

                    # If the sender is online and not yet notified, inform them that their message has been delivered
                    try :
                        sender = message["sender"]
                        if sender not in senders_notified and sender in users_sockets:
                            senders_notified.add(sender)
                            sender_sid = users_sockets[sender]['sid']
                            await sio.emit("live", {
                                'action': 'delivered',
                                'delivered_to': username,
                                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            }, to=sender_sid)
                    except:
                        print('error in partner olnile')

            await sio.emit("messages", {'retcode': 0, "data": messages}, to=sid)
            print('sent data')
        else:
            await sio.emit("messages", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except Exception as e :
        print(e)
        await sio.emit("messages", {'retcode': 999, "message": f'e'}, to=sid)
@sio.on("read-chat")
async def read_conversation(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        chat_partner = data.get('partner')
        db = Database()

        if is_authenticated(sid, token, username):
            # Update all messages where the user is the recipient and isread is not 2 to be marked as isread=2
            db.cursor.execute("UPDATE messages SET isread=2 WHERE recipient=? AND sender=? AND isread!=2",
                              (username, chat_partner))
            db.conn.commit()
            # If the chat_partner is online, inform them that their messages have been seen
            if chat_partner in users_sockets:
                chat_partner_sid = users_sockets[chat_partner]['sid']
                await sio.emit("live", {
                    'action': 'seen',
                    'seen_by': username,
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }, to=chat_partner_sid)
        else:
            await sio.emit("chat-read", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await sio.emit("chat-read", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
@sio.on("send-message")
async def send_message(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        chat_partner = data.get('partner')
        message_text = data.get('message')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(token)
        print(f'username : {username}')
        db = Database()
        print('in send message')
        if is_authenticated(sid, token, username):
            if not username_exists(chat_partner,db.cursor) :
                await sio.emit("send-message-response", {"retcode": 4, "message": "User Not Found."}, to=sid)
                return
            # Store the message in the database
            db.cursor.execute("INSERT INTO messages (sender, recipient, message, timestamp, isread) VALUES (?, ?, ?, ?, ?)",
                              (username, chat_partner, message_text, timestamp, 0))
            db.conn.commit()
            message_id = db.cursor.lastrowid  # Get the ID of the recently inserted message

            # If the chat partner is online, send the message to them immediately
            if chat_partner in users_sockets:
                print('partner online')
                chat_partner_sid = users_sockets[chat_partner]['sid']

                acknowledged = await sio.call("live", {
                    'action': 'new_message',
                    'sender': username,
                    'message_text': message_text,
                    'timestamp': timestamp,
                    'id': message_id
                }, to=chat_partner_sid, timeout=2)  # Await an acknowledgment for up to 2 seconds

                if acknowledged and acknowledged.get('status') == 'received':
                    # Mark the message as read (isread = 2)
                    db.cursor.execute("UPDATE messages SET isread=1 WHERE id=?", (message_id,))
                    db.conn.commit()
                    print('message marked as delivered')
                await sio.emit("send-message-response", {'retcode': 1, "message": "Message processed."}, to=sid)


            print('messege sent')
            await sio.emit("send-message-response", {'retcode': 0,'id':message_id, "message": "Message sent successfully."}, to=sid)
        else:
            print('auth failed')

            await sio.emit("send-message-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except Exception as e:
        print(e)
        await sio.emit("send-message-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
@sio.on("signup")
async def signup(sid, data):
    try:
        print('in signup')
        username = data.get('username')
        password = data.get('password')
        fullname = data.get('fullname')
        email = data.get('email')
        db = Database()

        # Validation
        if not is_valid_email(email):
            print('invalid mail')
            await sio.emit("signup-response", {"retcode": 1, "message": "Invalid email format."}, to=sid)
            return

        if db.email_exists(email):
            print('exist mail')
            await sio.emit("signup-response", {"retcode":2, "message": "Email Already Registered."}, to=sid)
            return

        if db.username_exists(username):
            print('exist username')
            await sio.emit("signup-response", {"retcode":3, "message": "Username exists."}, to=sid)
            return

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        verification_code = generate_verification_code()

        # Store in database
        db.insert_user(username, hashed_password, email, fullname, verification_code)

        # Send verification code to email
        send_email_verification(email, verification_code)
        print('signed up')
        await sio.emit("signup-response", {"retcode": 0 ,"message": "User registered. Please check email for verification code."}, to=sid)

    except Exception as e:
        print(f'error {e}')
        await sio.emit("signup-response", {"retcode": 999, "message": f"Unknown error occurred. {e}"}, to=sid)
@sio.on("fetch-messages-status")
async def fetch_messages_status(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        date = "1970-01-01 00:00:00"
        db = Database()

        if is_authenticated(sid, token, username):

            # Fetch messages for the user where isread and isnotify differ
            messages = db.fetch_messages_with_status_differences(username, date)
            status_updates = [{"message_id": message["id"], "isread": message["isread"]} for message in messages]

            # Update isnotify for these messages
            for message in messages:
                db.update_message_notification_status(message["id"], message["isread"])

            await sio.emit("messages-status-response", {'retcode': 0, "data": status_updates}, to=sid)

        else:
            await sio.emit("messages-status-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)

    except Exception as e:
        print(f"Error: {e}")
        await sio.emit("messages-status-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)

@sio.on("verify-user")
async def verify_user(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        verification_code = data.get('code')
        db = Database()

        if is_authenticated(sid, token, username):

            if db.verify_email(username,verification_code) :
                await sio.emit("verification-response", {"retcode": 0, "message": "user verified"}, to=sid)
            else :
                await sio.emit("verification-response", {"retcode": 1, "message": "Wrong code"}, to=sid)

        else:
            print('auth error')
            await sio.emit("verification-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await sio.emit("verification-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)\

@sio.on("change-password")
async def change_password(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        verification_code = data.get('code')
        newpassword = data.get('newpassword')
        oldpassword = data.get('oldpassword')
        db = Database()

        if is_authenticated(sid, token, username):
            if db.change_password(username, newpassword,oldpassword, verification_code) :
                await sio.emit("change-password-response", {"retcode": 0, "message": "passwor dchanged"}, to=sid)
            else :
                await sio.emit("verification-response", {"retcode": 1, "message": "Wrong "}, to=sid)

        else:
            print('auth error')
            await sio.emit("verification-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await sio.emit("verification-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
@sio.on("request-verification-code")
async def resend_verification_code(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        db = Database()

        if is_authenticated(sid, token, username):

            verification_code = generate_verification_code()
            # Store in database
            db.cursor.execute("UPDATE users SET verification_code=? WHERE username=?", (verification_code,username,))
            db.conn.commit()
            db.cursor.execute("SELECT email FROM users WHERE username=?", (username,))
            email = db.cursor.fetchone()
            print(email)
            # Send verification code to email
            send_email_verification(email, verification_code)
            await sio.emit("code-request-response",
                           {"retcode": 0, "message": "Code sent. Please check email for verification code."},
                           to=sid)

        else:
            await sio.emit("code-request-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await sio.emit("code-request-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)

if __name__ == "__main__":
    web.run_app(app,host=HOST, port=PORT)
