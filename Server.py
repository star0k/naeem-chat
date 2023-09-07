import datetime
import bcrypt
import socketio
import base64
from aiohttp import web
from Functionality import Configs,get_wlan_ip
from Database import Database
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
# Load environment variables from .env file
load_dotenv()
socket_service = socketio.AsyncServer(cors_allowed_origins="*")
app = web.Application()
app.router.add_static('/profile_images/', path='profile_images', name='profile_images')
socket_service.attach(app)
online_users = {}
get = Configs(
    host=os.environ.get('HOST', get_wlan_ip()),
    port=int(os.environ.get('PORT', 65432)),
    secret=os.environ.get('SECRET', 'njdskfhjdkshfjkdshfjkdshfjkdshnfjksdhjkfhs'),
    email=os.environ.get('GMAIL_ADDRESS', 'samerhabbal89@gmail.com'),
    password=os.environ.get('GMAIL_PASSWORD', 'uwoletedyumokjxa'),

)
@socket_service.event
async def connect(sid, environ):
    global get
    username = next((user for user, details in get.online_users.items() if details['sid'] == sid), None)
    print(f"Connection Established with: {sid} user : {username if username else 'not auth yet'}")
    print(f'online users : {get.online_users}')

@socket_service.event
async def disconnect(sid):
    global get

    # Identify the username associated with the sid
    user_to_remove = None
    for username, details in get.online_users.items():
        if details['sid'] == sid:
            user_to_remove = username
            break

    # Remove the identified user from the dictionary
    username = next((user for user, details in get.online_users.items() if details['sid'] == sid), None)
    print(f"Connection closed with: {sid} user : {username if username else 'not auth yet'}")
    if user_to_remove:
        del get.online_users[user_to_remove]

    print(f'online users : {list(get.online_users.keys())}')

@socket_service.on("signin")
async def signin(sid, data):
    global get
    print(get.PORT)
    try:

        print('insignin')
        username = data.get('username')
        password = data.get('password')
        db = Database()
        print('pass')
        if db.authenticate_user(username, password):  # Assuming `authenticate_user` checks the hashed password
            print('pass2')
            token = get.generate_token(username)
            get.online_users[username] = {'sid': sid, 'token': token}
            print('send data')

            user_data_result = db.user_data(username)
            print(user_data_result)
            if user_data_result['profile_image']:
                user_data_result['profile_image'] = f"http://{get.HOST}:{get.PORT}/{user_data_result['profile_image']}"

            else:
                user_data_result['profile_image'] = ""
            await socket_service.emit("signin-response", {'retcode': 0, 'token': token, "data": user_data_result}, to=sid)

            print('data sent')

        else:
            print('invalid sent')
            await socket_service.emit("signin-response", {'retcode': 1, "message": "Invalid credentials."}, to=sid)
    except Exception as n:
        print(f'error {n}')
        await socket_service.emit("signin-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
    print(f'online users : {list(get.online_users.keys())}')


@socket_service.on("fetch-chats")
async def fetch_chats(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        db = Database()

        if get.is_authenticated(sid, token, username):

            # Use the new fetch_chat_partners method
            chat_partners = db.fetch_chat_partners(username)

            # Fetch chat partners data
            chat_data_list = []
            # base_url = f"http://{get.HOST}:{get.PORT}/user_images"  # Make sure HOST and PORT are defined

            for partner in chat_partners:
                partner_data = db.user_data(partner)
                if  partner_data['profile_image']:
                    partner_data['profile_image'] = f"http://{get.HOST}:{get.PORT}/{partner_data['profile_image']}"

                else:
                    partner_data['profile_image'] = ""

                partner_data['bio'] = 'mmm'
                partner_data['interest_language'] = 'en'
                partner_data['native_language'] = 'ar'
                chat_data_list.append(partner_data)

            # Emit the chat data list back to the user
            await socket_service.emit("chats-response", {'retcode': 0, "data": chat_data_list}, to=sid)
            print(chat_data_list)

        else:
            await socket_service.emit("chats-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)

    except Exception as e:
        print(f"Error: {e}")
        await socket_service.emit("chats-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
@socket_service.on("user-online")
async def user_online(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        partner= data.get('partner')
        db = Database()

        if get.is_authenticated(sid, token, username):
            if partner in get.online_users :
                await socket_service.emit("online-response", {'retcode': 0, "messages": 'online'}, to=sid)
        else:
            await socket_service.emit("online-response", {'retcode': 1, "messages": 'offline'}, to=sid)

    except Exception as e:
        print(f"Error: {e}")
        await socket_service.emit("chats-response", {'retcode': 999, "message": e}, to=sid)
@socket_service.on("fetch-messages")
async def fetch_messages(sid, data):
    print('asked for messages')
    try:
        username = data.get('username')
        token = data.get('token')
        date = data.get('date') if data.get('date') else "1970-01-01 00:00:00"
        db = Database()

        user_data = get.online_users.get(username, {})
        if get.is_authenticated(sid, token, username):
            messages = db.fetch_messages(username, date)

            senders_notified = set()
            await socket_service.emit("messages", {'retcode': 0, "data": messages}, to=sid)
            print('sent data')
            # Iterate through the messages
            for message in messages:

                # Update the isnotify status
                message_id = message['id']
                db.update_message_notification_status(message_id, message['isread'])

                # Mark these messages as delivered (isread = 1) only if the recipient is the user
                if message["recipient"] == username and message["isread"] == 0:
                    db.mark_message_delivered(message_id)

                    # If the sender is online and not yet notified, inform them that their message has been delivered
                    try:
                        sender = message["sender"]
                        if sender not in senders_notified and sender in get.online_users:
                            senders_notified.add(sender)
                            sender_sid = get.online_users[sender]['sid']
                            await socket_service.emit("live", {
                                'action': 'delivered',
                                'delivered_to': username,
                                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            }, to=sender_sid)
                    except:
                        print('error in partner online')


    except Exception as e :
        print(e)
        await socket_service.emit("messages", {'retcode': 999, "message": f'e'}, to=sid)
@socket_service.on("read-chat")
async def read_conversation(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        chat_partner = data.get('partner')
        db = Database()

        if get.is_authenticated(sid, token, username):
            db.mark_message_read(chat_partner)
            # If the chat_partner is online, inform them that their messages have been seen
            if chat_partner in get.online_users:
                chat_partner_sid = get.online_users[chat_partner]['sid']
                await socket_service.emit("live", {
                    'action': 'seen',
                    'seen_by': username,
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }, to=chat_partner_sid)

        else:
            await socket_service.emit("chat-read", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await socket_service.emit("chat-read", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
@socket_service.on("send-message")
async def send_message(sid, data):
    print('here')
    print(data)
    try:
        print('hereeee')
        username = data.get('username')
        token = data.get('token')
        chat_partner = data.get('partner')
        message_text = data.get('message')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(token)
        print(f'username : {username}')
        db = Database()
        print('in send message')
        if get.is_authenticated(sid, token, username):
            if not db.username_exists(chat_partner) :
                await socket_service.emit("send-message-response", {"retcode": 4, "message": "User Not Found."}, to=sid)
                return
            # Store the message in the database
            message_id = db.store_message(username,chat_partner,message_text,0,0)

            # If the chat partner is online, send the message to them immediately
            if chat_partner in get.online_users:
                print('partner online')
                chat_partner_sid = get.online_users[chat_partner]['sid']
                print(chat_partner_sid)
                acknowledged = False
                try :
                    acknowledged = await socket_service.call("live", {
                    'action': 'new_message',
                    'data' : {
                    'sender': username,
                    'recipient' : chat_partner,
                    'message': message_text,
                    'timestamp': timestamp,
                    'id': message_id}
                }, to=chat_partner_sid, timeout=2)  # Await an acknowledgment for up to 2 seconds
                except Exception as e :
                    print(e)
                if acknowledged == True :
                    if acknowledged.get('status') == 'received':
                        db.mark_message_delivered(message_id)
                        print('message marked as delivered')
                        await socket_service.emit("send-message-response", {'retcode': 1, "message": "Message processed."}, to=sid)


            print('messege sent')
            await socket_service.emit("send-message-response", {'retcode': 0, 'id':message_id, "message": "Message sent successfully."}, to=sid)
        else:
            print('auth failed')

            await socket_service.emit("send-message-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except Exception as e:
        print(e)
        await socket_service.emit("send-message-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
@socket_service.on("signup")
async def signup(sid, data):
    try:
        print('in signup')
        username = data.get('username')
        password = data.get('password')
        fullname = data.get('fullname')
        email = data.get('email')
        db = Database()

        # Validation
        if not get.is_valid_email(email):
            print('invalid mail')
            await socket_service.emit("signup-response", {"retcode": 1, "message": "Invalid email format."}, to=sid)
            return

        if db.email_exists(email):
            print('exist mail')
            await socket_service.emit("signup-response", {"retcode":2, "message": "Email Already Registered."}, to=sid)
            return

        if db.username_exists(username):
            print('exist username')
            await socket_service.emit("signup-response", {"retcode":3, "message": "Username exists."}, to=sid)
            return

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        verification_code = get.generate_verification_code()

        # Store in database
        db.insert_user(username, hashed_password, email, fullname, verification_code)
        print('signed up')
        await socket_service.emit("signup-response",
                                  {"retcode": 0, "message": "User registered. Please check email for verification code."}, to=sid)

        # Send verification code to email
        if not 'test' in email :
            get.send_email_verification(email, verification_code)

    except Exception as e:
        print(f'error {e}')
        await socket_service.emit("signup-response", {"retcode": 999, "message": f"Unknown error occurred. {e}"}, to=sid)
@socket_service.on("fetch-messages-status")
async def fetch_messages_status(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        date = "1970-01-01 00:00:00"
        db = Database()

        if get.is_authenticated(sid, token, username):

            # Fetch messages for the user where isread and isnotify differ
            messages = db.fetch_messages_with_status_differences(username, date)
            status_updates = [{"message_id": message["id"], "isread": message["isread"]} for message in messages]

            # Update isnotify for these messages
            for message in messages:
                db.update_message_notification_status(message["id"], message["isread"])

            await socket_service.emit("messages-status-response", {'retcode': 0, "data": status_updates}, to=sid)

        else:
            await socket_service.emit("messages-status-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)

    except Exception as e:
        print(f"Error: {e}")
        await socket_service.emit("messages-status-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)

@socket_service.on("verify-user")
async def verify_user(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        verification_code = data.get('code')
        db = Database()

        if get.is_authenticated(sid, token, username):

            if db.verify_email(username,verification_code) :
                await socket_service.emit("verification-response", {"retcode": 0, "message": "user verified"}, to=sid)
            else :
                await socket_service.emit("verification-response", {"retcode": 1, "message": "Wrong code"}, to=sid)

        else:
            print('auth error')
            await socket_service.emit("verification-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await socket_service.emit("verification-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)\

@socket_service.on("change-password")
async def change_password(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        verification_code = data.get('code')
        newpassword = data.get('newpassword')
        oldpassword = data.get('oldpassword')
        db = Database()

        if get.is_authenticated(sid, token, username):
            if db.change_password(username, newpassword,oldpassword, verification_code) :
                await socket_service.emit("change-password-response", {"retcode": 0, "message": "passwor dchanged"}, to=sid)
            else :
                await socket_service.emit("verification-response", {"retcode": 1, "message": "Wrong "}, to=sid)

        else:
            print('auth error')
            await socket_service.emit("verification-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await socket_service.emit("verification-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)
@socket_service.on("request-verification-code")
async def resend_verification_code(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        db = Database()

        if get.is_authenticated(sid, token, username):

            verification_code = get.generate_verification_code()

            # Set verification code using Database method
            if db.set_verification_code(username, verification_code):

                # Fetch email using Database method
                email = db.get_email_by_username(username)
                if email:
                    print(email)

                    # Send verification code to email
                    get.send_email_verification(email, verification_code)
                    await socket_service.emit("code-request-response",
                                              {"retcode": 0, "message": "Code sent. Please check email for verification code."},
                                              to=sid)

        else:
            await socket_service.emit("code-request-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await socket_service.emit("code-request-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)

@socket_service.on("advanced-users-search")
async def advance_search_users(sid, data):
    try:
        query = data.get('query')  # This contains either the username or fullname
        interest_language = data.get('interest_language')
        native_language = data.get('native_language')

        db = Database()
        results = db.advanced_user_search(query, interest_language, native_language)
        print(results)
        await socket_service.emit("advanced-search-response", {'retcode': 0, "data": results}, to=sid)

    except Exception as e:
        print(f"Error in advance user search: {e}")
        await socket_service.emit("advanced-search-response", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)


@socket_service.on("upload-profile-image")
async def upload_profile_image(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        file_data = data.get('encoded_image')  # Make sure to use the correct key
        filename = data.get('filename')  # You can set a default name

        if not get.is_authenticated(sid, token, username):
            await socket_service.emit("upload-image-response", {"retcode": 3, "message": "Authentication failed."}, to=sid)
            return

        directory = "profile_images"  # the directory where you want to save the file
        if not os.path.exists(directory):
            os.makedirs(directory)  # this line will create the directory if it doesn't exist

        print(data['filename'])
        if file_data and get.allowed_file(filename):
            filename = secure_filename(data['filename'])

            # Decode and save the image
            image_path = os.path.join('profile_images', f"{username}.{filename.rsplit('.', 1)[1].lower()}")

            with open(image_path, "wb") as fh:
                fh.write(base64.b64decode(file_data))

            # Update the user data in your database to point to this file.
            db = Database()
            db.update_user_image(username, image_path)

            await socket_service.emit("upload-image-response", {"retcode": 0, "message": "Image uploaded successfully."}, to=sid)

        else:
            await socket_service.emit("upload-image-response", {"retcode": 1, "message": f"Invalid file format.{filename}"}, to=sid)

    except Exception as e:
        print(f"Error: {e}")
        await socket_service.emit("upload-image-response", {"retcode": 999, "message": "Unknown error occurred."}, to=sid)

if __name__ == "__main__":
    web.run_app(app,host=get.HOST, port=get.PORT)
