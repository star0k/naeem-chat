@sio.on("signin")
async def signin(sid, data):
        username = data.get('username')
        password = data.get('password')
        if db.authenticate_user(username, password):  # Assuming `authenticate_user` checks the hashed password
            token = generate_token(username)
            users_sockets[username] = {'sid': sid, 'token': token}
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


            chat_data_list = db.cursor.fetchall()

            await sio.emit("chats-response", {'retcode': 0, "data": chat_data_list}, to=sid)

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
            await sio.emit("messages", {'retcode': 0, "data": messages}, to=sid)
            print('sent data')
        else:
            await sio.emit("messages", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except Exception as e :
        print(e)
        await sio.emit("messages", {'retcode': 999, "message": f'e'}, to=sid)
@sio.on("send-message")
async def send_message(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        chat_partner = data.get('partner')
        message_text = data.get('message')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db = Database()
        print('in send message')
        if is_authenticated(sid, token, username):
            if not username_exists(chat_partner,db.cursor) :
                await sio.emit("send-message-response", {"retcode": 4, "message": "User Not Found."}, to=sid)
                return
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
            print(email)
            await sio.emit("signup-response", {"retcode": 1, "message": "Invalid email format."}, to=sid)
            return
        if email_exists(email, db.cursor):
            print('exist mail')
            await sio.emit("signup-response", {"retcode":2, "message": "Email Already Registered."}, to=sid)
            return
        if username_exists(username, db.cursor):
            print('exist username')
            await sio.emit("signup-response", {"retcode":3, "message": "Username exist."}, to=sid)
            return

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        verification_code = generate_verification_code()
        # Store in database
        db.cursor.execute(
            "INSERT INTO users (username, fullname, email, password, verification_code, isverified, iscompleted) VALUES (?, ?, ?, ?, ?, 0, 0)",
            (username, fullname, email, hashed_password, verification_code))
        db.conn.commit()

        # Send verification code to email
        send_email_verification(email, verification_code)
        print('signed up')
        await sio.emit("signup-response", {"retcode": 0 ,"message": "User registered. Please check email for verification code."}, to=sid)


    except Exception as e:
        print(f'error {e}')
        await sio.emit("signup-response", {"retcode": 999, "message": f"Unknown error occurred. {e}"}, to=sid)

@sio.on("read-conversation")
async def read_conversation(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        chat_partner = data.get('chat')
        message = data.get('message')
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
            await sio.emit("conversation-read", {"retcode": 3, "message": "Authentication failed."}, to=sid)
    except:
        await sio.emit("conversation-read", {'retcode': 999, "message": "Unknown error occurred."}, to=sid)


@sio.on("fetch-messages-status")
async def fetch_messages_status(sid, data):
    try:
        username = data.get('username')
        token = data.get('token')
        date = "1970-01-01 00:00:00"
        db = Database()

        if is_authenticated(sid, token, username):

            # Fetch messages for the user where isread and isnotify differ
            db.cursor.execute("""
                SELECT id, isread 
                FROM messages 
                WHERE (sender = ?) 
                AND timestamp > ?
                AND isread != isnotify
            """, ( username, date))

            results = db.cursor.fetchall()

            status_updates = [{"message_id": message["id"], "isread": message["isread"]} for message in results]

            # Update isnotify for these messages
            for message in results:
                db.cursor.execute("""
                    UPDATE messages 
                    SET isnotify = ? 
                    WHERE id = ?
                """, (message["isread"], message["id"]))
                db.conn.commit()

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
        verification_code = data.get('code')
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
