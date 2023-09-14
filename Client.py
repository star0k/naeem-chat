import socketio
import json
import base64
import requests

HOST = '192.168.1.9'
PORT = 65432
sio = socketio.Client()

# Variables to store user state
current_username = None
current_token = None


@sio.on("connect")
def on_connect():
    print("Connected!")

@sio.on("live")
def on_live_event(data):
    print(f"Received live event data: {json.dumps(data)}")
    # Handle the received data, if needed



@sio.on("messages")
def on_live_event(data):
    print(f"Received live event data: {json.dumps(data)}")
    # Handle the received data, if needed

@sio.on("signin-response")
def on_signin_response(data):
    global current_token
    print(f"Received signin-response: {json.dumps(data)}")
    if 'token' in data:
        current_token = data['token']\

@sio.on("upload-image-response")
def on_signin_response(data):
    global current_token
    print(f"Received image-response: {json.dumps(data)}")



# ... similarly for other events

def send_signin():
    global current_username
    username = input("Enter username: ")
    password = input("Enter password: ")

    current_username = username if username else 'user1'
    sio.emit("signin", {"username": username if username else 'user1', "password": password if password else 'pass'})

def upload_profile_image():
    global current_username, current_token

    # Ensure the user is authenticated (i.e., has a token) before attempting to upload an image
    if not current_token:
        print("You need to sign in first!")
        return

    # Convert image to Base64
    with open("test.jpeg", "rb") as image_file:
        encoded_image = base64.b64encode(image_file.read()).decode()

    # Emit the upload profile image event to the server
    sio.emit("upload-profile-image", {
        "username": current_username,
        "token": current_token,
        "encoded_image": encoded_image,
        "filename": "test.jpeg"  # Add filename
    })

def send_signup():
    username = input("Enter username: ")
    password = input("Enter password: ")
    fullname = input("Enter full name: ")
    email = input("Enter email: ")
    sio.emit("signup", {
        "username": username,
        "password": password,
        "fullname": fullname,
        "email": email
    })

def call():
    global current_username, current_token
    sender = current_username
    token = current_token
    sio.emit("request-call", {
        "sender": sender,
        "token": token,
        "recipient": "n.najjar10",
        "isVideo": True,
    })


def send_message():
    global current_username, current_token

    # Ensure the user is authenticated (i.e., has a token) before attempting to send a message
    if not current_token:
        print("You need to sign in first!")
        return

  #  recipient = input("Enter recipient's username: ")
   # content = input("Enter your message: ")

    # Emit the message event to the server
    sio.emit("send-message", {
        "username": current_username,
        "token": current_token,
        "partner": "n.najjar10",
        "message": "hiiiii"
    })
# ... add other command functions
def fetch():
    global current_username, current_token

    # Ensure the user is authenticated (i.e., has a token) before attempting to send a message
    if not current_token:
        print("You need to sign in first!")
        return
    print(current_username)

    sio.emit("fetch-chats", {
        "username": current_username,
        "token": current_token,

    })
def read():
    global current_username, current_token

    # Ensure the user is authenticated (i.e., has a token) before attempting to send a message
    if not current_token:
        print("You need to sign in first!")
        return

    # Emit the message event to the server
    sio.emit("read-chat", {
        "username": current_username,
        "token": current_token,
        "partner": "n.najjar10",

    })
# ... add other command functions

def main():
    commands = {
        "s": send_signin,
        "signup": send_signup,
        "send": send_message,
        'f' : fetch,
        'r' : read,
        'c' : call,
        "u": upload_profile_image,

        # ... add other commands
    }

    url = (f'http://{HOST}:{PORT}/socket.io')
    sio.connect(url)

    while True:
        cmd = input("\nEnter command (signin, signup, ...): ")
        if cmd in commands:
            commands[cmd]()
        elif cmd == "exit":
            break
        else:
            print(f"Unknown command: {cmd}")

    sio.disconnect()


if __name__ == "__main__":
    main()
