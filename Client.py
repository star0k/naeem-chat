import socketio
import json
import requests

HOST = '172.20.10.2'
HOST = '192.168.1.9'
# HOST = '127.0.0.1'
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
    if data.get('action') == 'new_message':
        print(f"New message from {data['sender']} at {data['timestamp']}: {data['message_text']}")


@sio.on("signin-response")
def on_signin_response(data):
    global current_token
    print(f"Received signin-response: {json.dumps(data)}")
    if 'token' in data:
        current_token = data['token']


# ... similarly for other events

def send_signin():
    global current_username
    username = input("Enter username: ")
    password = input("Enter password: ")

    current_username = username if username else 'user1'
    sio.emit("signin", {"username": username if username else 'user1', "password": password if password else 'pass'})


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

def send_message():
    global current_username, current_token

    # Ensure the user is authenticated (i.e., has a token) before attempting to send a message
    if not current_token:
        print("You need to sign in first!")
        return

    recipient = input("Enter recipient's username: ")
    content = input("Enter your message: ")

    # Emit the message event to the server
    sio.emit("send-message", {
        "username": current_username,
        "token": current_token,
        "partner": recipient,
        "message": content
    })
# ... add other command functions

def main():
    commands = {
        "signin": send_signin,
        "signup": send_signup,
        "send-message": send_message,

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
