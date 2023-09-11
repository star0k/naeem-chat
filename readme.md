Project Title
Your project description goes here.

Setup
Prerequisites
Python (Check your version by running python --version)
Initial Setup
the setup.bat file already installs python for you if its not already installed 
Run the setup script: Run the setup.bat file for Windows users to install necessary packages and create a virtual environment.

setup.bat

.env File
In the root directory, you'll find a .env file with the following contents:


HOST: The IP address where your server will run.
PORT: The port number for the server.
SECRET: Secret key used for various cryptographic operations.
GMAIL_ADDRESS: Email address used for sending verification codes or notifications.
GMAIL_PASSWORD: The password for the Gmail account.

modify the host to meet your local address 

Start the Server

Run the start script: This will start your server. Make sure your virtual environment is activated before doing so.