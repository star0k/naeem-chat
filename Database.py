import sqlalchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy import or_, and_
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, func
from Functionality import Configs
import os
get = Configs()
Base = sqlalchemy.orm.declarative_base()

Base = sqlalchemy.orm.declarative_base()

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


class Database :
    def __init__(self, db_name="sqlite:///chat.db"):
        self.engine = create_engine(db_name)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)

    def authenticate_user(self, username, password):
        user = self.session.query(User).filter_by(username=username).one_or_none()
        return user and get.check_password(password, user.password)

    def fetch_chat_partners(self, username):
        """Fetch distinct chat partners for a given username using SQLAlchemy."""

        # Query for messages where the user is either the sender or the recipient
        messages_as_sender = self.session.query(Message.recipient).filter_by(sender=username).all()
        messages_as_recipient = self.session.query(Message.sender).filter_by(recipient=username).all()

        # Create a set to store unique chat partners
        chat_partners = set()

        for row in messages_as_sender:
            chat_partners.add(row.recipient)

        for row in messages_as_recipient:
            chat_partners.add(row.sender)

        return chat_partners

    def store_message(self, sender, recipient, message, isread, isnotify):
        new_message = Message(sender=sender, recipient=recipient, message=message, isread=isread , isnotify=isnotify)
        self.session.add(new_message)
        self.session.commit()
        return new_message.id

    def fetch_messages(self, username, date):
        message_objects = self.session.query(Message).filter(
            (Message.recipient == username) | (Message.sender == username), Message.timestamp >= date
        ).all()

        messages = []

        for msg in message_objects:
            data = {
                'id': msg.id,
                'sender': msg.sender,
                'recipient': msg.recipient,
                'message': msg.message,
                'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),  # Convert datetime to string
                'isread': msg.isread,
                'isnotify': msg.isnotify
                # Add any other fields from your Message model that you need
            }
            messages.append(data)

        return messages

    def mark_message_delivered(self, message_id):
        message = self.session.query(Message).filter_by(id=message_id).one_or_none()
        if message:
            message.isread = 1
            self.session.commit()

    def mark_message_read(self, chat_partner):
        messages = self.session.query(Message).filter_by(sender=chat_partner).all()
        if messages :
            for message in messages :
                message.isread = 2
                self.session.commit()

    def register_user(self, username, hashed_password, email):
        new_user = User(username=username, password=hashed_password, email=email, isverified=False)
        self.session.add(new_user)
        self.session.commit()

    def user_data(self, username):
        user = self.session.query(User).filter_by(username=username).one_or_none()

        if not user:
            return None

        # Creating a dictionary with the required attributes
        data = {
            'username': user.username,
            'bio': user.bio,
            'iscompleted': user.iscompleted,
            'interest_language': user.interest_language,
            'fullname': user.fullname,
            'email': user.email,
            'profile_image': user.profile_image,
            'isverified': user.isverified,
            'native_language': user.native_language
        }

        return data

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

        user.password = get.hash_password(new_password)
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

    def set_verification_code(self, username, verification_code):
                """
                Set the verification code for the specified user.

                Args:
                    username (str): The user's username.
                    verification_code (str): The verification code to be set.

                Returns:
                    bool: True if successfully set, False otherwise.
                """
                user = self.session.query(User).filter_by(username=username).one_or_none()
                if user:
                    user.verification_code = verification_code
                    self.session.commit()
                    return True
                return False

    def get_email_by_username(self, username):
                """
                Fetch the email of a user by their username.

                Args:
                    username (str): The user's username.

                Returns:
                    str: The email of the user, or None if user not found.
                """
                user = self.session.query(User).filter_by(username=username).one_or_none()
                return user.email if user else None

    def advanced_user_search(self, query, interest_language=None, native_language=None):
        try:
            # Build the initial query
            search_query = self.session.query(User)

            # Apply filters based on input
            if interest_language and native_language:
                # Exclude users who have the exact same native and interest languages
                search_query = search_query.filter(
                    and_(
                        User.interest_language == interest_language,
                        User.native_language == native_language,
                        User.interest_language != User.native_language
                    )
                )
            else:
                if interest_language:
                    search_query = search_query.filter(User.interest_language == interest_language)

                if native_language:
                    search_query = search_query.filter(User.native_language == native_language)

            if query:  # This will filter by username or fullname
                search_query = search_query.filter(
                    or_(User.username.like(f"%{query}%"), User.fullname.like(f"%{query}%")))

            # Fetch and return results
            results = search_query.all()

            # Format the results to match the desired structure
            formatted_results = []
            for user in results:
                data = {
                    'username': user.username,
                    'bio': user.bio,
                    'iscompleted': user.iscompleted,
                    'interest_language': user.interest_language,
                    'fullname': user.fullname,
                    'email': user.email,
                    'profile_image': user.profile_image,
                    'isverified': user.isverified,
                    'native_language': user.native_language
                }
                formatted_results.append(data)

            return formatted_results

        except Exception as e:
            print(f"Search error: {e}")
            return []

        finally:
            self.session.close()

    def update_user_image(self, username, image_path):
        """
        Upload a profile image for the user with the given username.

        :param username: The username of the user
        :param image_path: The file path of the image to be uploaded
        """
        # Check if the image file exists
        if not os.path.exists(image_path):
            print(f"The file {image_path} does not exist.")
            return False

        # Query for the user
        user = self.session.query(User).filter_by(username=username).one_or_none()

        # If the user exists, update the profile_image field
        if user:
            user.profile_image = image_path
            self.session.commit()
            print(f"Successfully updated the profile image for {username}.")
            return True
        else:
            print(f"User with username {username} does not exist.")
            return False
