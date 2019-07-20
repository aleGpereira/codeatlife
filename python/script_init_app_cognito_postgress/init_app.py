"""
Init app script
===============

This script add an admin user to app database if there is any in it. User data
and database url are passed as arguments. Also, it will assume that users
table is ALREADY CREATED. To add more, the remote database IS configured
properly.
Optionally, a cognito user would be created as well for this admin user.


Requirements
------------
    * Python 3.6 an further versions.

If you do not have a supported version you can work with pyenv (virtual
environment tool). To install pyenv on Ubuntu follow these instructions:
https://github.com/pyenv/pyenv-installer

Add pyenv into .bashrc as prompt says.

Now, install python 3.7.3 or any 3.7.x and set it up as default:
$ pyenv install 3.7.3
$ pyenv global 3.7.3

In case you need to have a different python version as default, you can define
the python version locally in the path where this script will live. For that
run:
$ cd my/script/path
$ pyenv local 3.7.3

Next, if requirements.txt is not going to be installed locally, then you should
use a virtual environment. Since python 3 comes with venv command, we can use
it:
$ python -m venv envname
$ source envname/bin/activate
[envname] $ pip install -r requirements.txt

And to run the script, just do (in this context we have the VE activated):
[envname] $ python init_app.py -d "postgresql+psycopg2://user:secret@localhost:5433/mydb" -e app.user@domain.com -n UserName -l UserLastname -p "userPoolId"

"""
import argparse
import logging
import sys

import boto3
from botocore.exceptions import ClientError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from email_validator import validate_email, EmailNotValidError

from .user import User


logging.basicConfig(format='%(message)s', level=logging.INFO)
ERROR_STATUS = 1
SUCCESS_STATUS = 0


def create_parser():
    """Creates a parser for input arguments.

    Create a parser that will handle all arguments. Defines accepted arguments
    and provides help menu for end user.

    :returns: ArgumentParser object
    """
    parser = argparse.ArgumentParser(
        description="Initialize app application after first deployment",
        prog="Init app"
    )
    parser.add_argument('-d', '--db', type=str,
                        help='Database URI where user should be added',
                        required=True
                        )
    parser.add_argument('-e', '--email', type=str,
                        help='Admin user email', required=True)
    parser.add_argument('-n', '--fistname', type=str,
                        help='Admin fistname', required=True)
    parser.add_argument('-l', '--lastname', type=str,
                        help='Admin user lastname', required=True)
    parser.add_argument('-p', '--userpoolid', type=str, default='',
                        help='Cognito user pool id where this user should be created.',
                        required=True)
    return parser


def init_db(db_uri):
    """Return a DB engine linked to the provided DB URI.

    :returns: Engine object
    """
    db = create_engine(db_uri)
    return db


def create_session(db):
    """Return a DB session.

    :returns: Session object
    """
    Session = sessionmaker(db)
    session = Session()
    return session


def create_cognito_user(userdata, user_pool_id):
    """Creates a user in cognito.

    Makes an api call to AWS Cognito as admin to create a user. After this
    step user state will be FORCE_CHANGE_PASSWORD.

    :returns: True if user created successfully. False if already created. If
        error, returns None.
    :rtype: dict
    """
    client = boto3.client('cognito-idp')

    email = userdata.get('email')
    username = email.replace('@', '_at_')   # A Cognito user name can't have
                                            # special character as '@'.
    name = userdata.get('first_name')
    lastname = userdata.get('last_name')
    user_attributes = [
        {
            "Name": "email",
            "Value": email
        },
        {
            "Name": "email_verified",
            "Value": "true"
        },
        {
            "Name": "name",
            "Value": name
        },
        {
            "Name": "family_name",
            "Value": lastname
        }
    ]
    kwargs = {
        'UserPoolId': user_pool_id,
        'Username': username,
        'UserAttributes': user_attributes
    }
    try:
        user = client.admin_create_user(**kwargs)
        user = True
    except ClientError as e:
        if e.response.get('Error').get('Code') == 'UsernameExistsException':
            user = False
        else:
            logging.error(e.response)
            user = None
    except Exception as e:
        logging.error(e)
        user = None
    return user


def create_user(session, userdata):
    """Create an admin user in DB.

    Admin user is added to the DB but only if there are no users in it.

    :returns: User object if created. False if already user en DB.
        None if error.
    """

    try:
        users = session.query(User).all()
        if not users:
            user = User(**userdata)
            session.add(user)
            session.commit()
        else:
            user = False
    except Exception as e:
        logging.error(f"Error creating user: {e}")
        user = None
    return user


def valid_email(email):
    """Validate email address.

    :returns: True if everything went well. False otherwise.
    """
    try:
        v = validate_email(email)
        result = True
    except EmailNotValidError as e:
        logging.error(f"Email not valid: {e}")
        result = False
    return result


if __name__ == "__main__":
    parser = create_parser()
    arguments = parser.parse_args()
    if not valid_email(arguments.email):
        sys.exit(ERROR_STATUS)

    userdata = {
        'first_name': arguments.fistname,
        'last_name': arguments.lastname,
        'email': arguments.email,
        'admin': True
    }
    user_pool_id = arguments.userpoolid
    cognito_user = create_cognito_user(userdata, user_pool_id)
    if cognito_user is None:
        logging.error("Cognito User could not be created. Unexpected error detected.")
        sys.exit(ERROR_STATUS)
    elif cognito_user is True:
        logging.info("Cognito user created successfully.")
    elif cognito_user is False:
        logging.info('User is already created. Nothing to do.')

    db_uri = arguments.db
    db = init_db(db_uri)
    session = create_session(db)
    user = create_user(session, userdata)
    if user is None:
        sys.exit(ERROR_STATUS)
    if user is False:
        logging.info("Your database already have users.")
        sys.exit(SUCCESS_STATUS)
    if user:
        logging.info("User successfully added to DB.")

    logging.info("Done")
    sys.exit(SUCCESS_STATUS)
