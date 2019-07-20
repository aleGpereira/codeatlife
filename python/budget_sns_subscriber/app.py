from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c67ujets280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
current_app.config['NOTIFICATION_EMAIL_ADDRESS'] = 'alepereira.dev@gmail.com'
current_app.config['AWS_SES_REGION'] = 'us-east-1'
db = SQLAlchemy(app)
