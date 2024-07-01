
from os import environ, path
from dotenv import load_dotenv, find_dotenv
from web.utils import entry
load_dotenv(find_dotenv())

#app-config
TESTING = True
DEBUG = True
FLASK_ENV='development'
FLASK_APP='app.py'
APP_SETTINGS = entry + '/confiq.py'
SECRET_KEY = environ.get('SECRET_KEY')
UPLOAD_FOLDER='/static/img/uploads'
MAX_CONTENT_PATH = None
LANGUAGES = ['en', 'es']
MS_TRANSLATOR_KEY = environ.get('MS_TRANSLATOR_KEY')
ELASTICSEARCH_URL = environ.get('ELASTICSEARCH_URL')
POSTS_PER_PAGE = 25
LOGO = '/static/img/favicon/favicon32x32.png'
ALLOWED_EXTENSIONS=set(['txt', 'pdf', 'png', 'svg', 'jpg', 'jpeg', 'gif','mp4'])

'''
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:cuong1990@localhost:3306/rusian" //mysql

SQLALCHEMY_DATABASE_URI = environ.get('DATABASE_URL', '').replace('postgres://', 'postgresql://') or \
    'sqlite:///' + path.join(basedir, 'russian.db' )
'''
#SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:@localhost:3306/empty" #mysql(no-password set, it's supposed to come after //root:)

SQLALCHEMY_DATABASE_URI = environ.get('DATABASE_URL')
SQLALCHEMY_TRACK_MODIFICATIONS = False
LOG_TO_STDOUT = environ.get('LOG_TO_STDOUT')

# email config
MAIL_DEBUG = True
DEFAULT_MAIL_SENDER = environ.get('DEFAULT_MAIL_SENDER') 
MAIL_SERVER = 'smtp.gmail.com' or "smtplib.SMTP('smtp.gmail.com', 587)"
MAIL_PORT = 587
MAIL_USE_TLS=True
MAIL_USE_SSL = False
MAIL_USERNAME = environ.get('MAIL_USERNAME')
MAIL_PASSWORD = environ.get('MAIL_PASSWORD')

# -- > 
MAIL_SERVER = environ.get('MAILTRAP_SERVER')
MAIL_PORT = environ.get('MAILTRAP_PORT')
MAIL_USE_TLS=True
MAIL_USE_SSL = False
MAIL_USERNAME = environ.get('MAILTRAP_USERNAME')
MAIL_PASSWORD = environ.get('MAILTRAP_PASSWORD')

MAIL_MAX_EMAILS=None
MAIL_SUPPRESS_SEND = False
MAIL_ASCII_ATTACHMENTS = True
ADMINS = ['jameschristo962@gmail.com', 'chrisjsmez@gmail.com']


