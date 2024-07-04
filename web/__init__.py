from flask import (
    Flask
)
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_moment import Moment
from flask_session import Session
from flask_cors import CORS
# from flask_oauthlib.client import OAuth
from web.models import db, User

from dotenv import load_dotenv
from web.utils import activelink, slug
load_dotenv()

csrf = CSRFProtect()
f_session = Session()
bcrypt = Bcrypt()
s_manager = LoginManager()
mail = Mail()
migrate = Migrate()
moment = Moment()
cors = CORS()

# oauth = OAuth()

@s_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

s_manager.login_view = 'auth.signin'

def configure_extensions(app):
    db.init_app(app)
    csrf.init_app(app)
    f_session.init_app(app)
    bcrypt.init_app(app)
    s_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    moment.init_app(app)
    cors.init_app(app)
    # oauth.init_app(app)

def create_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_pyfile('confiq.py')  # Load configuration from a separate file
    configure_extensions(app)
    
    # Register blueprints
    from web.apis.order import order_bp
    app.register_blueprint(order_bp)
    
    from web.apis.account_detail import account_detail_bp
    app.register_blueprint(account_detail_bp)
    
    from web.apis.task import task_bp
    app.register_blueprint(task_bp)

    from web.apis.notify import notify_bp
    app.register_blueprint(notify_bp)
    
    from web.auth.routes import auth
    app.register_blueprint(auth)
    
    from web.main.routes import main
    app.register_blueprint(main)
    
    from web.errors.handlers import errors_bp
    app.register_blueprint(errors_bp)
    
    app.jinja_env.filters['slugify'] = slug.slugify
    app.jinja_env.globals.update(is_active=activelink.is_active)

    return app
