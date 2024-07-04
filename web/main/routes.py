
from flask import g, get_flashed_messages, stream_template, Blueprint, flash, request, jsonify
from flask_login import current_user, login_required
from sqlalchemy import func
import traceback
from datetime import datetime, date, timedelta

from web.models import (
    Task, 
)

from web import db, csrf

from web.utils.db_session_management import db_session_management
from web.utils.decorators import role_required

main = Blueprint('main', __name__)

@main.route("/")
# @role_required('*')
# @db_session_management
def index():
    return stream_template('index.html')

@main.route("/users", methods=['GET', 'POST'])
@role_required('admin')
@db_session_management
def users():

    referrer =  request.headers.get('Referer')
    
    username, action = request.args.get('username', None), request.args.get('action', None)
    if username != None and action == 'del':
        if not current_user.is_admin():
            return jsonify({ 
                'response': f'Hey! {current_user.name or current_user.username}, You do not have permission to remove or delete this account',
                'flash':'alert-danger',
                'link': f'{referrer}'})

        user = User.query.filter(User.deleted == 0, User.username==username).first()
        
        if user:
            
            user.name = user.name
            user.deleted = True
            db.session.commit()
            
            return jsonify({ 
                'response': f'Hmm, User Deleted!!!',
                'flash':'alert-danger',
                'link': f'{referrer}'})
            
        return jsonify({ 
                'response': f'User Not Available',
                'flash':'alert-warning',
                'link': f'{referrer}'})
    
    page = request.args.get('page', 1, type=int)  # Get the requested page number
    per_page = 10  # Number of items per page
    #users = User.query.order_by(User.id.desc()).paginate(page=page, per_page=per_page)
    users = User.query.filter(User.deleted == 0).order_by( User.created.desc()).paginate(page=page, per_page=per_page)
    g.brand = {"name":"dunistech.ng"}
    g.user = User.query.filter(User.deleted == 0, User.username==username).first()
    context = {
    'pname' : 'Users : (staffs | clients | student)',
    'users': users
    }
    
    return stream_template('users/index.html', **context)
    # return render_template('users/index.html', **context)
