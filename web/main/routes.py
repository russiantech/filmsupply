
from flask import g, get_flashed_messages, stream_template, Blueprint, flash, request, jsonify
from flask_login import current_user, login_required
from sqlalchemy import func
import traceback
from datetime import datetime, date, timedelta

from web.models import (
    Task, Assigned_Task, User, Attendance
)

from web import db, csrf

from web.utils.db_session_management import db_session_management
from web.utils.decorators import role_required


def handle_response(message=None, alert=None, data=None):
    """ only success response should have data and be set to True. And  """
    response_data = {
        'message': message,
    }
    if data:
        response_data['alert'] = alert

    if data:
        response_data['data'] = data

    return response_data

main = Blueprint('main', __name__)

@main.route("/")
@login_required
# @role_required('manager', 'admin', '*')
@role_required('*')
@db_session_management
def index():
    user_id = current_user.id
    # tasks = Task.query.filter_by(user_id=user_id).order_by(Task.timestamp.desc()).all()
    tasks = Task.query.filter_by(user_id=user_id).order_by(Task.timestamp.desc()).limit(15).all()
    assigned_tasks = Assigned_Task.query.filter_by(user_id=user_id).order_by(Assigned_Task.created.desc()).all()

    tasks_list = []
    for task in tasks:
        
        tasks_list.append({
            'id': task.id,
            'description': task.description,
            'status': task.status,
            'timestamp': task.timestamp.strftime('%Y-%m-%d') \
                if task.timestamp is not None and task.timestamp != "" else None
        })
    
    assigned_tasks_list = []
    for task in assigned_tasks:
        
        assigned_tasks_list.append({
            'id': task.id,
            'detail': task.detail,
            'duration': task.duration or None
        })
    
    context = {
        "tasks_list": tasks_list,
        "assigned_tasks_list": assigned_tasks_list,
        "status_options" : ["pending", "completed", "on-going", "stucked", "cancelled"]  # Define status options
        }

    return stream_template('index.html', **context)

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
            
            flash(f'User Has Been Deleted!', 'danger')
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
