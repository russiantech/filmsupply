from datetime import datetime
from flask import abort, current_app, session, jsonify, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import or_

import sqlalchemy as sa, traceback
from jsonschema import validate, ValidationError

from web.apis.errors import bad_request
from web import db, bcrypt
from web.models import Transaction, Role, User, Task, Order, Notification, AccountType, AccountDetail
from sqlalchemy.orm import joinedload

from web.utils import save_image, email, ip_adrs
from web.auth.forms import ( SignupForm, SigninForm, UpdateMeForm, ForgotForm, ResetForm)
from web.utils.decorators import admin_or_current_user, role_required
from web.utils.providers import oauth2providers

from web.utils.db_session_management import db_session_management
from web import db, csrf

#oauth implimentations
import secrets, requests
from urllib.parse import urlencode

user_bp = Blueprint('user', __name__)

def hash_txt(txt):
    return bcrypt.generate_password_hash(txt).decode('utf-8') # use .encode('utf-8') to decode this

auth_schema = {
    "type": "object",
    "properties": {
        "signin": {"type": "string"},
        "password": {"type": "string"},
        "remember": {"type": "boolean"}
    },
    "required": ["signin", "password"]
}


signup_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "email": {"type": "string", "format": "email"},
        "phone": {"type": "string"},
        "password": {"type": "string"}
    },
    "required": ["username", "email", "password"]
}

update_user_schema = {
    "type": "object",
    "properties": {
        "user_id": {"type": "number"},
        "username": {"type": "string"},
        "email": {"type": "string", "format": "email"},
        "password": {"type": "string"},
        "withdrawal_password": {"type": "string"},
        "phone": {"type": "string"},
        "name": {"type": "string"},
        "gender": {"type": "string"},
        "membership": {"type": "string"},
        "balance": {"type": "number"},
        "about": {"type": "string"},
        "verified": {"type": "boolean"},
        "ip": {"type": "string"},
        "image": {"type": ["string", "null"]}
    },
    "required": ["username", "email", "password", "withdrawal_password"]
}


@user_bp.route("/user", methods=['POST'])
@csrf.exempt
def create_user():
    
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.content_type != 'application/json':
        return jsonify({"success": False, "message": "Content-Type must be application/json"})

    data = request.get_json()

    # Log received data for debugging purposes
    print(f"Received data: {data}")

    # Validate the data against the schema
    try:
        validate(instance=data, schema=signup_schema)
    except ValidationError as e:
        return jsonify({"success": False, "error": e.message})

    # Ensure that no fields are empty
    if not all(data.get(key) for key in ('username', 'email', 'password')):
        return jsonify({"success": False, "error": "Required field is empty"})

    # Perform checks on the data
    if db.session.scalar(sa.select(User).where(User.username == data['username'])):
        return jsonify({"success": False, "error": "Please use a different username."})

    if db.session.scalar(sa.select(User).where(User.email == data['email'])):
        return jsonify({"success": False, "error": "Please use a different email address."})

    if db.session.scalar(sa.select(User).where(User.phone == data['phone'])):
        return jsonify({"success": False, "error": "Please use a different phone number."})

    try:
        # Create and save the new user
        user = User(
            username=data['username'],
            email=data['email'],
            phone=data['phone'],
            password=bcrypt.generate_password_hash(data['password']),
            ip=ip_adrs.user_ip()
        )
        db.session.add(user)
        db.session.commit()

        # Send verification email
        email.verify_email(user)

        return jsonify({"success": True, "message": "Registration Successful", "redirect": url_for('auth.signin')})

    except Exception as e:
        print(traceback.print_exc())
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

@user_bp.route('/<string:username>/update_user', methods=['PUT'])
@csrf.exempt
@admin_or_current_user()
def update(username):
    try:
        
        if not current_user.is_admin and current_user.username != username:
            return jsonify({"success": False, "error": "Unauthorized"})

        if request.content_type == 'application/json':
            data = request.get_json()

        elif 'multipart/form-data' in request.content_type:
            data = request.form.to_dict()

        else:
            return jsonify({"success": False, "message": "Content-Type must be application/json or multipart/form-data"})

        if not data:
            return jsonify({"success": False, "message": "No data received"})
        
        # Validate the data against the schema
        try:
            validate(instance=data, schema=update_user_schema)

        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)})
            #return jsonify({"success": False, "error": e.message})

        # Check for uniqueness of phone, email, and username
        if db.session.scalar(sa.select(User).where(User.phone == data.get('phone'), User.username != username)):
            # print(data.get('phone'), User.phone)
            return jsonify({"success": False, "error": "The phone number is already in use. Please use a different phone number."}), 200

        if db.session.scalar(sa.select(User).where(User.email == data.get('email'), User.username != username)):
            return jsonify({"success": False, "error": "The email address is already in use. Please use a different email address."}), 200

        if db.session.scalar(sa.select(User).where(User.username == data.get('username'), User.username != username)):
            return jsonify({"success": False, "error": "The username is already in use. Please use a different username."}), 200

        user = User.query.filter_by(username=username).first_or_404()

        # Update user attributes based on JSON data
        if 'password' in data:
            user.password = bcrypt.generate_password_hash(data['password'])

        if 'withdrawal_password' in data:
            user.withdrawal_password = bcrypt.generate_password_hash(data['withdrawal_password'])

        if 'image' in request.files:
            image_filename = save_image.save_file(request.files['image'], './static/img/avatars/', current_user.username)
            user.image = image_filename

        user.name = data.get('name', user.name)
        user.admin = data.get('admin', user.admin)
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        user.phone = data.get('phone', user.phone)
        user.membership = data.get('membership', user.membership)
        user.balance = data.get('balance', user.balance)
        user.gender = data.get('gender', user.gender)
        user.about = data.get('about', user.about)
        user.verified = data.get('verified', user.verified)
        user.ip = ip_adrs.user_ip()

        # Update account details
        # Ensure account_details is initialized
        if user.account_details is None:
            user.account_details = []

        # Update account details
        account_details_data = data.get('account_details', {})

        if user.account_details:
            # Update the existing account detail (assuming there's only one per user)
            account_detail = user.account_details[0]
            for field, value in account_details_data.items():
                if value is not None:
                    setattr(account_detail, field, value)
        else:
            # Insert new if none exists
            account_detail = AccountDetail(
                user_id=user.id,
                **account_details_data
            )
            user.account_details.append(account_detail)
            db.session.add(account_detail)

        db.session.commit()
        
       # Ensure account_details is initialized
        if user.account_details is None:
            user.account_details = []

        # Update account details
        if user.account_details:
            # Update the first existing account detail (assuming there's only one per user)
            account_details_data = {
                'user_id': data.get('user_id', current_user.id),
                'account_name': data.get('account_name'),
                'account_phone': data.get('account_phone'),
                'exchange': data.get('exchange'),
                'exchange_address': data.get('exchange_address'),
                'cash_app_email': data.get('cash_app_email'),
                'cash_app_username': data.get('cash_app_username'),
                'paypal_phone': data.get('paypal_phone'),
                'paypal_email': data.get('paypal_email')
            }

            account_detail = user.account_details[0]

            for field, value in account_details_data.items():
                if value is not None:
                    setattr(account_detail, field, value)
        else:
            # Insert new if none exists
            account_detail = AccountDetail(
                user_id=data.get('user_id', current_user.id),
                account_name=data.get('account_name'),
                account_phone=data.get('account_phone'),
                exchange=data.get('exchange'),
                exchange_address=data.get('exchange_address'),
                cash_app_email=data.get('cash_app_email'),
                cash_app_username=data.get('cash_app_username'),
                paypal_phone=data.get('paypal_phone'),
                paypal_email=data.get('paypal_email')
            )

            user.account_details.append(account_detail)
            db.session.add(account_detail)

        db.session.commit()
        
        
        return jsonify({"success": True, "message": "User updated successfully."}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

""" ------------------------------------------------------------------------- """
@user_bp.route('/<string:username>/get_user_x', methods=['GET'])
@csrf.exempt
@admin_or_current_user()
def get_user_x(username):
    try:
        # Fetch the user by username and eagerly load account details
        user = db.session.query(User).options(joinedload(User.account_details)).filter_by(username=username).first_or_404()

        # Prepare user details dictionary
        user_details = {
            "username": user.username,
            "user_id": user.user_id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "membership": user.membership,
            "balance": user.balance,
            "gender": user.gender,
            "about": user.about,
            "verified": user.verified,
            "ip": user.ip,
            "admin": user.admin,
            "image": user.image,
            "password": "+ + + + +",
            "withdrawal_password": "+ + + + +",
            "refcode": user.refcode,
            "uuid": user.user_id,
            "created": user.created.strftime('%Y-%m-%d %H:%M:%S') if user.created else None,
            "account_details": []
        }

        # Function to convert account details to dictionary
        def account_detail_to_dict(account_detail):
            return {
                "account_type": account_detail.account_type.name if account_detail.account_type else None,
                "exchange": account_detail.exchange,
                "exchange_address": account_detail.exchange_address,
                "bank_account": account_detail.bank_account,
                "short_code": account_detail.short_code,
                "link": account_detail.link,
                "account_name": account_detail.account_name,
                "account_phone": account_detail.account_phone,
                "cash_app_email": account_detail.cash_app_email,
                "cash_app_username": account_detail.cash_app_username,
                "paypal_phone": account_detail.paypal_phone,
                "paypal_email": account_detail.paypal_email,
                "deleted": account_detail.deleted,
                "created": account_detail.created.strftime('%Y-%m-%d %H:%M:%S') if account_detail.created else None,
                "updated": account_detail.updated.strftime('%Y-%m-%d %H:%M:%S') if account_detail.updated else None
            }

        # Update user details with account details
        if user.account_details:
            for detail in user.account_details:
                user_details["account_details"].append(account_detail_to_dict(detail))

        # Return the user details as a JSON response
        return jsonify({"success": True, "user": user_details}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
""" ---------------------------------------------------------------------------------- """

@user_bp.route("/auth", methods=['POST'])
@csrf.exempt
def auth():
    try:
        if not current_user.is_anonymous:
            return redirect(url_for('main.index'))

        # Check if the request content type is application/json
        if request.content_type != 'application/json':
            return jsonify({"success": False, "message": "Content-Type must be application/json"})

        # Parse JSON data from the request
        data = request.get_json()

        # Validate the data against the schema
        try:
            validate(instance=data, schema=auth_schema)
        except ValidationError as e:
            return jsonify({"success": False, "message": e.message})

        # Ensure that no fields are empty
        if not all(data.get(key) for key in ('signin', 'password')):
            return jsonify({"success": False, "message": "All fields are required and must not be empty."})

        # Authentication logic
        user = User.query.filter(
            sa.or_(
                User.email == data['signin'],
                User.phone == data['signin'],
                User.username == data['signin']
            )
        ).first()

        if user and bcrypt.check_password_hash(user.password, data['password']):
            user.online = True
            user.last_seen = datetime.utcnow()
            user.ip = ip_adrs.user_ip()
            db.session.commit()
            login_user(user, remember=data.get('remember', False))
            return jsonify({"success": True, "message": "Authentication Successful", "redirect": url_for('main.index')})
        else:
            return jsonify({"success": False, "error": "Invalid Authentication"})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/api/users', methods=['GET'])
@role_required('admin')
def get_users():
    users = User.query.all()
    user_list = [{
        'contact': user.username or user.email or user.phone,
        'image': user.image,
        'balance': user.balance,
        'membership': user.membership,
        'pending_tasks': get_pending_tasks(user.id)  # Calculate pending tasks
    } for user in users]
    return jsonify(user_list)

def get_pending_tasks(user_id):
    # Get all task IDs
    total_task_ids = {task.id for task in Task.query.filter_by(deleted=False).all()}
    # Get completed task IDs for the user
    completed_task_ids = {order.task_id for order in Order.query.filter_by(user_id=user_id).all()}
    # Pending tasks are those in total_task_ids but not in completed_task_ids
    pending_task_ids = total_task_ids - completed_task_ids
    return len(pending_task_ids)



@user_bp.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        total_deposits = db.session.query(
            db.func.sum(Transaction.amount)
        ).filter(Transaction.transaction_type == 'deposit', Transaction.deleted == False).scalar() or 0.0
        
        total_withdrawals = db.session.query(
            db.func.sum(Transaction.amount)
        ).filter(Transaction.transaction_type == 'withdrawal', Transaction.deleted == False).scalar() or 0.0
        
        total_signups = db.session.query(db.func.count(User.id)).scalar() or 0
        total_tasks = db.session.query(db.func.count(Task.id)).scalar() or 0
        
        stats = {
            'total_deposits': total_deposits,
            'total_withdrawals': total_withdrawals,
            'total_signups': total_signups,
            'total_tasks': total_tasks
        }
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route("/signout")
@login_required
@db_session_management
def signout():
    logout_user()
    current_user.online = False
    db.session.commit()
    return redirect(url_for('auth.signin'))

#this route-initializes auth
@user_bp.route('/authorize/<provider>')
@db_session_management
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('auth.update', username=current_user.username))

    provider_data = oauth2providers.get(provider)
    if provider_data is None:
        abort(404)

    # generate a random string for the state parameter
    session['oauth2_state'] = secrets.token_urlsafe(16)

    # create a query string with all the OAuth2 parameters
    qs = urlencode({
        'client_id': provider_data['client_id'],
        'redirect_uri': url_for('auth.oauth2_callback', provider=provider, _external=True),
        'response_type': 'code',
        'scope': ' '.join(provider_data['scopes']),
        'state': session['oauth2_state'],
    })

    # redirect the user to the OAuth2 provider authorization URL
    return redirect(provider_data['authorize_url'] + '?' + qs)

@user_bp.route('/callback/<provider>')
@db_session_management
def oauth2_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))

    provider_data = oauth2providers.get(provider)
    if provider_data is None:
        abort(404)

    # if there was an authentication error, flash the error messages and exit
    if 'error' in request.args:
        for k, v in request.args.items():
            if k.startswith('error'):
                flash(f'{k}: {v}')
        return redirect(url_for('main.index'))

    # make sure that the state parameter matches the one we created in the
    # authorization request
    if request.args['state'] != session.get('oauth2_state'):
        abort(401)

    # make sure that the authorization code is present
    if 'code' not in request.args:
        abort(401)

    # exchange the authorization code for an access token
    response = requests.post(provider_data['token_url'], data={
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('auth.oauth2_callback', provider=provider,
                                _external=True),
    }, headers={'Accept': 'application/json'})

    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get('access_token')
    if not oauth2_token:
        abort(401)

    # use the access token to get the user's email address
    response = requests.get(provider_data['userinfo']['url'], headers={
        'Authorization': 'Bearer ' + oauth2_token,
        'Accept': 'application/json',
    })
    if response.status_code != 200:
        abort(401)
    email = provider_data['userinfo']['email'](response.json())

    # find or create the user in the database
    user = db.session.scalar(db.select(User).where(User.email == email))
    if user is None:
        user = User(email=email, username=email.split('@')[0], password=hash_txt(secrets.token_urlsafe(5)), src=provider)
        db.session.add(user)
        db.session.commit()

    # log the user in
    login_user(user)
    return redirect(url_for('main.index'))

@user_bp.route("/forgot", methods=['GET', 'POST'])
@db_session_management
def forgot():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ForgotForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        email.reset_email(user) if user else flash('Undefined User.', 'info')
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('auth.signin'))
    elif request.method == 'GET':
        form.email.data = request.args.get('e')
    return render_template('auth/forgot.html', form=form)

#->for unverified-users, notice use of 'POST' instead of 'post' before it works
@user_bp.route("/unverified", methods=['post', 'get'])
@login_required
@db_session_management
def unverified():
    if request.method == 'POST':
        email.verify_email(current_user)
        flash('Verication Emails Sent Again, Check You Mail Box', 'info')
    return render_template('auth/unverified.html')

#->for both verify/reset tokens
@user_bp.route("/confirm/<token>", methods=['GET', 'POST'])
@db_session_management
def confirm(token):
    #print(current_user.generate_token(type='verify'))
    if current_user.is_authenticated:
        #print(current_user.generate_token(type='verify')) #generate-token
        return redirect(url_for('main.index'))
    
    conf = User.verify_token(token) #verify

    if not conf:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('auth.signin'))
    
    user = conf[0] 
    type = conf[1]

    if not user :
        flash('Invalid/Expired Token', 'warning')
        return redirect(url_for('main.index'))
    
    if type == 'verify' and user.verified == True:
        flash(f'Weldone {user.username}, you have done this before now', 'success')
        return redirect(url_for('auth.signin', _external=True))

    if type == 'verify' and user.verified == False:
        user.verified = True
        db.session.commit()
        flash(f'Weldone {user.username}, Your Email Address is Confirmed, Continue Here', 'success')
        return redirect(url_for('auth.signin', _external=True))

    if type == 'reset':
        form = ResetForm() 
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! Continue', 'success')
            return redirect(url_for('auth.signin'))
        return render_template('auth/reset.html', user=user, form=form)


@user_bp.route('/fetch_notifications', methods=['GET'])
@login_required
def fetch_notifications():
    notifications = Notification.query.filter_by(
        user_id=current_user.id, is_read=False, deleted=False
        ).order_by(Notification.created_at.desc()).all()
    notifications_list = [{
        'id': notification.id,
        'message': notification.message,
        'is_read': notification.is_read,
        'file_path': notification.file_path,
        'created_at': notification.created_at.strftime('%a, %b %d %I:%M %p')
    } for notification in notifications]

    return jsonify({"notifications": notifications_list}), 200

@user_bp.route('/mark_as_read/<int:notification_id>', methods=['PUT'])
@role_required('*')
@csrf.exempt
def mark_notification_as_read(notification_id):
    try:
        notification = Notification.query.get(notification_id)
        if notification:
            notification.is_read = True
            db.session.commit()
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'error': 'Notification not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/impersonate', methods=['POST'])
@login_required
# @role_required('admin') //this will cause issues/undefined. better do it under the route
@csrf.exempt
def impersonate():
    try:
        
        if not current_user.is_admin() and not "original_user_id" in session:
            return jsonify({'success': False, 'error': "Admin required"})
        
        data = request.get_json()
        
        action = data.get('action')
        user_id = data.get('user_id')
        
        if action == "impersonate":
            user = User.query.get(user_id)
            if user:
                session['original_user_id'] = current_user.id
                login_user(user)
                return jsonify({'success': True, 'message': f'You are now impersonating {user.username}'}), 200
            else:
                return jsonify({'success': False, 'error': "User not found"})

        elif action == "revert":
            original_user_id = session.pop('original_user_id', None)
            if original_user_id:
                original_user = User.query.get(original_user_id)
                if original_user:
                    login_user(original_user)
                    return jsonify({'success': True, 'message': f'You are now back as {original_user.username}'}), 200
                return jsonify({'success': False, 'error': "original user not found"})
            return jsonify({'success': False, 'error': "Failed to revert to original user, invalid user-id"})
        
        return jsonify({'success': False, 'error': "Invalid action"})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

