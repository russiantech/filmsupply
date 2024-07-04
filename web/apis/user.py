from datetime import datetime
from flask import abort, current_app, session, jsonify, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import or_

import sqlalchemy as sa, traceback
from jsonschema import validate, ValidationError

from web.apis.errors import bad_request
from web import db, bcrypt
from web.models import Role, User, Notification

from web.utils import save_image, email, ip_adrs
from web.auth.forms import ( SignupForm, SigninForm, UpdateMeForm, ForgotForm, ResetForm)
from web.utils.decorators import admin_or_current_user, role_required
from web.utils.providers import oauth2providers
from web.utils.ip_adrs import user_ip

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

@user_bp.route("/user", methods=['POST'])
@csrf.exempt
def create_user():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.content_type != 'application/json':
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()

    try:
        validate(instance=data, schema=signup_schema)
    except ValidationError as e:
        return jsonify({"success": False, "message": e.message}), 400

    if db.session.scalar(sa.select(User).where(User.username == data['username'])):
        return jsonify({"success": False, "message": "Please use a different username."})

    if db.session.scalar(sa.select(User).where(User.email == data['email'])):
        return jsonify({"success": False, "message": "Please use a different email address."})

    if db.session.scalar(sa.select(User).where(User.phone == data['phone'])):
        return jsonify({"success": False, "message": "Please use a different phone number."})

    try:
        user = User(
            username=data['username'],
            email=data['email'],
            phone=data['phone'],
            password=hash_txt(data['password']),
            ip=ip_adrs.user_ip()
        )
        db.session.add(user)
        db.session.commit()

        email.verify_email(user)

        return jsonify({"success": True, "message": "Registration Successful", "redirect": url_for('auth.signin')})

    except Exception as e:
        print(traceback.print_exc())
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})




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

        # Authentication logic
        user = User.query.filter(
            sa.or_(
                User.email == data['signin'],
                User.phone == data['signin'],
                User.username == data['signin']
            )
        ).first()

        if user and check_password_hash(user.password, data['password']):
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


@user_bp.route("/signout")
@login_required
@db_session_management
def signout():
    logout_user()
    current_user.online = False
    db.session.commit()
    return redirect(url_for('auth.signin'))

@user_bp.route("/<string:username>/update", methods=['GET', 'POST'])
@login_required
@admin_or_current_user()
# @db_session_management
def update(username):
    try:

        user = User.query.filter(User.username==username).first_or_404()
        form = UpdateMeForm()

        if not ( (current_user.is_admin()) | (current_user.username == user.username)):
            return redirect(url_for('auth.update', username = current_user.username))

        if user.role:
            # Get the user's current role
            current_role = [ (r.id, r.type) for r in user.role] or [('0', 'Not Granted')]
            other_roles = Role.query.filter( ~Role.id.in_(current_role[0]) if current_role[0] else None ).all() 

            choices = [ ( x[0], x[1]) for x in current_role] or [('0', 'nothing')] #if current_role else [ '', 'Nothing']
            choices.extend( (role.id, role.type) for role in other_roles) if current_user.is_admin() else None
            # Set choices for the form's role field
            form.role.choices = choices

        if form.validate_on_submit():

            with db.session.no_autoflush:
                existing_user = User.query.filter(User.phone == form.phone.data, User.username != user.username).first()
                if existing_user:
                    message = "The phone number is already in use. Please use a different phone number."
                    return jsonify({"success": False, "error": str(message) }), 200
            
            if 'image' in request.files:
                photo_filename = save_image.save_photo(request.files['image'])
                user.image = photo_filename
                print("photo file-name", photo_filename)
                
            user.admin = form.admin.data
            user.name = form.name.data
            user.username = form.username.data
            user.email = form.email.data
            user.phone = form.phone.data
            user.tier = form.tier.data
            user.balance = form.balance.data
            user.gender = form.gender.data
            user.about = form.about.data
            user.password = hash_txt(form.password.data) if form.password.data else user.password
            user.withdrawal_password = hash_txt(form.withdrawal_password.data) if form.withdrawal_password.data else user.withdrawal_password
            user.ip = user_ip()
            user.verified = False
            new_role_ids = [form.role.data]  # Assuming the form data provides a list of role IDs
            new_roles = Role.query.filter(Role.id.in_(new_role_ids) ).all()
            user.roles = new_roles

            db.session.commit()
            db.session.flush()
            
            message = 'Account updated successfully!'
            return jsonify({"success": True, "message":str(message)}), 200
        
        elif request.method == 'GET':
            form.admin.data = user.admin
            form.name.data = user.name
            form.username.data = user.username
            form.email.data = user.email
            form.phone.data = user.phone
            form.tier.data = user.tier
            form.balance.data = user.balance
            form.gender.data = user.gender
            form.about.data = user.about
            form.password.data = '***'
            form.withdrawal_password.data = '***'

        if request.method == "POST" and not form.validate_on_submit():
            return jsonify({"success": False, "error": str(form.errors) }), 200

        context = {
            'form' : form, 
            'user': user, 
            'brand': {"name":"Film Supply"} }
        
        return render_template('auth/update.html',  **context)

    except Exception as e:
        print(e)
        return jsonify({"success": False, "error": str(e) }), 200

#this route-initializes auth
@user_bp.route('/authorize/<provider>')
@db_session_management
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('auth.update', usrname=current_user.username))

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

