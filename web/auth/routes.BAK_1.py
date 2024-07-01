from datetime import datetime
import traceback
from flask import abort, current_app, session, jsonify, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import or_

import sqlalchemy as sa

#from utils.time_ago import timeAgo
from web.apis.errors import bad_request
from web import db, bcrypt
from web.models import Query, Role, User, Notification

from web.utils import save_image, email, ip_adrs
from web.auth.forms import (QueryForm, SignupForm, SigninForm, UpdateMeForm, ForgotForm, ResetForm)
from web.utils.decorators import admin_or_current_user
from web.utils.providers import oauth2providers

from web.utils.db_session_management import db_session_management
from web import db, csrf

#oauth implimentations
import secrets, requests
from urllib.parse import urlencode

auth = Blueprint('auth', __name__)

def hash_txt(txt):
    return bcrypt.generate_password_hash(txt).decode('utf-8') #use .encode('utf-8') to decode this

@auth.route('/query/<int:user_id>', methods=['POST'])
@login_required
@csrf.exempt
def query(user_id):
    user = User.query.get_or_404(user_id)
    
    if 'file_input' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400

    file_input = request.files['file_input']
    if file_input.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400

    if file_input:
        # filename = secure_filename(file.filename)
        # file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # file.save(file_path)
        
        # Example in a route or form processing function
        file_input = request.files['file_input']
        # Default upload path ('uploads') and no username
        # saved_filename = save_file(file)

        # Specify custom upload path
        # saved_filename = save_file(file, 'custom_path')

        # Specify custom upload path and username
        saved_filename = save_image.save_file(file_input, './static/images/queries', user.username)


        query = Query(user_id=user.id, file_path=saved_filename, message=request.form.get('message'))
        db.session.add(query)
        db.session.commit()

        # Send email notification
        # msg = Message('New Query Received', sender='your-email@example.com', recipients=[user.email])
        # msg.body = f'You have received a new query.\n\nMessage: {request.form.get("message")}\n\nPlease check the attached file.'
        # with app.open_resource(file_path) as fp:
            # msg.attach(filename, "application/octet-stream", fp.read())
        # mail.send(msg)

        # Example usage:
        subject = "Query Alert"
        sender = f"{current_app.config['MAIL_USERNAME']}"
        recipients = [f"{user.email}"]
        text_body = request.form.get('message')
        html_body = f"<p>{request.form.get('message')}.</p>"
        email.send_email(subject, sender, recipients, text_body, html_body)

        # Create in-app notification
        notification = Notification(user_id=user.id, message='You have received a new query.')
        db.session.add(notification)
        db.session.commit()

        return jsonify({"success": True, "message": "Query sent successfully!"}), 200

    return jsonify({"success": False, "error": "File upload failed"}), 400

@auth.route("/signup", methods=['GET', 'POST'])
@db_session_management
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = SignupForm()
    if form.validate_on_submit():
        # Retrieve form data
        data = {
            'username': form.username.data,
            'email': form.email.data,
            'phone': form.phone.data,
            'password': form.password.data
        }

        # Perform checks on the data
        if not all(key in data for key in ('username', 'email', 'phone', 'password')):
            return bad_request('Must include username, email, phone, and password fields.')

        if db.session.scalar(sa.select(User).where(User.username == data['username'])):
            return bad_request('Please use a different username.')

        if db.session.scalar(sa.select(User).where(User.email == data['email'])):
            return bad_request('Please use a different email address.')

        if db.session.scalar(sa.select(User).where(User.phone == data['phone'])):
            return bad_request('Please use a different phone number.')

        try:
            # Create and save the new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone=form.phone.data,
                password=hash_txt(form.password.data),
                ip=ip_adrs.user_ip()
            )
            db.session.add(user)
            db.session.commit()

            # Send verification email
            email.verify_email(user)

            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('auth.signin'))
        except Exception as e:
            print(traceback.print_exc())
            db.session.rollback()  # Rollback the transaction to maintain data integrity
            flash(f'User registration failed. {str(e)}', 'danger')

    return render_template('auth/signup.html', title='Sign-up', form=form)

#this route-initializes auth
@auth.route('/authorize/<provider>')
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

@auth.route('/callback/<provider>')
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

@auth.route("/signin", methods=['GET', 'POST'])
@db_session_management
def signin():

    referrer = request.referrer
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))

    form = SigninForm()
    if form.validate_on_submit():
        user = User.query.filter( or_( User.email==form.signin.data, User.phone==form.signin.data, User.username==form.signin.data) ).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user.online = True
            user.last_seen = datetime.utcnow()
            user.ip = ip_adrs.user_ip()
            db.session.commit()
            login_user(user, remember=form.remember.data)
            #login_user(user)
            next_page = request.args.get('next')
            #return f"{current_user, form.remember.data}"
            return redirect(next_page or url_for('main.index'))
        else: 
            flash('Invalid Login Details. Try Again', 'danger')
            return redirect(referrer)
            #return f"Authentication failed. Reach out to admin regarding this"
    return render_template('auth/signin.html', title='Sign In', form=form)

@auth.route("/signout")
@login_required
@db_session_management
def signout():
    logout_user()
    current_user.online = False
    db.session.commit()
    return redirect(url_for('main.welcome'))

@auth.route("/<string:username>/update", methods=['GET', 'POST'])
@login_required
@admin_or_current_user()
# @db_session_management
def update(username):
    try:

        user = User.query.filter(User.username==username).first_or_404()
        form = UpdateMeForm()
        query_form = QueryForm()

        # only admins/account-ownr | this is also done by this decorator `@admin_or_current_user()`
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
        
        handles = user.socials # Retrieve existing dictionary or create a new one

        if form.validate_on_submit():
            with db.session.no_autoflush:
                existing_user = User.query.filter(User.phone == form.phone.data, User.username != user.username).first()
                if existing_user:
                    message = "The phone number is already in use. Please use a different phone number."
                    return jsonify({"success": False, "error": str(message) }), 200
            
            if 'photo' in request.files:
                photo_filename = save_image.save_photo(request.files['photo'])
                user.photo = photo_filename
                print("photo file-name", photo_filename)
                
            user.name = form.name.data
            user.username = form.username.data
            user.email = form.email.data
            user.phone = form.phone.data
            user.address = form.address.data
            user.gender = form.gender.data
            user.acct_no = form.acct_no.data
            user.bank = form.bank.data
            user.city = form.city.data
            user.about = form.about.data
            user.password = hash_txt(form.password.data) if form.password.data else user.password
            user.category = form.category.data or 'user'
            new_role_ids = [form.role.data]  # Assuming the form data provides a list of role IDs
            new_roles = Role.query.filter(Role.id.in_(new_role_ids) ).all()
            user.role = new_roles
            
            # Additional fields from UpdateMeForm
            user.designation = form.designation.data
            user.academic_qualification = form.academic_qualification.data
            user.experience_years = form.experience_years.data
            user.experience_level = form.experience_level.data
            user.refferee_type = form.refferee_type.data
            user.refferee_email = form.refferee_email.data
            user.refferee_phone = form.refferee_phone.data
            user.refferee_address = form.refferee_address.data
            user.dob = form.dob.data
            user.reg_num = form.reg_num.data
            user.course = form.course.data
            user.cert_status = form.cert_status.data
            user.completion_status = form.completion_status.data
                
            social_handles = \
                {'facebook': form.facebook.data, 'twitter' : form.twitter.data, 
                 'instagram' :form.instagram.data, 'linkedin' :form.linkedin.data }
            #user.socials = str(social_handles)
            user.socials = social_handles
                
            db.session.commit()
            db.session.flush()
            
            message = 'Account updated successfully!'
            return jsonify({"success": True, "message":str(message)}), 200
        
        elif request.method == 'GET':
            if handles:
                form.twitter.data = handles['twitter'] 
                form.facebook.data = handles['facebook'] 
                form.instagram.data = handles['instagram'] 
                form.linkedin.data = handles['linkedin'] 
            form.name.data = user.name
            form.username.data = user.username
            form.email.data = user.email
            form.phone.data = user.phone
            form.gender.data = user.gender
            form.acct_no.data = user.acct_no
            form.city.data = user.city
            form.address.data = user.address
            form.about.data = user.about
            form.bank.data = user.bank
            
            # Additional fields from User to UpdateMeForm
            form.designation.data = user.designation
            form.academic_qualification.data = user.academic_qualification
            form.experience_years.data = user.experience_years
            form.experience_level.data = user.experience_level
            form.refferee_type.data = user.refferee_type
            form.refferee_email.data = user.refferee_email
            form.refferee_phone.data = user.refferee_phone
            form.refferee_address.data = user.refferee_address
            form.dob.data = user.dob
            form.reg_num.data = user.reg_num
            form.course.data = user.course
            form.cert_status.data = user.cert_status
            form.completion_status.data = user.completion_status

        if request.method == "POST" and not form.validate_on_submit():
            return jsonify({"success": False, "error": str(form.errors) }), 200

        context = {
            'form' : form, 
            "query_form" : query_form, 
            'user': user, 
            'brand': {"name":"Dunistech academy"} }
        
        return render_template('auth/update.html',  **context)

    except Exception as e:
        print(e)
        return jsonify({"success": False, "error": str(e) }), 200
    
@auth.route("/forgot", methods=['GET', 'POST'])
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
@auth.route("/unverified", methods=['post', 'get'])
@login_required
@db_session_management
def unverified():
    if request.method == 'POST':
        email.verify_email(current_user)
        flash('Verication Emails Sent Again, Check You Mail Box', 'info')
    return render_template('auth/unverified.html')

#->for both verify/reset tokens
@auth.route("/confirm/<token>", methods=['GET', 'POST'])
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

@auth.route('/get_notifications/api', methods=['POST', 'GET', 'PUT', 'DELETE']) 
@login_required
@db_session_management
def get_notifications():

    unread_notifications = Notification.query.filter(Notification.deleted == False).order_by(Notification.created.desc()).all()

    # Mark the fetched notifications as read
    for notification in unread_notifications:
        notification.is_read = True
    db.session.commit()

    # Return unread notifications as JSON
    notifications_data = [{'id': n.id, 'title': n.title, 'message': n.message, 'photo': n.photo, 'created': n.created.strftime('%H:%M:%S')} for n in unread_notifications]
    return jsonify(notifications=notifications_data)
    