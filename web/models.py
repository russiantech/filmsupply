from datetime import datetime
import jwt, time
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask import current_app

db = SQLAlchemy()

user_roles = db.Table(
    'user_roles',
    db.Column('uid', db.Integer, db.ForeignKey('user.id')),
    db.Column('rid', db.Integer, db.ForeignKey('role.id')),
    keep_existing=True
)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), index=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), unique=True, index=True)
    image = db.Column(db.String(1000))
    
    password = db.Column(db.String(500), nullable=False)
    withdrawal_password = db.Column(db.String(500), nullable=False)

    tier = db.Column(db.String(50), nullable=False, default='normal')
    balance = db.Column(db.Float, default=0.0)

    admin = db.Column(db.Boolean(), default=False)
    gender = db.Column(db.String(50))
    about = db.Column(db.String(5000))
    
    verified = db.Column(db.Boolean(), default=False)
    ip = db.Column(db.String(50))
    
    orders = db.relationship('Order', backref='user', lazy=True)
    account_details = db.relationship('AccountDetails', backref='user', lazy=True)

    notifications = db.relationship('Notification', backref='user', lazy=True)
    roles = db.relationship('Role', secondary=user_roles, back_populates='user', lazy='dynamic')

    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), onupdate = func.now(),  default=func.now())
    deleted = db.Column(db.Boolean(), default=False)

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return any(role.type == 'admin' for role in self.role)

    def permit(self):
        return [r.type for r in self.role]

    def generate_token(self, exp=600, type='reset'):
        payload = {'uid': self.id, 'exp': time.time() + exp, 'type': type }
        secret_key = current_app.config['SECRET_KEY']
        return jwt.encode(payload, secret_key, algorithm='HS256')

    @staticmethod
    def verify_token(token):
        try:
            secret_key = current_app.config['SECRET_KEY']
            uid = jwt.decode(token, secret_key, algorithms=['HS256'])['uid']
            user = User.query.get(uid)
            type = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['type']
        except:
            return
        return user, type

    def __repr__(self):
        return f"User('{self.name}', '{self.email}', '{self.photo}')"


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(128), index=True)
    image = db.Column(db.String(128), index=True)
    message = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)

    deleted = db.Column(db.Boolean(), default=False)
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now())

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'image': self.image,
            'message': self.message,
            'file_path': self.file_path,
            'is_read': self.is_read,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat(),
            'deleted': self.deleted
        }
        
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key = True)
    level = db.Column(db.String(100), unique=True)
    user = db.relationship('User', secondary=user_roles, back_populates='role', lazy='dynamic')

class Payment(db.Model):
    __tablename__ = 'payment'
    id = db.Column(db.Integer, unique=True, primary_key=True, nullable=False)
    usr_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Orderinfo->User->foreign-key
    
    txn_ref = db.Column(db.String(100)) #['dollar, naira etc]
    txn_amt = db.Column(db.Integer())
    txn_desc = db.Column(db.String(100)) 
    txn_status = db.Column(db.String(100), default='pending') #['pending','successful', 'cancelled', 'reversed']
    currency_code = db.Column(db.String(100)) #['dollar, naira, cedis etc]
    provider = db.Column(db.String(100)) #['paypal','stripe', 'visa', 'mastercard', paystack']
    
    deleted = db.Column(db.Boolean(), default=False)  # 0-deleted, 1-not-deleted
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now())


from sqlalchemy import Enum
from enum import Enum as PyEnum

class AccountType(PyEnum):
    EXCHANGE = "exchange"
    REVOLUT = "revolut"
    WISE = "wise"

class AccountDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    account_type = db.Column(Enum(AccountType), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    exchange = db.Column(db.String(100), nullable=True)
    exchange_address = db.Column(db.String(255), nullable=True)
    bank_account = db.Column(db.String(50), nullable=True)
    short_code = db.Column(db.String(20), nullable=True)
    link = db.Column(db.String(255), nullable=True)
    wise_email = db.Column(db.String(100), nullable=True)
    
    deleted = db.Column(db.Boolean(), default=False)  # 0-deleted, 1-not-deleted
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now())
    def __repr__(self):
        return f'<AccountDetail {self.name} - {self.account_type}>'


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    task_id = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    
    # Rating attributes
    rating = db.Column(db.Integer, nullable=True)
    comment = db.Column(db.Text, nullable=True)

    deleted = db.Column(db.Boolean(), default=False)  # False: not deleted, True: deleted
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now(), onupdate=func.now())


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    reward = db.Column(db.Float, nullable=False)

    deleted = db.Column(db.Boolean(), default=False)  # 0-deleted, 1-not-deleted
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now())


    

