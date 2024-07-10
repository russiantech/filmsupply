from datetime import datetime
import random, uuid, string, jwt, time
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask import current_app
# from web.utils.ip_adrs import user_ip
    
db = SQLAlchemy()
user_roles = db.Table(
    'user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id')),
    keep_existing=True
)

def generate_user_id(length=4):
    if length < 1:
        raise ValueError("Length must be at least 1")
    range_start = 10**(length-1)
    range_end = (10**length) - 1
    return str(random.randint(range_start, range_end))


def generate_refcode():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    uu_id = db.Column(db.String(50), default='0000')
    refcode = db.Column(db.String(50), default='0000')
    name = db.Column(db.String(100), index=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), unique=True, index=True)
    image = db.Column(db.String(1000))
    password = db.Column(db.String(500), nullable=False)
    withdrawal_password = db.Column(db.String(20))
    membership = db.Column(db.String(50), nullable=False, default='normal')
    # balance = db.Column(db.Float, default=315.0)
    balance = db.Column(db.Numeric(15, 2), default=315.00, nullable=False)
    admin = db.Column(db.Boolean(), default=False)
    gender = db.Column(db.String(50))
    about = db.Column(db.String(5000))
    verified = db.Column(db.Boolean(), default=False)
    ip = db.Column(db.String(50), default='0.0.0')
    
    orders = db.relationship('Order', backref='user', lazy=True)
    account_details = db.relationship('AccountDetail', backref='user', lazy=True)
    # account_details = db.relationship('AccountDetail', backref='user', uselist=False, lazy=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    roles = db.relationship('Role', secondary=user_roles, back_populates='user', lazy='dynamic')
    # tasks = db.relationship('Task', backref='user', lazy=True)

    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), onupdate=func.now(), default=func.now())
    deleted = db.Column(db.Boolean(), default=False)


    @property
    def completed_task_ids(self):
        return [order.task_id for order in Order.query.filter_by(user_id=self.id).all()]

    @property
    def total_tasks(self):
        return Task.query.count()

    @property
    def pending_tasks(self):
        return self.total_tasks - len(self.completed_task_ids)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.uu_id or self.uu_id == '0000':
            self.uu_id = generate_user_id(5)
        if not self.refcode or self.refcode == '0000':
            self.refcode = generate_refcode()


    def get_account_details(self):
        return {detail.account_type: detail for detail in self.account_details}

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return any(role.level == 'admin' for role in self.roles)

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
    __tablename__ = 'notiications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
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
    user = db.relationship('User', secondary=user_roles, back_populates='roles', lazy='dynamic')

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, unique=True, primary_key=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Orderinfo->User->foreign-key
    
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

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Numeric(15, 2), nullable=False)
    # transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    deleted = db.Column(db.Boolean(), default=False)  # 0-deleted, 1-not-deleted

    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now())

class AccountType(PyEnum):
    EXCHANGE = "exchange"
    PAYPAL = "paypal"
    CASH_APP = "cash_app"


class AccountDetail(db.Model):
    __tablename__ = 'accountdetails'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_type = db.Column(Enum(AccountType), nullable=False, default=AccountType.PAYPAL)

    account_name = db.Column(db.String(100), nullable=False)
    account_phone = db.Column(db.String(20), nullable=True)
    exchange = db.Column(db.String(100), nullable=True)
    exchange_address = db.Column(db.String(255), nullable=True)

    bank_account = db.Column(db.String(50), nullable=True)
    short_code = db.Column(db.String(20), nullable=True)
    link = db.Column(db.String(255), nullable=True)
    
    cash_app_email = db.Column(db.String(100), nullable=True)
    cash_app_username = db.Column(db.String(100), nullable=True)
    
    paypal_phone = db.Column(db.String(100), nullable=True)
    paypal_email = db.Column(db.String(100), nullable=True)
    
    deleted = db.Column(db.Boolean(), default=False)  # 0-deleted, 1-not-deleted
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f'<AccountDetail {self.account_name} - {self.account_type}>'

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    # user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    image = db.Column(db.String(128), index=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    reward = db.Column(db.Float, nullable=False)
    orders = db.relationship('Order', backref='task', lazy=True)
    deleted = db.Column(db.Boolean(), default=False)  # 0-deleted, 1-not-deleted
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now())


class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    # user_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    # task_id = db.Column(db.Integer, nullable=False)
    earnings = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    
    # Rating attributes
    rating = db.Column(db.Integer, nullable=True)
    comment = db.Column(db.Text, nullable=True)

    deleted = db.Column(db.Boolean(), default=False)  # False: not deleted, True: deleted
    created = db.Column(db.DateTime(timezone=True), default=func.now())
    updated = db.Column(db.DateTime(timezone=True), default=func.now(), onupdate=func.now())

    

