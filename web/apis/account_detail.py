from flask_login import current_user, login_required
from web.models import (  User )
from web import db, csrf
from datetime import datetime

from flask import Blueprint
account_detail_bp = Blueprint('account-details-api', __name__)

@account_detail_bp.route('/accountdetails', methods=['POST'])
def create_account_detail():
    data = request.json
    new_account = AccountDetail(
        user_id=data['user_id'],
        account_type=data['account_type'],
        name=data['name'],
        phone=data.get('phone'),
        exchange=data.get('exchange'),
        exchange_address=data.get('exchange_address'),
        bank_account=data.get('bank_account'),
        short_code=data.get('short_code'),
        link=data.get('link'),
        wise_email=data.get('wise_email')
    )
    db.session.add(new_account)
    db.session.commit()
    return jsonify({'message': 'Account detail created successfully'}), 201

@account_detail_bp.route('/accountdetails/<int:id>', methods=['GET'])
def get_account_detail(id):
    account = AccountDetail.query.get_or_404(id)
    return jsonify({
        'user_id': account.user_id,
        'account_type': account.account_type.value,
        'name': account.name,
        'phone': account.phone,
        'exchange': account.exchange,
        'exchange_address': account.exchange_address,
        'bank_account': account.bank_account,
        'short_code': account.short_code,
        'link': account.link,
        'wise_email': account.wise_email
    })

@account_detail_bp.route('/accountdetails/<int:id>', methods=['PUT'])
def update_account_detail(id):
    data = request.json
    account = AccountDetail.query.get_or_404(id)
    account.name = data['name']
    account.phone = data.get('phone', account.phone)
    account.exchange = data.get('exchange', account.exchange)
    account.exchange_address = data.get('exchange_address', account.exchange_address)
    account.bank_account = data.get('bank_account', account.bank_account)
    account.short_code = data.get('short_code', account.short_code)
    account.link = data.get('link', account.link)
    account.wise_email = data.get('wise_email', account.wise_email)
    db.session.commit()
    return jsonify({'message': 'Account detail updated successfully'})

@account_detail_bp.route('/accountdetails/<int:id>', methods=['DELETE'])
def delete_account_detail(id):
    account = AccountDetail.query.get_or_404(id)
    db.session.delete(account)
    db.session.commit()
    return jsonify({'message': 'Account detail deleted successfully'})
