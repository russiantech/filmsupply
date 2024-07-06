from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import ( User, Task , Order, Transaction)
from web import db, csrf
from datetime import datetime

from sqlalchemy import func, case
import numpy as np

from flask import Blueprint
trxn_bp = Blueprint('transaction-api', __name__)

@trxn_bp.route('/deposit', methods=['POST'])
def deposit():
    data = request.json
    user_id = data.get('user_id')
    amount = data.get('amount')
    description = data.get('description', '')

    if not user_id or not amount:
        return jsonify({'error': 'User ID and amount are required'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        user.balance += amount
        db.session.add(user)

        transaction = Transaction(
            user_id=user_id,
            transaction_type='deposit',
            amount=amount,
            description=description
        )
        db.session.add(transaction)

        db.session.commit()
        return jsonify({'message': 'Deposit successful'}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Transaction failed'}), 500

@trxn_bp.route('/withdraw', methods=['POST'])
def withdraw():
    data = request.json
    user_id = data.get('user_id')
    amount = data.get('amount')
    description = data.get('description', '')

    if not user_id or not amount:
        return jsonify({'error': 'User ID and amount are required'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    try:
        user.balance -= amount
        db.session.add(user)

        transaction = Transaction(
            user_id=user_id,
            transaction_type='withdrawal',
            amount=amount,
            description=description
        )
        db.session.add(transaction)

        db.session.commit()
        return jsonify({'message': 'Withdrawal successful'}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Transaction failed'}), 500


@trxn_bp.route('/statistics', methods=['GET'])
def statistics():
    try:
        def calculate_statistics(data):
            earnings = np.array(data['earnings'])
            deposits = np.array(data['deposits'])
            
            statistics = {
                'average_earnings': np.mean(earnings),
                'median_earnings': np.median(earnings),
                'std_dev_earnings': np.std(earnings),
                'min_earnings': np.min(earnings),
                'max_earnings': np.max(earnings),
                'average_deposits': np.mean(deposits),
                'median_deposits': np.median(deposits),
                'std_dev_deposits': np.std(deposits),
                'min_deposits': np.min(deposits),
                'max_deposits': np.max(deposits),
            }
            
            return statistics

        return calculate_statistics(data)

    except Exception as e:
        return jsonify({'success':False, 'error': str(e)})

@trxn_bp.route('/analyze_data', methods=['GET'])
def analyze_data():

    import random
    def insert_random_transactions(num_transactions):
        transaction_types = ['deposit', 'withdrawal']
        descriptions = [
            "Salary", "Grocery shopping", "Electricity bill", 
            "Dining out", "Gym membership", "Online purchase"
        ]
        
        for _ in range(num_transactions):
            # user_id = random.randint(1, 10)  # Assuming you have user IDs from 1 to 10
            user_id = 3  # Assuming you have user IDs from 1 to 10
            transaction_type = random.choice(transaction_types)
            amount = round(random.uniform(10.00, 1000.00), 2)
            description = random.choice(descriptions)
            
            transaction = Transaction(
                user_id=user_id,
                transaction_type=transaction_type,
                amount=amount,
                description=description
            )
            db.session.add(transaction)
        
        db.session.commit()

    insert_random_transactions(20)  # Insert 20 random transactions

    user_id = current_user.id

    # Retrieve deposits and earnings from the database
    # Retrieve deposits and earnings from the database
    deposits_query = db.session.query(Transaction.amount).filter(
        Transaction.user_id == user_id,
        Transaction.transaction_type == 'deposit'
    ).all()

    earnings_query = db.session.query(Transaction.amount).filter(
        Transaction.user_id == user_id,
        Transaction.transaction_type == 'withdrawal'
    ).all()

    # Extract the amounts from the queries
    deposits = [float(deposit[0]) for deposit in deposits_query] if deposits_query else []
    earnings = [float(earning[0]) for earning in earnings_query] if earnings_query else []

    # Check if we have data
    if not deposits or not earnings:
        return jsonify({'error': 'Insufficient data for analysis'}), 404

    # Convert to numpy arrays for easy calculations
    deposits_array = np.array(deposits)
    earnings_array = np.array(earnings)

    # Calculate statistics for deposits
    deposit_mean = round(np.mean(deposits_array), 2) if deposits_array.size else float('nan')
    deposit_median = round(np.median(deposits_array), 2) if deposits_array.size else float('nan')
    deposit_std_dev = round(np.std(deposits_array), 2) if deposits_array.size else float('nan')
    total_deposits = round(np.sum(deposits_array), 2)

    # Calculate statistics for earnings
    earning_mean = round(np.mean(earnings_array), 2) if earnings_array.size else float('nan')
    earning_median = round(np.median(earnings_array), 2) if earnings_array.size else float('nan')
    earning_std_dev = round(np.std(earnings_array), 2) if earnings_array.size else float('nan')
    total_earnings = round(np.sum(earnings_array), 2)

    # Ensure arrays are of the same length for correlation calculation
    min_length = min(len(deposits_array), len(earnings_array))
    deposits_array = deposits_array[:min_length]
    earnings_array = earnings_array[:min_length]

    # Calculate correlation if arrays are not empty after truncation
    correlation = round(np.corrcoef(deposits_array, earnings_array)[0, 1], 2) if deposits_array.size and earnings_array.size else float('nan')

    # Return analysis as JSON
    analysis_results = {
        'deposits': {
            'mean': deposit_mean,
            'median': deposit_median,
            'std_dev': deposit_std_dev,
            'total': total_deposits
        },
        'earnings': {
            'mean': earning_mean,
            'median': earning_median,
            'std_dev': earning_std_dev,
            'total': total_earnings
        },
        'correlation': correlation
    }

    return jsonify(analysis_results)

""" 
@trxn_bp.route('/analyze_data1', methods=['GET'])
def analyze_data1():

    import random
    def insert_random_transactions(num_transactions):
        transaction_types = ['deposit', 'withdrawal']
        descriptions = [
            "Salary", "Grocery shopping", "Electricity bill", 
            "Dining out", "Gym membership", "Online purchase"
        ]
        
        for _ in range(num_transactions):
            # user_id = random.randint(1, 10)  # Assuming you have user IDs from 1 to 10
            user_id = 3  # Assuming you have user IDs from 1 to 10
            transaction_type = random.choice(transaction_types)
            amount = round(random.uniform(10.00, 1000.00), 2)
            description = random.choice(descriptions)
            
            transaction = Transaction(
                user_id=user_id,
                transaction_type=transaction_type,
                amount=amount,
                description=description
            )
            db.session.add(transaction)
        
        db.session.commit()

    insert_random_transactions(20)  # Insert 20 random transactions

    user_id = current_user.id

    # Retrieve deposits and earnings from the database
    deposits_query = db.session.query(Transaction.amount).filter(
        Transaction.user_id == user_id,
        Transaction.transaction_type == 'deposit'
    ).all()

    earnings_query = db.session.query(Transaction.amount).filter(
        Transaction.user_id == user_id,
        Transaction.transaction_type == 'withdrawal'
    ).all()

    # Extract the amounts from the queries
    deposits = [float(deposit[0]) for deposit in deposits_query] if deposits_query else []
    earnings = [float(earning[0]) for earning in earnings_query] if earnings_query else []

    # Check if we have data
    if not deposits or not earnings:
        return jsonify({'error': 'Insufficient data for analysis'}), 404

    # Convert to numpy arrays for easy calculations
    deposits_array = np.array(deposits)
    earnings_array = np.array(earnings)

    # Calculate statistics for deposits
    deposit_mean = np.mean(deposits_array) if deposits_array.size else float('nan')
    deposit_median = np.median(deposits_array) if deposits_array.size else float('nan')
    deposit_std_dev = np.std(deposits_array) if deposits_array.size else float('nan')
    total_deposits = np.sum(deposits_array)

    # Calculate statistics for earnings
    earning_mean = np.mean(earnings_array) if earnings_array.size else float('nan')
    earning_median = np.median(earnings_array) if earnings_array.size else float('nan')
    earning_std_dev = np.std(earnings_array) if earnings_array.size else float('nan')
    total_earnings = np.sum(earnings_array)

    # Ensure arrays are of the same length for correlation calculation
    min_length = min(len(deposits_array), len(earnings_array))
    deposits_array = deposits_array[:min_length]
    earnings_array = earnings_array[:min_length]

    # Calculate correlation if arrays are not empty after truncation
    correlation = np.corrcoef(deposits_array, earnings_array)[0, 1] if deposits_array.size and earnings_array.size else float('nan')

    # Return analysis as JSON
    analysis_results = {
        'deposits': {
            'mean': deposit_mean,
            'median': deposit_median,
            'std_dev': deposit_std_dev,
            'total': total_deposits
        },
        'earnings': {
            'mean': earning_mean,
            'median': earning_median,
            'std_dev': earning_std_dev,
            'total': total_earnings
        },
        'correlation': correlation
    }

    return jsonify(analysis_results)

 """