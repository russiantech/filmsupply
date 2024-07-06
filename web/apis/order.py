from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import ( Task, Order, User )
from web import db, csrf
from datetime import datetime

from flask import Blueprint
order_bp = Blueprint('orders-api', __name__)

def calculate_percentage(percentage, number):
    """
    Calculate the percentage of a given number with input validation.
    
    :param percentage: The percentage to calculate (e.g., 0.7 for 0.7%)
    :param number: The number to calculate the percentage of
    :return: The result of the percentage calculation
    """
    # Validate that percentage is a number
    if not isinstance(percentage, (int, float)):
        raise ValueError("Percentage must be a number.")
    
    # Validate that number is a number
    if not isinstance(number, (int, float)):
        raise ValueError("Number must be a number.")
    
    # Validate that percentage is between 0 and 100
    if percentage < 0 or percentage > 100:
        raise ValueError("Percentage must be between 0 and 100.")
    
    # Calculate the percentage
    return (percentage / 100) * number

# Example usage:
try:
    result = calculate_percentage(0.7, 10)
    print(result)  # Output: 0.07
except ValueError as e:
    print(e)

# Assuming 'user_plan_percentages' dictionary maps user plans to their corresponding percentages
user_plan_percentages = {
    'normal': 0.7,
    'vip': 0.9,
    'vvip': 1.5,
    'vvvip': 2.0
}

@order_bp.route('/orders', methods=['POST'])
@login_required
@csrf.exempt
def create_order():
    try:
        data = request.get_json()

        if not data:
            raise ValueError("No input data provided")

        user_id = data.get('user_id') or current_user.id
        task_id = data.get('task_id')
        rating = data.get('rating')
        comment = data.get('comment')
        
        print(data)

        # Validate required fields
        if task_id is None:
            raise ValueError("Task ID is required")
        if rating is None:
            raise ValueError("Kindly select a rating first")
        if comment is None:
            raise ValueError("Comment is required")
        print(task_id, user_id)
        user = User.query.get_or_404(user_id)
        task = Task.query.get_or_404(task_id)

        plan_percentage = user_plan_percentages.get(user.tier, 0)
        # amount = task.reward * plan_percentage
        earnings = calculate_percentage(plan_percentage, task.reward)

        new_order = Order(
            user_id=user_id,
            task_id=task_id,
            earnings=earnings,
            status='completed',
            rating=rating,
            comment=comment
        )

        db.session.add(new_order)
        db.session.commit()

        return jsonify({"success": True, "message": "Order created successfully, continue to next one"})
        # return jsonify({"success": True, "message": "Task completed, continue to next one"})

    except ValueError as ve:
        print(ve)
        return jsonify({'success': False, 'error': str(ve)})
    except Exception as e:
        print(e)
        # Log the exception for debugging purposes
        # logging.exception("An error occurred while creating an order")
        return jsonify({'success': False, 'error': 'An internal error occurred'})

# get single-order
@order_bp.route('/orders/<int:id>', methods=['GET'])
def get_order(id):
    order = Order.query.get_or_404(id)
    if order.deleted:
        return jsonify({"message": "Order not found"}), 404
    result = {
        "id": order.id,
        "user_id": order.user_id,
        "task_id": order.task_id,
        "amount": order.amount,
        "status": order.status,
        "rating": order.rating,
        "comment": order.comment,
        "created": order.created,
        "updated": order.updated
    }
    return jsonify(result)

# get many orders
@order_bp.route('/orders', methods=['GET'])
def get_orders():
    orders = Order.query.filter_by(deleted=False).all()
    result = [
        {
            "id": order.id,
            "user_id": order.user_id,
            "task_id": order.task_id,
            "amount": order.amount,
            "status": order.status,
            "rating": order.rating,
            "comment": order.comment,
            "created": order.created,
            "updated": order.updated
        }
        for order in orders
    ]
    return jsonify(result)

# update an order
@order_bp.route('/orders/<int:id>', methods=['PUT'])
def update_order(id):
    data = request.get_json()
    order = Order.query.get_or_404(id)
    if 'user_id' in data:
        order.user_id = data['user_id']
    if 'task_id' in data:
        order.task_id = data['task_id']
    if 'amount' in data:
        order.amount = data['amount']
    if 'status' in data:
        order.status = data['status']
    if 'rating' in data:
        order.rating = data['rating']
    if 'comment' in data:
        order.comment = data['comment']
    
    db.session.commit()
    return jsonify({"message": "Order updated successfully"})

# delete order
@order_bp.route('/orders/<int:id>', methods=['DELETE'])
def delete_order(id):
    order = Order.query.get_or_404(id)
    # db.session.delete(order)
    order.deleted = True
    db.session.commit()
    return jsonify({'message': 'Order deleted successfully!'})

