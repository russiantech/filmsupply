from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import (  Order )
from web import db, csrf
from datetime import datetime

from flask import Blueprint
order = Blueprint('orders', __name__)

# create order
@order.route('/orders', methods=['POST'])
def create_order():
    data = request.get_json()
    new_order = Order(
        user_id=data['user_id'],
        task_id=data['task_id'],
        amount=data['amount'],
        status=data['status'],
        rating = data['rating'],
        comment = data['comment']
    )
    db.session.add(new_order)
    db.session.commit()
    return jsonify({"message": "Order created successfully"}), 201

# get single-order
@app.route('/orders/<int:id>', methods=['GET'])
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
@app.route('/orders', methods=['GET'])
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

# update an oreder
@order.route('/orders/<int:id>', methods=['PUT'])
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
@order.route('/orders/<int:id>', methods=['DELETE'])
def delete_order(id):
    order = Order.query.get_or_404(id)
    # db.session.delete(order)
    order.deleted = True
    db.session.commit()
    return jsonify({'message': 'Order deleted successfully!'})

