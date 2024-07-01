from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import (  Task )
from web import db, csrf
from datetime import datetime

from flask import Blueprint
task= Blueprint('tasks', __name__)

@task.route('/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    new_task = Task(name=data['name'], description=data['description'], price=data['price'])
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task created successfully!'}), 201

@task.route('/tasks/<int:id>', methods=['GET'])
def get_task(id):
    task = Task.query.get_or_404(id)
    return jsonify({
        'id': task.id,
        'name': task.name,
        'description': task.description,
        'price': task.price
    })

@task.route('/tasks/<int:id>', methods=['PUT'])
def update_task(id):
    data = request.get_json()
    task = Task.query.get_or_404(id)
    task.name = data['name']
    task.description = data['description']
    task.price = data['price']
    db.session.commit()
    return jsonify({'message': 'Task updated successfully!'})

@task.route('/tasks/<int:id>', methods=['DELETE'])
def delete_task(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully!'})
