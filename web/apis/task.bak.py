from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import (  Task )
from web import db, csrf
from datetime import datetime

from flask import Blueprint
task_bp = Blueprint('task-api', __name__)

@app.route('/tasks', methods=['POST'])
def create_task():
    data = request.json
    new_task = Task(
        title=data['title'],
        description=data.get('description'),
        reward=data['reward']
    )
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'success':True, 'message': 'Task created successfully'}), 201

@app.route('/tasks/<int:id>', methods=['GET'])
def get_task(id):
    task = Task.query.get_or_404(id)
    return jsonify({
        'title': task.title,
        'description': task.description,
        'reward': task.reward
    })

@app.route('/tasks/<int:id>', methods=['PUT'])
def update_task(id):
    data = request.json
    task = Task.query.get_or_404(id)
    task.title = data['title']
    task.description = data.get('description', task.description)
    task.reward = data['reward']
    db.session.commit()
    return jsonify({'message': 'Task updated successfully'})

@app.route('/tasks/<int:id>', methods=['DELETE'])
def delete_task(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully'})





@task_bp.route('/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    new_task = Task(name=data['name'], description=data['description'], price=data['price'])
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task created successfully!'}), 201

@task_bp.route('/tasks', methods=['GET'])
def get_tasks():
    tasks = Task.query.all()  # Get all tasks
    tasks_list = [{'id': task.id, 'name': task.name, 'description': task.description, 'price': task.price} for task in tasks]
    return jsonify(tasks_list), 200

@task_bp.route('/tasks/<int:id>', methods=['GET'])
def get_task(id):
    task = Task.query.get_or_404(id)
    return jsonify({
        'id': task.id,
        'name': task.name,
        'description': task.description,
        'price': task.price
    })

@task_bp.route('/tasks/<int:id>', methods=['PUT'])
def update_task(id):
    data = request.get_json()
    task = Task.query.get_or_404(id)
    task.name = data['name']
    task.description = data['description']
    task.price = data['price']
    db.session.commit()
    return jsonify({'message': 'Task updated successfully!'})

@task_bp.route('/tasks/<int:id>', methods=['DELETE'])
def delete_task(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully!'})

@task_bp.route('/insert_tasks', methods=['GET'])
def insert_sample_tasks():
    tasks = [
        Task(name="Task 1", description="Complete the introduction module.", price=10.0),
        Task(name="Task 2", description="Submit your first assignment.", price=15.0),
        Task(name="Task 3", description="Participate in the group discussion.", price=20.0),
        Task(name="Task 4", description="Complete the quiz for module 1.", price=25.0),
        Task(name="Task 5", description="Submit your project proposal.", price=30.0),
        Task(name="Task 6", description="Attend the live webinar.", price=35.0),
        Task(name="Task 7", description="Submit the midterm report.", price=40.0),
        Task(name="Task 8", description="Complete the quiz for module 2.", price=45.0),
        Task(name="Task 9", description="Submit your final project.", price=50.0),
        Task(name="Task 10", description="Provide feedback on the course.", price=55.0)
    ]

    for task in tasks:
        db.session.add(task)

    db.session.commit()
    print("Sample tasks inserted successfully!")
    return ("Sample tasks inserted successfully!")