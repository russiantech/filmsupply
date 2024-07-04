from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import (  Task )
from web import db, csrf
from datetime import datetime

from flask import Blueprint
task_bp = Blueprint('task-api', __name__)


@task_bp.route('/tasks', methods=['POST'])
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

# get one
@task_bp.route('/tasks/<int:id>', methods=['GET'])
def get_task(id):
    task = Task.query.get_or_404(id)
    return jsonify({
        'title': task.title,
        'description': task.description,
        'reward': task.reward
    })

# get many
@task_bp.route('/tasks', methods=['GET'])
def get_tasks():
    tasks = Task.query.all()  # Get all tasks
    tasks_list = [{'id': task.id, 'title': task.title, 'description': task.description, 'reward': task.reward} for task in tasks]
    return jsonify(tasks_list), 200

# update task
@task_bp.route('/tasks/<int:id>', methods=['PUT'])
def update_task(id):
    data = request.json
    task = Task.query.get_or_404(id)
    task.title = data['title']
    task.description = data.get('description', task.description)
    task.reward = data['reward']
    db.session.commit()
    return jsonify({'message': 'Task updated successfully'})

@task_bp.route('/tasks/<int:id>', methods=['DELETE'])
def delete_task(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully'})


@task_bp.route('/insert_tasks', methods=['GET'])
def insert_sample_tasks():
    tasks = [
        Task(title="Task 1", description="Complete the introduction module.", reward=10.0),
        Task(title="Task 2", description="Submit your first assignment.", reward=15.0),
        Task(title="Task 3", description="Participate in the group discussion.", reward=20.0),
        Task(title="Task 4", description="Complete the quiz for module 1.", reward=25.0),
        Task(title="Task 5", description="Submit your project proposal.", reward=30.0),
        Task(title="Task 6", description="Attend the live webinar.", reward=35.0),
        Task(title="Task 7", description="Submit the midterm report.", reward=40.0),
        Task(title="Task 8", description="Complete the quiz for module 2.", reward=45.0),
        Task(title="Task 9", description="Submit your final project.", reward=50.0),
        Task(title="Task 10", description="Provide feedback on the course.", reward=55.0)
    ]

    for task in tasks:
        db.session.add(task)

    db.session.commit()
    print("Sample tasks inserted successfully!")
    return ("Sample tasks inserted successfully!")