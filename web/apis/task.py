from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import ( User, Task , Order)
from web import db, csrf
from datetime import datetime
from web.apis.utils import round_up, user_plan_percentages, calculate_percentage
from flask import Blueprint
task_bp = Blueprint('task-api', __name__)

@task_bp.route('/tasks-completed', methods=['GET'])
def get_tasks_completed():
    try:
        """Return the list of completed tasks for the user"""
        user_id = request.args.get('user_id', type=int, default=current_user.id)
        
        completed_tasks = Order.query.filter_by(user_id=user_id).all()
        tasks_list = [{
            'id': order.task.id,
            'image': order.task.image,
            'title': order.task.title,
            'description': order.task.description,
            'rating': str(order.rating),
            'status': order.status,
            'earnings': order.earnings,
            'amount': order.task.reward,
            'created': order.created.strftime('%A %d, %Y')
        } for order in completed_tasks if order.task]
        # return jsonify(tasks_list), 200
        return jsonify({'success': True, 'tasks': tasks_list}), 200

    except Exception as e:
        return jsonify({'success':False, 'error': str(e)})

@task_bp.route('/tasks-pending', methods=['GET'])
@login_required
def get_next_pending_task():
    try:
        """ Return the next pending task for the user along with task stats """
        user_id = request.args.get('user_id', type=int, default=current_user.id)  # Replace with actual user logic
        # print(user_id)
        # Fetch the user's plan
        user = User.query.get(user_id) or current_user
        user_plan = user.tier if user else 'normal'  # Default to 'normal' plan if user not found

        plan_percentage = user_plan_percentages.get(user_plan, 0.7)  # Default to 0.7 if plan not found
        
        completed_task_ids = [order.task_id for order in Order.query.filter_by(user_id=user_id).all()]

        # print("completed task ids:", completed_task_ids)

        total_tasks = Task.query.count()
        completed_tasks = len(completed_task_ids)
        next_task = Task.query.filter(~Task.id.in_(completed_task_ids) ).first()
        
        if next_task:
            #calculate earnings
            plan_percentage = user_plan_percentages.get(user_plan, 0)
            earnings = calculate_percentage(plan_percentage, next_task.reward)
            task_data = {
                'id': next_task.id,
                'image': next_task.image,
                'title': next_task.title,
                'description': next_task.description,
                'reward': next_task.reward,
                'earnings': round_up(earnings)
            }
            return jsonify({
                'task': task_data,
                'total_tasks': total_tasks,
                'completed_tasks': completed_tasks
            }), 200
        else:
            return jsonify({
                'task': None,
                'total_tasks': total_tasks,
                'completed_tasks': completed_tasks
            }), 200

    except Exception as e:
        return jsonify({'success':False, 'error': str(e)})


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


@task_bp.route('/tasks/<int:id>', methods=['GET'])
def get_task(id):
    try:
        task = Task.query.get_or_404(id)
        user_id = request.args.get('user_id', current_user.id) # do not forget to update this line ti work with actual user_id
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'})
        
        return jsonify({
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'reward': task.reward,
            'user_plan': user.plan  # Assuming user.plan stores the user's plan
        })
    except Exception as e:
        return jsonify({'success':False, 'error': str(e)})

# get many
@task_bp.route('/tasks-all', methods=['GET'])
def get_tasks():
    tasks = Task.query.all()  # Get all tasks
    tasks_list = [{'id': task.id, 'image': task.image, 'title': task.title, 'description': task.description, 'reward': task.reward} for task in tasks]
    return jsonify(tasks_list), 200

# Add this endpoint to your Flask application
@task_bp.route('/tasks/total', methods=['GET'])
def get_total_tasks():
    total_tasks = Task.query.count()
    return jsonify({'total_tasks': total_tasks}), 200

@task_bp.route('/tasks-pending', methods=['GET'])
@login_required
def tasks_pending():
    """ filter out and return only pending tasks for the user """
    user_id = request.args.get('user_id', current_user.id)
    completed_task_ids = [order.task_id for order in Order.query.filter_by(user_id=user_id).all()]
    tasks = Task.query.filter(~Task.id.in_(completed_task_ids)).all()
    tasks_list = [{'id': task.id, 'image':task.image, 'title': task.title, 'description': task.description, 'reward': task.reward} for task in tasks]
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