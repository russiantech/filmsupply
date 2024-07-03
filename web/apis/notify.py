from flask import request, jsonify
from flask_login import current_user, login_required
from web.models import (  Notification )
from web import db, csrf
from datetime import datetime

from flask import Blueprint
notify_bp = Blueprint('notify-api', __name__)

@notify_bp.route('/notifications', methods=['POST'])
@login_required
def create_notification():
    data = request.get_json()
    new_notification = Notification(
        user_id=data['user_id'],
        title=data['title'],
        image=data.get('image', ''),
        message=data['message'],
        file_path=data.get('file_path', ''),
    )
    db.session.add(new_notification)
    db.session.commit()
    return jsonify({'success':True, "message": "Notification created successfully."}), 201

@notify_bp.route('/notifications', methods=['GET'])
def get_notifications():
    notifications = Notification.query.filter_by(deleted=False).all()
    return jsonify([notification.to_dict() for notification in notifications]), 200

@notify_bp.route('/notifications/<int:id>', methods=['GET'])
def get_notification(id):
    notification = Notification.query.filter_by(id=id, deleted=False).first_or_404()
    return jsonify(notification.to_dict()), 200

@notify_bp.route('/notifications/<int:id>', methods=['PUT'])
def update_notification(id):
    data = request.get_json()
    notification = Notification.query.filter_by(id=id, deleted=False).first_or_404()

    notification.title = data.get('title', notification.title)
    notification.image = data.get('image', notification.image)
    notification.message = data.get('message', notification.message)
    notification.file_path = data.get('file_path', notification.file_path)
    notification.is_read = data.get('is_read', notification.is_read)

    db.session.commit()
    return jsonify({"message": "Notification updated successfully."}), 200

@notify_bp.route('/notifications/<int:id>', methods=['DELETE'])
def delete_notification(id):
    notification = Notification.query.filter_by(id=id).first_or_404()
    notification.deleted = True
    db.session.commit()
    return jsonify({"message": "Notification deleted successfully."}), 200

