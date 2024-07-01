""" def get_users(user_id):
    messages = cls.query.filter(or_(cls.from_id == user_id, cls.to_id == user_id)).subquery()

    users = User.query.join(messages, or_(messages.c.to_id == User.id,
                           messages.c.from_id == User.id)).filter(User.id != user_id)

    return users """

from flask_login import current_user
from sqlalchemy import or_
from web.models import Message, User


""" def chat_list():
    #messages = Message.query.filter(or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)).subquery()
    messages = Message.query.filter(or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)).distinct()
    users = User.query.join(messages, or_(messages.author.id == User.id, messages.recipient.id == User.id)
                            ).filter(User.id != current_user.id)
    return users """

def chat_list():
    #messages = Message.query.filter(or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)).subquery()
    messages = Message.query.filter(or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)).distinct()
    """     users = User.query.join(messages, or_(messages.sender_id == User.id, messages.recipient_id == User.id)
                            ).filter(User.id != current_user.id) """

    return messages


