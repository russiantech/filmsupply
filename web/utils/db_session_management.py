import traceback
from sqlalchemy.exc import IntegrityError
from functools import wraps
from flask import redirect, request, jsonify, url_for
from web.models import db

def db_session_management(route_function):
    @wraps(route_function)
    def decorated_function(*args, **kwargs):
        try:
            # Check if a transaction is already active, if not, begin a new one
            # This prevents a "transaction already started" error
            if not db.session.is_active:
                db.session.begin()

            result = route_function(*args, **kwargs)

            # Commit the transaction only if it was started in this decorator
            if not db.session.is_active:
                db.session.commit()

            return result

        except IntegrityError as e:
            # Handle IntegrityError (constraint violation)
            print(e)
            db.session.rollback()
            referrer = request.headers.get('Referer')
            response = {'success': False, 'link': str(referrer), 'error': 'Sorry this already existed, and should not be duplicated'}
            return jsonify(response)

        except Exception as e:
            # Rollback the transaction in case of any other exception
            db.session.rollback()
            referrer = request.headers.get('Referer')

            error_message = str(e)
            response = {'success': False, 'link': str(referrer), 'error': error_message }

        finally:
            if not db.session.is_active:
                db.session.close()

    return decorated_function
