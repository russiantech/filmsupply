from flask import request

def user_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip =  request.environ['REMOTE_ADDR']
    else:
        ip = request.environ['HTTP_X_FORWARDED_FOR'] # if behind a proxy
    return ip