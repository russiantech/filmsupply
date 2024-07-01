""" function is_active(endpoint) {
        return request.endpoint === endpoint || request.endpoint.startsWith(endpoint + '.');
    }  """
from flask import request


# Custom function definition
def is_active(*endpoints):
    #return any(request.endpoint == endpoint or request.endpoint.startswith(endpoint + '.') for endpoint in endpoints)
    return any(request.endpoint == endpoint or request.endpoint.endswith('.' + endpoint) for endpoint in endpoints)
