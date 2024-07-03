
def type(user):
    
    for r in user.role:
        return r.level.capitalize() or 'student'

    """    
    r = 0
    r =   r in [ r.type for r in user.role] if r in user.role else 'student'
    return  r
"""

'''    for r in user.role:
        #role = r.type if r in user.role else 'student'
        return r.type if r else 'student'
        #return r.type or 'student'
'''

"""    for r in user.role:
        return r.type or 'student'"""

"""
<!---- #TEST-CASES
{%for r in current_user.role%}{{r.type}}{%endfor%}
{{ current_user|type }} 
<!--
{{current_user.role}} ---
{% for role in current_user.role %} 
{{
role.id, 
role.type, 
role.created|time_ago
}} 
{% endfor %} --->"""