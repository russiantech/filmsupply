def direct_user(user):
    if user.is_authenticated:
        #roles = [role.type for role in current_user.role]
        user_url = ''
        roles = [user.role[0].type for role in current_user.role]
            if 'admin' in roles:
                user_url = redirect(url_for('main.index'))
            elif 'kitchen' in roles:
                user_url = redirect(url_for('main.kitchen'))
            elif 'cocktail' in roles:
                user_url = redirect(url_for('main.cocktail'))
            elif 'bar' in roles:
                user_url = redirect(url_for('main.bar'))
            else:
                user_url = redirect(url_for('auth.update', usrname=current_user.username))
        else:
            return current_app.login_manager.unauthorized()

        return user_url

""" def direct_user(user):
    if user.is_authenticated:
        #roles = [role.type for role in current_user.role]
        roles = [user.role[0].type for role in current_user.role]
            if 'admin' in roles:
                return redirect(url_for('main.index'))
            elif 'kitchen' in roles:
                return redirect(url_for('main.kitchen'))
            elif 'cocktail' in roles:
                return redirect(url_for('main.cocktail'))
            elif 'bar' in roles:
                return redirect(url_for('main.bar'))
            else:
                return redirect(url_for('auth.update', usrname=current_user.username))
        else:
            return current_app.login_manager.unauthorized() """
