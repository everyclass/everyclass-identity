import functools

from flask import request

from everyclass.identity.consts import E_LOGIN_REQUIRED


def login_required(func):
    """
    a decorator for routes which is only available for logged-in users.
    """

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        if not request.headers.get("STUDENT_ID", None):
            from everyclass.identity.views import return_err
            return return_err(E_LOGIN_REQUIRED)
        return func(*args, **kwargs)

    return wrapped
