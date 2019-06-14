from typing import NamedTuple


class Error(NamedTuple):
    err_code: int
    message: str


E_EMPTY_USERNAME = Error(4001, "Empty username")  # 用户名为空
E_EMPTY_PASSWORD = Error(4002, "Empty password")  # 密码空
E_INVALID_CAPTCHA = Error(4003, "Invalid captcha")  # 验证码验证未通过
E_STUDENT_UNEXIST = Error(4004, "Student not exist")  # 学号不存在
E_STUDENT_NOT_REGISTERED = Error(4005, "Student not registered")  # 此学生未注册
E_WRONG_PASSWORD = Error(4006, "Wrong password")  # 密码错误
E_ALREADY_REGISTERED = Error(4007, "Already registered")  # 已经注册过了，不要重复注册
E_EMPTY_TOKEN = Error(4008, "Empty token")  # 邮件 token 验证没有传递 token
E_INVALID_TOKEN = Error(4009, "Invalid token")  # 邮件 token 无效
E_WEAK_PASSWORD = Error(4010, "Weak password")  # 密码强度过弱
E_LOGIN_REQUIRED = Error(4011, "Login required")  # 需要登录
E_INTERNAL_ERROR = Error(5001, "Internal error")  # 内部未定义的错误
