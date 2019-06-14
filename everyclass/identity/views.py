import elasticapm
from flask import Blueprint, flash, jsonify, redirect, request, session, url_for
from zxcvbn import zxcvbn

from everyclass.identity import logger
from everyclass.identity.consts import *
from everyclass.identity.db.dao import ID_STATUS_PASSWORD_SET, ID_STATUS_PWD_SUCCESS, ID_STATUS_SENT, \
    ID_STATUS_TKN_PASSED, ID_STATUS_WAIT_VERIFY, IdentityVerification, PrivacySettings, Redis, \
    SimplePassword, User, VisitTrack
from everyclass.identity.utils.decorators import login_required
from everyclass.rpc import RpcResourceNotFound, handle_exception_with_error_page, handle_exception_with_message
from everyclass.rpc.api_server import APIServer
from everyclass.rpc.auth import Auth
from everyclass.rpc.tencent_captcha import TencentCaptcha

user_bp = Blueprint('user', __name__)


def return_err(err_code: Error):
    return jsonify({"success" : False,
                    "err_code": err_code.err_code,
                    "message" : err_code.message})


@user_bp.route('/login', methods=["GET", "POST"])
def login():
    """
    用户登录

    采用表单 POST。如果正确则返回 JWT Token

    表单参数：
    - student_id
    - password
    """
    if not request.form.get("student_id", None):
        return return_err(E_EMPTY_USERNAME)
    else:
        student_id = request.form.get("student_id", None)

    if not request.form.get("password", None):
        return return_err(E_EMPTY_PASSWORD)

    # captcha
    if not TencentCaptcha.verify():
        return return_err(E_INVALID_CAPTCHA)

    # 检查学号是否存在
    try:
        student = APIServer.get_student(student_id)
    except RpcResourceNotFound:
        return return_err(E_STUDENT_UNEXIST)

    except Exception as e:
        return handle_exception_with_message(e)

    try:
        success = User.check_password(student_id, request.form["password"])
    except ValueError:
        # 未注册
        return return_err(E_STUDENT_NOT_REGISTERED)

    if success:
        print(student.name)
        # todo 颁发 jwt token
    else:
        return return_err(E_WRONG_PASSWORD)


@user_bp.route('/register', methods=["POST"])
def register():
    """注册第一步：输入学号，检查是否已经注册

    表单参数：
    - student_id
    """
    if not request.form.get("student_id", None):  # 表单为空
        return return_err(E_EMPTY_USERNAME)
    else:
        student_id = request.form.get("student_id", None)

    # 如果输入的学号已经注册，跳转到登录页面
    if User.exist(student_id):
        return return_err(E_ALREADY_REGISTERED)

    return jsonify({"success": True})


@user_bp.route('/register/byEmail')
def register_by_email():
    """使用邮箱验证注册

    表单参数：
    - student_id
    """
    if not request.form.get("student_id", None):
        return return_err(E_EMPTY_USERNAME)
    else:
        student_id = request.form.get("student_id", None)

    if User.exist(student_id):
        return return_err(E_ALREADY_REGISTERED)

    request_id = IdentityVerification.new_register_request(student_id, "email", ID_STATUS_SENT)

    with elasticapm.capture_span('send_email'):
        try:
            rpc_result = Auth.register_by_email(request_id, student_id)
        except Exception as e:
            return handle_exception_with_error_page(e)

    if rpc_result['acknowledged']:
        return jsonify({"success": True,
                        "message": "Email sent"})
    else:
        return return_err(E_INTERNAL_ERROR)


@user_bp.route('/emailVerification', methods=['GET', 'POST'])
def email_verification():
    """
    注册：邮箱验证。GET 代表验证 token，POST 代表设置密码。

    GET 表单参数：
    - token

    POST 表单参数：
    - token
    - password
    """
    if request.method == 'POST':
        # 设置密码表单提交
        if not request.form.get("token", None):
            return return_err(E_EMPTY_TOKEN)
        if not request.form.get("password", None):
            return return_err(E_EMPTY_PASSWORD)

        try:
            rpc_result = Auth.verify_email_token(token=request.form.get("token", None))
        except Exception as e:
            return handle_exception_with_message(e)

        if not rpc_result.success:
            return return_err(E_INVALID_TOKEN)

        req = IdentityVerification.get_request_by_id(rpc_result.request_id)
        if req["status"] != ID_STATUS_TKN_PASSED:
            return return_err(E_INVALID_TOKEN)

        sid_orig = req['sid_orig']

        # 密码强度检查
        pwd_strength_report = zxcvbn(password=request.form["password"])
        if pwd_strength_report['score'] < 2:
            SimplePassword.new(password=request.form["password"], sid_orig=sid_orig)
            return return_err(E_WEAK_PASSWORD)

        User.add_user(sid_orig=sid_orig, password=request.form['password'])
        IdentityVerification.set_request_status(str(req["request_id"]), ID_STATUS_PASSWORD_SET)

        return jsonify({"success": True,
                        "message": "Register success"})
    else:
        # GET 验证 token
        if not request.args.get("token", None):
            return return_err(E_EMPTY_TOKEN)

        try:
            rpc_result = Auth.verify_email_token(token=request.form.get("token", None))
        except Exception as e:
            return handle_exception_with_message(e)

        if rpc_result.success:
            IdentityVerification.set_request_status(rpc_result.request_id, ID_STATUS_TKN_PASSED)
            return jsonify({"success": True,
                            "message": "Valid token"})
        else:
            return return_err(E_INVALID_TOKEN)


@user_bp.route('/register/byPassword', methods=['POST'])
def register_by_password():
    """使用密码验证注册

    表单参数：
    - student_id
    - password
    - jwPassword
    """
    if not request.form.get("student_id", None):
        return return_err(E_EMPTY_USERNAME)
    else:
        student_id = request.form["student_id"]
    if any(map(lambda x: not request.form.get(x, None), ("password", "jwPassword"))):
        return return_err(E_EMPTY_PASSWORD)

    # todo 这里可以通过 api-server 查询判断一下学号是否存在

    # 密码强度检查
    pwd_strength_report = zxcvbn(password=request.form["password"])
    if pwd_strength_report['score'] < 2:
        SimplePassword.new(password=request.form["password"],
                           sid_orig=student_id)
        return return_err(E_WEAK_PASSWORD)

    # captcha
    if not TencentCaptcha.verify():
        return return_err(E_INVALID_CAPTCHA)

    request_id = IdentityVerification.new_register_request(student_id,
                                                           "password",
                                                           ID_STATUS_WAIT_VERIFY,
                                                           password=request.form["password"])

    # call everyclass-auth to verify password
    with elasticapm.capture_span('register_by_password'):
        try:
            rpc_result = Auth.register_by_password(request_id=str(request_id),
                                                   student_id=student_id,
                                                   password=request.form["jwPassword"])
        except Exception as e:
            return handle_exception_with_error_page(e)

    if rpc_result['acknowledged']:
        return jsonify({"success": True,
                        "message": "Acknowledged"})
    else:
        return return_err(E_INTERNAL_ERROR)


@user_bp.route('/register/passwordStrengthCheck', methods=["POST"])
def password_strength_check():
    """AJAX 密码强度检查"""
    if request.form.get("password", None):
        # 密码强度检查
        pwd_strength_report = zxcvbn(password=request.form["password"])
        if pwd_strength_report['score'] < 2:
            return jsonify({"strong": False,
                            "score" : pwd_strength_report['score']})
        else:
            return jsonify({"strong": True,
                            "score" : pwd_strength_report['score']})
    return jsonify({"invalid_request": True})


@user_bp.route('/register/byPassword/statusRefresh')
def register_by_password_status():
    """AJAX 刷新教务验证状态"""
    if not request.args.get("request", None) or not isinstance(request.args["request"], str):
        return "Invalid request"
    req = IdentityVerification.get_request_by_id(request.args.get("request"))
    if not req:
        return "Invalid request"
    if req["verification_method"] != "password":
        logger.warn("Non-password verification request is trying get status from password interface")
        return "Invalid request"

    # fetch status from everyclass-auth
    with elasticapm.capture_span('get_result'):
        try:
            rpc_result = Auth.get_result(str(request.args.get("request")))
        except Exception as e:
            return handle_exception_with_error_page(e)

    if rpc_result['success']:  # 密码验证通过，设置请求状态并新增用户
        IdentityVerification.set_request_status(str(request.args.get("request")), ID_STATUS_PWD_SUCCESS)

        verification_req = IdentityVerification.get_request_by_id(str(request.args.get("request")))

        # 从 api-identity 查询学生基本信息
        try:
            student = APIServer.get_student(verification_req["sid_orig"])
        except Exception as e:
            return handle_exception_with_error_page(e)

        # 添加用户
        try:
            User.add_user(sid_orig=verification_req["sid_orig"], password=verification_req["password"],
                          password_encrypted=True)
        except ValueError:
            return return_err(E_ALREADY_REGISTERED)

        return jsonify({"message": "SUCCESS"})
    elif rpc_result["message"] in ("PASSWORD_WRONG", "INTERNAL_ERROR"):
        return jsonify({"message": rpc_result["message"]})
    else:
        return jsonify({"message": "NEXT_TIME"})


@user_bp.route('/setPreference', methods=["POST"])
@login_required
def js_set_preference():
    """更新偏好设置"""
    if request.form.get("privacyLevel", None):
        # update privacy level
        privacy_level = int(request.form["privacyLevel"])
        if privacy_level not in (0, 1, 2):
            logger.warn("Received malformed set preference request. privacyLevel value not valid.")
            return jsonify({"acknowledged": False,
                            "message"     : "Invalid value"})

        PrivacySettings.set_level(request.headers["STUDENT_ID"], privacy_level)
    return jsonify({"acknowledged": True})


@user_bp.route('/resetCalendarToken')
@login_required
def reset_calendar_token():
    """重置日历订阅令牌"""
    CalendarToken.reset_tokens(session[SESSION_CURRENT_USER].sid_orig)
    flash("日历订阅令牌重置成功")
    return redirect(url_for("user.main"))


@user_bp.route('/visitors')
@login_required
def visitors():
    """我的访客页面"""
    visitor_list = VisitTrack.get_visitors(request.headers["STUDENT_ID"])
    visitor_count = Redis.get_visitor_count(request.headers["STUDENT_ID"])
    return jsonify({"success" : True,
                    "count"   : visitor_count,
                    "visitors": visitor_list})
