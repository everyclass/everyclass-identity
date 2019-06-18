from flask import Blueprint, current_app, jsonify, request
from zxcvbn import zxcvbn

from everyclass.identity import logger
from everyclass.identity.db.dao import CalendarToken, ID_STATUS_PASSWORD_SET, ID_STATUS_PWD_SUCCESS, ID_STATUS_SENT, \
    ID_STATUS_TKN_PASSED, ID_STATUS_WAIT_VERIFY, IdentityVerification, PrivacySettings, Redis, SimplePassword, User, \
    VisitTrack
from everyclass.identity.utils.decorators import login_required
from everyclass.identity.utils.payload import check_payloads
from everyclass.identity.utils.tokens import generate_token
from everyclass.rpc import RpcResourceNotFound, handle_exception_with_json
from everyclass.rpc.api_server import APIServer
from everyclass.rpc.auth import Auth
from everyclass.rpc.consts.identity import *
from everyclass.rpc.tencent_captcha import TencentCaptcha

user_bp = Blueprint('user', __name__)


def return_err(err: Error, message_overwrite: str = None):
    resp = jsonify({"success": False,
                    "err"    : err.err_code,
                    "message": message_overwrite if message_overwrite else err.message})
    if str(err.err_code).startswith("45"):  # 4500 表示 4 号服务（identity）的 5XX 系列错误（服务器内部错误）
        resp.status_code = 500
    return resp


@user_bp.route('/login')
def login():
    """
    用户登录

    采用JSON POST。如果正确则返回 JWT Token

    JSON 参数：
    - student_id
    - password
    - captcha_ticket
    - captcha_rand
    - remote_addr
    """
    passed, ret_msg, student_id, password = check_payloads(("student_id", return_err(E_EMPTY_USERNAME)),
                                                           ("password", return_err(E_EMPTY_PASSWORD)))
    if not passed:
        return ret_msg

    # captcha
    if not TencentCaptcha.verify():
        return return_err(E_INVALID_CAPTCHA)

    # 检查学号是否存在
    try:
        student = APIServer.get_student(student_id)
    except RpcResourceNotFound:
        return return_err(E_STUDENT_UNEXIST)
    except Exception as e:
        return handle_exception_with_json(e, lazy=True)

    try:
        success = User.check_password(student_id, password)
    except ValueError:
        # 未注册
        return return_err(E_STUDENT_NOT_REGISTERED)

    if success:
        return jsonify({"success": True,
                        "token"  : generate_token({"sub": student.student_id,
                                                   "pol": current_app.config.TYK_POLICY_ID})})
    else:
        return return_err(E_WRONG_PASSWORD)


@user_bp.route('/register')
def register():
    """注册第一步：输入学号，检查是否已经注册

    表单参数：
    - student_id
    """
    if not request.json.get("student_id", None):  # 表单为空
        return return_err(E_EMPTY_USERNAME)
    else:
        student_id = request.json.get("student_id", None).lower()

    # 如果输入的学号已经注册，跳转到登录页面
    if User.exist(student_id):
        return return_err(E_ALREADY_REGISTERED)

    return jsonify({"success": True})


@user_bp.route('/register/byEmail', methods=['POST'])
def register_by_email():
    """使用邮箱验证注册

    JSON 参数：
    - student_id
    """
    if not request.json.get("student_id", None):
        return return_err(E_EMPTY_USERNAME)
    else:
        student_id = request.json.get("student_id", None).lower()

    if User.exist(student_id):
        return return_err(E_ALREADY_REGISTERED)

    request_id = IdentityVerification.new_register_request(student_id, "email", ID_STATUS_SENT)

    try:
        rpc_result = Auth.register_by_email(request_id, student_id)
    except Exception as e:
        return handle_exception_with_json(e, lazy=True)

    if rpc_result['acknowledged']:
        return jsonify({"success": True,
                        "message": "Email sent"})
    else:
        return return_err(E_BE_INTERNAL)


@user_bp.route('/register/emailVerification', methods=['GET', 'POST'])
def email_verification():
    """
    注册：邮箱验证。GET 代表验证 token，POST 代表设置密码。

    GET JSON参数：
    - token

    POST JSON参数：
    - token
    - password
    """
    if request.method == 'POST':
        # 设置密码表单提交
        if not request.json.get("token", None):
            return return_err(E_EMPTY_TOKEN)
        else:
            token = request.json.get("token", None)

        if not request.json.get("password", None):
            return return_err(E_EMPTY_PASSWORD)
        else:
            password = request.json.get("password", None)

        try:
            rpc_result = Auth.verify_email_token(token=token)
        except Exception as e:
            return handle_exception_with_json(e, lazy=True)

        if not rpc_result.success:
            return return_err(E_INVALID_TOKEN)

        req = IdentityVerification.get_request_by_id(rpc_result.request_id)
        if req["status"] != ID_STATUS_TKN_PASSED:
            return return_err(E_INVALID_TOKEN)

        student_id = req['sid_orig']

        # 密码强度检查
        pwd_strength_report = zxcvbn(password=password)
        if pwd_strength_report['score'] < 2:
            SimplePassword.new(password=password, sid_orig=student_id)
            return return_err(E_WEAK_PASSWORD)

        User.add_user(sid_orig=student_id, password=password)
        IdentityVerification.set_request_status(str(req["request_id"]), ID_STATUS_PASSWORD_SET)

        return jsonify({"success"   : True,
                        "message"   : "Register success",
                        "student_id": student_id})
    else:
        # GET 验证 token
        if not request.json.get("token", None):
            return return_err(E_EMPTY_TOKEN)
        else:
            token = request.json.get("token", None)

        try:
            rpc_result = Auth.verify_email_token(token=token)
        except Exception as e:
            return handle_exception_with_json(e, True)

        if rpc_result.success:
            IdentityVerification.set_request_status(rpc_result.request_id, ID_STATUS_TKN_PASSED)
            return jsonify({"success": True,
                            "message": "Valid token"})
        else:
            return return_err(E_INVALID_TOKEN)


@user_bp.route('/register/byPassword', methods=['POST'])
def register_by_password():
    """使用密码验证注册

    JSON 参数：
    - student_id
    - password
    - jw_password
    - captcha_ticket
    - captcha_rand
    - remote_addr
    """
    passed, ret_msg, student_id, password, jw_password = check_payloads(
            ("student_id", return_err(E_EMPTY_USERNAME)),
            ("password", return_err(E_EMPTY_PASSWORD)),
            ("jw_password", return_err(E_EMPTY_PASSWORD)))
    if not passed:
        return ret_msg

    # todo 这里可以通过 api-server 查询判断一下学号是否存在

    # captcha
    if not TencentCaptcha.verify():
        return return_err(E_INVALID_CAPTCHA)

    # 密码强度检查
    pwd_strength_report = zxcvbn(password=password)
    if pwd_strength_report['score'] < 2:
        SimplePassword.new(password=password,
                           sid_orig=student_id)
        return return_err(E_WEAK_PASSWORD)

    request_id = IdentityVerification.new_register_request(student_id,
                                                           "password",
                                                           ID_STATUS_WAIT_VERIFY,
                                                           password=password)

    # call everyclass-auth to verify password
    try:
        rpc_result = Auth.register_by_password(request_id=str(request_id),
                                               student_id=student_id,
                                               password=jw_password)
    except Exception as e:
        return handle_exception_with_json(e, True)

    if rpc_result['acknowledged']:
        return jsonify({"success"   : True,
                        "message"   : "Acknowledged",
                        "request_id": str(request_id)})
    else:
        return return_err(E_BE_INTERNAL)


@user_bp.route('/register/passwordStrengthCheck', methods=["GET"])
def password_strength_check():
    """密码强度检查"""
    if request.json.get("password", None):
        # 密码强度检查
        pwd_strength_report = zxcvbn(password=request.json["password"])
        if pwd_strength_report['score'] < 2:
            return jsonify({"success": True,
                            "strong" : False,
                            "score"  : pwd_strength_report['score']})
        else:
            return jsonify({"success": True,
                            "strong" : True,
                            "score"  : pwd_strength_report['score']})
    return return_err(E_EMPTY_PASSWORD)


@user_bp.route('/register/byPassword/statusRefresh')
def register_by_password_status():
    """获取教务验证状态

    参数：
    - request_id
    """
    if not request.json.get("request_id", None):
        return return_err(E_EMPTY_REQUEST_ID)
    else:
        request_id = str(request.json.get("request_id", None))

    req = IdentityVerification.get_request_by_id(request_id)
    if not req:
        return return_err(E_INVALID_REQUEST)

    if req["verification_method"] != "password":
        logger.warn("Non-password verification request is trying get status from password interface")
        return return_err(E_INVALID_REQUEST)

    # fetch status from everyclass-auth
    try:
        rpc_result = Auth.get_result(request_id)
    except Exception as e:
        return handle_exception_with_json(e, lazy=True)

    if rpc_result['success']:  # 密码验证通过，设置请求状态并新增用户
        IdentityVerification.set_request_status(request_id, ID_STATUS_PWD_SUCCESS)

        verification_req = IdentityVerification.get_request_by_id(request_id)

        # 添加用户
        try:
            User.add_user(sid_orig=verification_req["sid_orig"], password=verification_req["password"],
                          password_encrypted=True)
        except ValueError:
            return return_err(E_ALREADY_REGISTERED)

        return jsonify({"success" : True,
                        "err_code": E_PWD_VER_SUCCESS.err_code,
                        "message" : E_PWD_VER_SUCCESS.message})

    elif rpc_result["message"] == "PASSWORD_WRONG":
        return jsonify({"success" : False,
                        "err_code": E_PWD_VER_WRONG.err_code,
                        "message" : E_PWD_VER_WRONG.message})
    elif rpc_result["message"] == "INTERNAL_ERROR":
        return jsonify({"success" : False,
                        "err_code": E_BE_INTERNAL.err_code,
                        "message" : E_BE_INTERNAL.message})
    else:
        return jsonify({"success" : False,
                        "err_code": E_PWD_VER_NEXT.err_code,
                        "message" : E_PWD_VER_NEXT.message})


@user_bp.route('/setPreference', methods=["POST"])
@login_required
def js_set_preference():
    """更新偏好设置"""
    if request.json.get("privacyLevel", None):
        # update privacy level
        privacy_level = int(request.json["privacyLevel"])
        if privacy_level not in (0, 1, 2):
            logger.warn("Received malformed set preference request. privacyLevel value not valid.")
            return return_err(E_INVALID_PRIVACY_LEVEL)

        PrivacySettings.set_level(request.headers["STUDENT_ID"], privacy_level)
        return jsonify({"success": True, "message": "Set privacy level success"})
    else:
        return return_err(E_INVALID_REQUEST)


@user_bp.route('/resetCalendarToken')
@login_required
def reset_calendar_token():
    """重置日历订阅令牌"""
    CalendarToken.reset_tokens(request.headers["STUDENT_ID"])
    return jsonify({"success": True,
                    "message": "Calendar token reset success"})


@user_bp.route('/visitors')
@login_required
def visitors():
    """我的访客列表"""
    visitor_list = VisitTrack.get_visitors(request.headers["STUDENT_ID"])
    visitor_count = Redis.get_visitor_count(request.headers["STUDENT_ID"])
    return jsonify({"success" : True,
                    "count"   : visitor_count,  # 实名+匿名
                    "visitors": visitor_list})  # 实名列表
