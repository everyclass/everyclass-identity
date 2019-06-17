from flask import request


def check_payloads(*fields):
    """检查请求是否包含需要的字段

    @:param json: request 对象
    @:param fields: 字段列表，每一项为一个元组（a, b）。其中 a 为名字，b 为不满足时的返回值
    """
    passed = True
    ret_msg = None
    ret_vals = []
    for field in fields:
        if field[0] not in request.json:
            passed = False
            ret_msg = field[1]
            ret_vals.append(None)
        else:
            ret_vals.append(request.json.get(field[0]))

    ret = passed, ret_msg, *ret_vals
    return ret
