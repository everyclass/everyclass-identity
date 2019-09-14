import datetime
import logging

import gc
from flask import Flask, jsonify
from raven.contrib.flask import Sentry
from raven.handlers.logbook import SentryHandler

logger = logging.getLogger(__name__)
sentry = Sentry()
__app = None
__load_time = datetime.datetime.now()

try:
    import uwsgidecorators

    """
    使用 `uwsgidecorators.postfork` 装饰的函数会在 fork() 后的**每一个**子进程内被执行，执行顺序与这里的定义顺序一致
    """


    @uwsgidecorators.postfork
    def enable_gc():
        """重新启用垃圾回收"""
        gc.set_threshold(700)


    @uwsgidecorators.postfork
    def init_plugins():
        """初始化日志、错误追踪插件，并将当前配置信息打 log"""
        from everyclass.common.flask import print_config

        # Sentry
        if __app.config['CONFIG_NAME'] in __app.config['SENTRY_AVAILABLE_IN']:
            sentry.init_app(app=__app)
            sentry_handler = SentryHandler(sentry.client)
            sentry_handler.setLevel(logging.WARNING)
            logging.getLogger().addHandler(sentry_handler)

            logger.info('Sentry is inited because you are in {} mode.'.format(__app.config['CONFIG_NAME']))

        print_config(__app, logger)


    @uwsgidecorators.postfork
    def init_db():
        """初始化数据库连接"""
        from everyclass.identity.db.postgres import init_pool as init_pg
        init_pg(__app)


except ModuleNotFoundError:
    pass


def create_app() -> Flask:
    """创建 flask app"""
    from everyclass.identity.utils.logbook_logstash.formatter import LOG_FORMAT_STRING

    print("Creating app...")

    app = Flask(__name__)

    # load app config
    from everyclass.identity.config import get_config
    _config = get_config()
    app.config.from_object(_config)  # noqa: T484

    # 日志
    if app.config['DEBUG']:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    from everyclass.identity.views import user_bp
    app.register_blueprint(user_bp, url_prefix='/')

    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({"success" : False,
                        "err_code": 500,
                        "error"   : f"Internal server error: {repr(error)}"})

    global __app
    __app = app

    return app
