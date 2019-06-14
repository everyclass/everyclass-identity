import datetime
import sys

import gc
import logbook
from flask import Flask, jsonify
from raven.contrib.flask import Sentry
from raven.handlers.logbook import SentryHandler

logger = logbook.Logger(__name__)
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
    def init_log_handlers():
        """初始化 log handlers 并将当前配置信息打 log"""
        from everyclass.identity.utils.logbook_logstash.handler import LogstashHandler
        from elasticapm.contrib.flask import ElasticAPM
        from everyclass.identity.config import print_config
        from everyclass.rpc import init as init_rpc

        # Elastic APM
        if __app.config['CONFIG_NAME'] in __app.config['APM_AVAILABLE_IN']:
            ElasticAPM(__app)
            print('APM is inited because you are in {} mode.'.format(__app.config['CONFIG_NAME']))

        # Logstash centralized log
        if __app.config['CONFIG_NAME'] in __app.config['LOGSTASH_AVAILABLE_IN']:
            logstash_handler = LogstashHandler(host=__app.config['LOGSTASH']['HOST'],
                                               port=__app.config['LOGSTASH']['PORT'],
                                               release=__app.config['GIT_DESCRIBE'],
                                               bubble=True,
                                               logger=logger,
                                               filter=lambda r, h: r.level >= 11)  # do not send DEBUG
            logger.handlers.append(logstash_handler)
            print('LogstashHandler is inited because you are in {} mode.'.format(__app.config['CONFIG_NAME']))

        # Sentry
        if __app.config['CONFIG_NAME'] in __app.config['SENTRY_AVAILABLE_IN']:
            sentry.init_app(app=__app)
            sentry_handler = SentryHandler(sentry.client, level='INFO')  # Sentry 只处理 INFO 以上的
            logger.handlers.append(sentry_handler)
            init_rpc(sentry=sentry)
            print('Sentry is inited because you are in {} mode.'.format(__app.config['CONFIG_NAME']))

        init_rpc(logger=logger)

        # 如果当前时间与模块加载时间相差一分钟之内，认为是第一次 spawn（进程随着时间的推移可能会被 uwsgi 回收），
        # 在 1 号 worker 里打印当前配置
        import uwsgi
        if uwsgi.worker_id() == 1 and (datetime.datetime.now() - __load_time) < datetime.timedelta(minutes=1):
            # 这里设置等级为 warning 因为我们希望在 sentry 里监控重启情况
            logger.warning('App (re)started in `{0}` environment'
                           .format(__app.config['CONFIG_NAME']), stack=False)
            print_config(__app)


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

    """
    每课统一日志机制


    规则如下：
    - WARNING 以下 log 输出到 stdout
    - WARNING 以上输出到 stderr
    - DEBUG 以上日志以 json 形式通过 TCP 输出到 Logstash，然后发送到日志中心
    - WARNING 以上级别的输出到 Sentry


    日志等级：
    critical – for errors that lead to termination
    error – for errors that occur, but are handled
    warning – for exceptional circumstances that might not be errors
    notice – for non-error messages you usually want to see
    info – for messages you usually don’t want to see
    debug – for debug messages


    Sentry：
    https://docs.sentry.io/clients/python/api/#raven.Client.captureMessage
    - stack 默认是 False
    """
    if app.config['CONFIG_NAME'] in app.config['DEBUG_LOG_AVAILABLE_IN']:
        stdout_handler = logbook.StreamHandler(stream=sys.stdout, bubble=True, filter=lambda r, h: r.level < 13)
    else:
        # ignore debug when not in debug
        stdout_handler = logbook.StreamHandler(stream=sys.stdout, bubble=True, filter=lambda r, h: 10 < r.level < 13)
    stdout_handler.format_string = LOG_FORMAT_STRING
    logger.handlers.append(stdout_handler)

    stderr_handler = logbook.StreamHandler(stream=sys.stderr, bubble=True, level='WARNING')
    stderr_handler.format_string = LOG_FORMAT_STRING
    logger.handlers.append(stderr_handler)

    from everyclass.identity.views import user_bp
    app.register_blueprint(user_bp, url_prefix='/')

    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({"success": False,
                        "error"  : repr(error)})

    global __app
    __app = app

    return app
