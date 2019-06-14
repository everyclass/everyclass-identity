import git


class LazyRefType:
    """
    The great lazy reference type.

    Sometimes you want a field to reference another field (i.e., `FIELD1 = FIELD2`). However, if you do this in
    base class and the referenced field is overwritten in subclass, the FIELD1 will still be associated with the
    base class. This is not what we want.

    For example, you have a field called `MONGODB_DB` which defines the database name you use in your business
    logic. However, the Flask-session extension requires a field called `SESSION_MONGODB_DB` which defines the
    database name that stores the session. Both of them need to be defined in base `Config` class. So you
    define:

    MONGODB_DB = "everyclass-db"
    SESSION_MONGODB_DB = MONGODB_DB

    Things go pretty well until you change `MONGODB_DB` in ProductionConfig. The `SESSION_MONGODB_DB` will still
    be "everyclass-db". So the "reference" is not really a reference now.

    If you do `SESSION_MONGODB_DB = LazyRefType("MONGODB_DB")` and call `LazyRefType.link(MixedConfig)` at last,
    the reference will be correctly linked.
    """

    def __init__(self, var_name):
        self.var_name = var_name

    @classmethod
    def link(cls, final_config):
        for key in dir(final_config):
            value = getattr(final_config, key)
            if isinstance(value, cls):
                setattr(final_config, key, getattr(final_config, value.var_name))


class Config(object):
    """
    the base class for configuration. all keys must define here.
    """
    DEBUG = True
    SECRET_KEY = 'development_key'

    """
    Git Hash
    """
    _git_repo = git.Repo(search_parent_directories=True)
    GIT_HASH = _git_repo.head.object.hexsha
    try:
        GIT_BRANCH_NAME = _git_repo.active_branch.name
    except TypeError:
        GIT_BRANCH_NAME = 'detached'
    _describe_raw = _git_repo.git.describe(tags=True).split("-")  # like `v0.8.0-1-g000000`
    GIT_DESCRIBE = _describe_raw[0]  # actual tag name like `v0.8.0`
    if len(_describe_raw) > 1:
        GIT_DESCRIBE += "." + _describe_raw[1]  # tag 之后的 commit 计数，代表小版本
        # 最终结果类似于：v0.8.0.1

    """
    Connection settings
    """
    # database
    REDIS = {
        'host': '127.0.0.1',
        'port': 6379,
        'db'  : 1
    }
    POSTGRES_CONNECTION = {
        'dbname'  : 'everyclass',
        'user'    : 'everyclass_server',
        'password': '',
        'host'    : 'localhost',
        'port'    : 5432
    }
    POSTGRES_SCHEMA = 'everyclass_server'

    # Sentry, APM and logstash
    SENTRY_CONFIG = {
        'dsn'    : '',
        'release': '',
        'tags'   : {'environment': 'default'}
    }
    ELASTIC_APM = {
        'SERVICE_NAME'                : 'everyclass-identity',
        'SECRET_TOKEN'                : 'token',
        'SERVER_URL'                  : 'http://127.0.0.1:8200',
        # https://www.elastic.co/guide/en/apm/agent/python/2.x/configuration.html#config-auto-log-stacks
        'AUTO_LOG_STACKS'             : False,
        'SERVICE_VERSION'             : GIT_DESCRIBE,
        'TRANSACTIONS_IGNORE_PATTERNS': ['GET /_healthCheck']
    }
    LOGSTASH = {
        'HOST': '127.0.0.1',
        'PORT': 8888
    }

    # other micro-services
    API_SERVER_BASE_URL = 'http://everyclass-api-server'
    API_SERVER_TOKEN = ''
    AUTH_BASE_URL = 'http://everyclass-auth'

    DEFAULT_PRIVACY_LEVEL = 0

    # define available environments for logs, APM and error tracking
    SENTRY_AVAILABLE_IN = ('production', 'staging', 'testing', 'development')
    APM_AVAILABLE_IN = ('production', 'staging', 'testing',)
    LOGSTASH_AVAILABLE_IN = ('production', 'staging', 'testing',)
    DEBUG_LOG_AVAILABLE_IN = ('development', 'testing', 'staging')

    # fields that should be overwritten in production environment
    PRODUCTION_OVERWRITE_FIELDS = ('SECRET_KEY',
                                   'TENCENT_CAPTCHA_AID',
                                   'TENCENT_CAPTCHA_SECRET'
                                   )

    # fields that should not be in log
    PRODUCTION_SECURE_FIELDS = ("SENTRY_CONFIG.dsn",
                                "REDIS.password",
                                "ELASTIC_APM.SECRET_TOKEN",
                                "MAINTENANCE_CREDENTIALS",
                                "SECRET_KEY",
                                "TENCENT_CAPTCHA_SECRET")
