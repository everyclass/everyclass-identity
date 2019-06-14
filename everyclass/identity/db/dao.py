"""

在 PostgreSQL 中以超级用户权限使用下列语句建库：
CREATE ROLE everyclass_admin WITH NOLOGIN;
CREATE DATABASE everyclass WITH OWNER = everyclass_admin;
CREATE USER everyclass_identity WITH LOGIN;
CREATE SCHEMA everyclass_identity AUTHORIZATION everyclass_identity;
CREATE EXTENSION hstore SCHEMA public;

说明：
- 与无模式的数据库不同，在 PostgreSQL 中，所有每课的服务只需要使用一个数据库，而不同的微服务之间使用模式(schema) 来区分
- 这样做充分使用了 PostgreSQL 的特性，并且在特定情况下可以使用一条连接访问其他微服务的表，尽管一个微服务直接访问另一个微服务的数据库增加
  了耦合性，并不被提倡（PostgreSQL 单条连接不能跨库，MySQL 允许多库实质上是因为 MySQL 没有模式的妥协方案）
- hstore 是 PostgreSQL 中的 KV 存储插件，开启后我们可以在一个字段中存储 KV 键值对。使用 PostgreSQL 作为数据库的知名论坛系统
  Discourse 也有使用到此扩展。虽然 crate extension 语句看起来像是“创建扩展”，但实际上是在本模式下“启用扩展”
"""
import abc
import datetime
import uuid
from typing import Dict, List, Optional, Union, overload

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from everyclass.identity.config import get_config
from everyclass.identity.db.postgres import pg_conn_context
from everyclass.identity.db.redis import redis


class PostgresBase(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def init(cls) -> None:
        """建立表和索引"""
        pass


class PrivacySettings(PostgresBase):
    """隐私级别"""

    @classmethod
    def get_level(cls, student_id: str) -> int:
        with pg_conn_context() as conn, conn.cursor() as cursor:
            select_query = "SELECT level FROM privacy_settings WHERE student_id=%s"
            cursor.execute(select_query, (student_id,))
            result = cursor.fetchone()
        return result[0] if result is not None else get_config().DEFAULT_PRIVACY_LEVEL

    @classmethod
    def set_level(cls, student_id: str, new_level: int) -> None:
        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_query = """
            INSERT INTO privacy_settings (student_id, level, create_time) VALUES (%s,%s,%s)
                ON CONFLICT (student_id) DO UPDATE SET level=EXCLUDED.level
            """
            cursor.execute(insert_query, (student_id, new_level, datetime.datetime.now()))
            conn.commit()

    @classmethod
    def init(cls) -> None:
        with pg_conn_context() as conn, conn.cursor() as cursor:
            create_table_query = """
            CREATE TABLE IF NOT EXISTS privacy_settings
                (
                    student_id character varying(15) NOT NULL PRIMARY KEY,
                    level smallint NOT NULL,
                    create_time  timestamp with time zone NOT NULL
                )
                WITH (
                    OIDS = FALSE
                );
            """
            cursor.execute(create_table_query)

            conn.commit()


class CalendarToken(PostgresBase):
    """日历订阅令牌
    """

    @classmethod
    def insert_calendar_token(cls, resource_type: str, semester: str, identifier: str) -> str:
        """
        生成日历令牌，写入数据库并返回字符串类型的令牌。此时的 last_used_time 是 NULL。

        :param resource_type: student/teacher
        :param semester: 学期字符串
        :param identifier: 学号或教工号
        :return: token 字符串
        """
        token = uuid.uuid4()

        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_query = """
            INSERT INTO calendar_tokens (type, identifier, semester, token, create_time)
                VALUES (%s,%s,%s,%s,%s);
            """
            cursor.execute(insert_query, (resource_type, identifier, semester, token, datetime.datetime.now()))
            conn.commit()
        return str(token)

    @classmethod
    def _parse(cls, result):
        return {"type"      : result[0],
                "identifier": result[1],
                "semester"  : result[2],
                "token"     : result[3]}

    @overload  # noqa: F811
    @classmethod
    def find_calendar_token(cls, token: str) -> Union[Dict, None]:
        ...

    @overload  # noqa: F811
    @classmethod
    def find_calendar_token(cls, tid: str, semester: str) -> Union[Dict, None]:
        ...

    @overload  # noqa: F811
    @classmethod
    def find_calendar_token(cls, sid: str, semester: str) -> Union[Dict, None]:
        ...

    @classmethod  # noqa: F811
    def find_calendar_token(cls, tid=None, sid=None, semester=None, token=None):
        """通过 token 或者 sid/tid + 学期获得 token 文档"""
        with pg_conn_context() as conn, conn.cursor() as cursor:
            if token:
                select_query = """
                SELECT type, identifier, semester, token, create_time, last_used_time FROM calendar_tokens
                    WHERE token=%s
                """
                cursor.execute(select_query, (uuid.UUID(token),))
                result = cursor.fetchall()
                return cls._parse(result[0]) if result else None
            elif (tid or sid) and semester:
                select_query = """
                SELECT type, identifier, semester, token, create_time, last_used_time FROM calendar_tokens
                    WHERE type=%s AND identifier=%s AND semester=%s;
                """
                cursor.execute(select_query, ("teacher" if tid else "student", tid, semester))
                result = cursor.fetchall()
                return cls._parse(result[0]) if result else None
            else:
                raise ValueError("tid/sid together with semester or token must be given to search a token document")

    @classmethod
    def get_or_set_calendar_token(cls, resource_type: str, identifier: str, semester: str) -> str:
        """寻找 token，如果找到了则直接返回 token。找不到则生成一个再返回 token"""
        if resource_type == "student":
            token_doc = cls.find_calendar_token(sid=identifier, semester=semester)
        else:
            token_doc = cls.find_calendar_token(tid=identifier, semester=semester)

        if not token_doc:
            if resource_type == "student":
                token = cls.insert_calendar_token(resource_type="student",
                                                  identifier=identifier,
                                                  semester=semester)
            else:
                token = cls.insert_calendar_token(resource_type="teacher",
                                                  identifier=identifier,
                                                  semester=semester)
        else:
            token = token_doc['token']
        return token

    @classmethod
    def update_last_used_time(cls, token: str):
        """更新token最后使用时间"""
        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_query = """
            UPDATE calendar_tokens SET last_used_time = %s WHERE token = %s;
            """
            cursor.execute(insert_query, (datetime.datetime.now(), uuid.UUID(token)))
            conn.commit()

    @classmethod
    def reset_tokens(cls, student_id: str, typ: Optional[str] = "student") -> None:
        """删除某用户所有的 token，默认为学生"""
        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_query = """
            DELETE FROM calendar_tokens WHERE identifier = %s AND type = %s;
            """
            cursor.execute(insert_query, (student_id, typ))
            conn.commit()

    @classmethod
    def init(cls) -> None:
        with pg_conn_context() as conn, conn.cursor() as cursor:
            create_type_query = """
            DO $$ BEGIN
                CREATE TYPE people_type AS enum('student', 'teacher');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            """
            cursor.execute(create_type_query)

            create_table_query = """
            CREATE TABLE IF NOT EXISTS calendar_tokens
                (
                    "type" people_type NOT NULL,
                    identifier character varying(15) NOT NULL,
                    semester character varying(15) NOT NULL,
                    token uuid NOT NULL,
                    create_time  timestamp with time zone NOT NULL,
                    last_used_time  timestamp with time zone
                )
                WITH (
                    OIDS = FALSE
                );
            """
            cursor.execute(create_table_query)

            create_index_query = """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_token
                ON calendar_tokens USING btree(token);
            """
            cursor.execute(create_index_query)

            create_index_query2 = """
            CREATE INDEX IF NOT EXISTS idx_type_idt_sem
                ON calendar_tokens USING btree("type", identifier, semester);
            """
            cursor.execute(create_index_query2)

            conn.commit()


class User(PostgresBase):
    """用户表
    """

    @classmethod
    def exist(cls, student_id: str) -> bool:
        """check if a student has registered"""
        with pg_conn_context() as conn, conn.cursor() as cursor:
            select_query = "SELECT create_time FROM users WHERE student_id=%s"
            cursor.execute(select_query, (student_id,))
            result = cursor.fetchone()
        return result is not None

    @classmethod
    def check_password(cls, sid_orig: str, password: str) -> bool:
        """verify a user's password. Return True if password is correct, otherwise return False."""
        with pg_conn_context() as conn, conn.cursor() as cursor:
            select_query = "SELECT password FROM users WHERE student_id=%s"
            cursor.execute(select_query, (sid_orig,))
            result = cursor.fetchone()
        if result is None:
            raise ValueError("Student not registered")
        return check_password_hash(result[0], password)

    @classmethod
    def add_user(cls, sid_orig: str, password: str, password_encrypted: bool = False) -> None:
        """add a user

        :param sid_orig: 学号
        :param password: 密码
        :param password_encrypted: 密码是否已经被加密过了（否则会被二次加密）
        """
        import psycopg2.errors

        if not password_encrypted:
            password_hash = generate_password_hash(password)
        else:
            password_hash = password

        with pg_conn_context() as conn, conn.cursor() as cursor:
            select_query = "INSERT INTO users (student_id, password, create_time) VALUES (%s,%s,%s)"
            try:
                cursor.execute(select_query, (sid_orig, password_hash, datetime.datetime.now()))
                conn.commit()
            except psycopg2.errors.UniqueViolation as e:
                raise ValueError("Student already exists in database") from e

    @classmethod
    def init(cls) -> None:

        with pg_conn_context() as conn, conn.cursor() as cursor:
            create_table_query = """
            CREATE TABLE IF NOT EXISTS users
                (
                    student_id character varying(15) NOT NULL PRIMARY KEY,
                    password character varying(120) NOT NULL,
                    create_time  timestamp with time zone NOT NULL
                )
                WITH (
                    OIDS = FALSE
                );
            """
            cursor.execute(create_table_query)

            conn.commit()


ID_STATUS_TKN_PASSED = "EMAIL_TOKEN_PASSED"  # email verification passed but password may not set
ID_STATUS_SENT = "EMAIL_SENT"  # email request sent to everyclass-auth(cannot make sure the email is really sent)
ID_STATUS_PASSWORD_SET = "PASSWORD_SET"
ID_STATUS_WAIT_VERIFY = "VERIFY_WAIT"  # wait everyclass-auth to verify
ID_STATUS_PWD_SUCCESS = "PASSWORD_PASSED"
ID_STATUSES = (ID_STATUS_TKN_PASSED,
               ID_STATUS_SENT,
               ID_STATUS_PASSWORD_SET,
               ID_STATUS_WAIT_VERIFY,
               ID_STATUS_PWD_SUCCESS)


class IdentityVerification(PostgresBase):
    """
    身份验证请求
    """

    @classmethod
    def get_request_by_id(cls, req_id: str) -> Optional[Dict]:
        """由 request_id 获得请求，如果找不到则返回 None"""

        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_query = """
            SELECT request_id, identifier, method, status, extra
                FROM identity_verify_requests WHERE request_id = %s;
            """
            cursor.execute(insert_query, (uuid.UUID(req_id),))
            result = cursor.fetchone()

        if not result:
            return None

        doc = {"request_id"         : result[0],
               "sid_orig"           : result[1],
               "verification_method": result[2],
               "status"             : result[3]}
        if result[4]:
            if "password" in result[4]:
                doc["password"] = result[4]["password"]
        return doc

    @classmethod
    def new_register_request(cls, sid_orig: str, verification_method: str, status: str,
                             password: str = None) -> str:
        """
        新增一条注册请求

        :param sid_orig: original sid
        :param verification_method: password or email
        :param status: status of the request
        :param password: if register by password, fill everyclass password here
        :return: the `request_id`
        """
        if verification_method not in ("email", "password"):
            raise ValueError("verification_method must be one of email, password")

        request_id = uuid.uuid4()

        with pg_conn_context() as conn, conn.cursor() as cursor:
            extra_doc = {}
            if password:
                extra_doc.update({"password": generate_password_hash(password)})

            insert_query = """
            INSERT INTO identity_verify_requests (request_id, identifier, method, status, create_time, extra)
                VALUES (%s,%s,%s,%s,%s,%s)
            """
            cursor.execute(insert_query, (request_id,
                                          sid_orig,
                                          verification_method,
                                          status,
                                          datetime.datetime.now(),
                                          extra_doc))
            conn.commit()

        return str(request_id)

    @classmethod
    def set_request_status(cls, request_id: str, status: str) -> None:
        """mark a verification request's status as email token passed"""

        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_query = """
            UPDATE identity_verify_requests SET status = %s WHERE request_id = %s;
            """
            cursor.execute(insert_query, (status, uuid.UUID(request_id)))
            conn.commit()

    @classmethod
    def init(cls) -> None:

        with pg_conn_context() as conn, conn.cursor() as cursor:
            create_verify_methods_type_query = """
            DO $$ BEGIN
                CREATE TYPE identity_verify_methods AS enum('password', 'email');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            """
            cursor.execute(create_verify_methods_type_query)

            create_status_type_query = f"""
            DO $$ BEGIN
                CREATE TYPE identity_verify_statuses AS enum({','.join(["'" + x + "'" for x in ID_STATUSES])});
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            """
            cursor.execute(create_status_type_query)

            create_table_query = """
            CREATE TABLE IF NOT EXISTS identity_verify_requests
                (
                    request_id uuid PRIMARY KEY,
                    identifier character varying(15) NOT NULL,
                    method identity_verify_methods NOT NULL,
                    status identity_verify_statuses NOT NULL,
                    create_time  timestamp with time zone NOT NULL,
                    extra hstore
                )
                WITH (
                    OIDS = FALSE
                );
            """
            cursor.execute(create_table_query)

            conn.commit()


class SimplePassword(PostgresBase):
    """
    Simple passwords will be rejected when registering. However, it's fun to know what kind of simple passwords are
    being used.
    """

    @classmethod
    def new(cls, password: str, sid_orig: str) -> None:
        """新增一条简单密码记录"""

        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_query = "INSERT INTO simple_passwords (student_id, time, password) VALUES (%s,%s,%s)"
            cursor.execute(insert_query, (sid_orig, datetime.datetime.now(), password))
            conn.commit()

    @classmethod
    def init(cls) -> None:
        with pg_conn_context() as conn, conn.cursor() as cursor:
            create_table_query = """
            CREATE TABLE IF NOT EXISTS simple_passwords
                (
                    student_id character varying(15) NOT NULL,
                    "time" timestamp with time zone NOT NULL,
                    password text NOT NULL
                )
                WITH (
                    OIDS = FALSE
                );
            """
            cursor.execute(create_table_query)

            create_index_query = """
            CREATE INDEX IF NOT EXISTS idx_time
                ON simple_passwords USING btree("time" DESC);
            """
            cursor.execute(create_index_query)
            conn.commit()


class VisitTrack(PostgresBase):
    """
    访客记录

    目前只考虑了学生互访的情况，如果将来老师支持注册，这里需要改动
    """

    @classmethod
    def update_track(cls, host: str, visitor: str) -> None:
        with pg_conn_context() as conn, conn.cursor() as cursor:
            insert_or_update_query = """
            INSERT INTO visit_tracks (host_id, visitor_id, last_visit_time) VALUES (%s,%s,%s)
                ON CONFLICT ON CONSTRAINT unq_host_visitor DO UPDATE SET last_visit_time=EXCLUDED.last_visit_time;
            """
            cursor.execute(insert_or_update_query, (host, visitor, datetime.datetime.now()))
            conn.commit()

    @classmethod
    def get_visitors(cls, sid_orig: str) -> List[Dict]:
        """获得访客列表"""
        from everyclass.rpc.api_server import APIServer

        with pg_conn_context() as conn, conn.cursor() as cursor:
            select_query = """
            SELECT visitor_id, last_visit_time FROM visit_tracks where host_id=%s ORDER BY last_visit_time DESC;
            """
            cursor.execute(select_query, (sid_orig,))
            result = cursor.fetchall()
            conn.commit()

        visitor_list = []
        for record in result:
            # query api-identity
            search_result = APIServer.search(record[0])

            visitor_list.append({"name"         : search_result.students[0].name,
                                 "student_id"   : search_result.students[0].student_id_encoded,
                                 "last_semester": search_result.students[0].semesters[-1],
                                 "visit_time"   : record[1]})
        return visitor_list

    @classmethod
    def init(cls) -> None:
        with pg_conn_context() as conn, conn.cursor() as cursor:
            create_table_query = """
            CREATE TABLE IF NOT EXISTS visit_tracks
                (
                    host_id character varying(15) NOT NULL,
                    visitor_id character varying(15) NOT NULL,
                    last_visit_time timestamp with time zone NOT NULL
                )
                WITH (
                    OIDS = FALSE
                );
            """
            cursor.execute(create_table_query)

            create_index_query = """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_host_time
                ON visit_tracks USING btree("host_id", "last_visit_time" DESC);
            """
            cursor.execute(create_index_query)

            create_constraint_query = """
            ALTER TABLE visit_tracks ADD CONSTRAINT unq_host_visitor UNIQUE ("host_id", "visitor_id");
            """
            cursor.execute(create_constraint_query)
            conn.commit()


class Redis:
    prefix = "ec_sv"

    @classmethod
    def add_visitor_count(cls, sid_orig: str, visitor: str) -> None:
        """增加用户的总访问人数"""
        if not visitor:  # 未登录用户使用分配的user_id代替学号标识
            visitor_sid_orig = "anm" + str(session["user_id"])
        else:
            if sid_orig != visitor:  # 排除自己的访问量
                return
            visitor_sid_orig = visitor
        redis.pfadd("{}:visit_cnt:{}".format(cls.prefix, sid_orig), visitor_sid_orig)

    @classmethod
    def get_visitor_count(cls, sid_orig: str) -> int:
        """获得总访问人数计数"""
        return redis.pfcount("{}:visit_cnt:{}".format(cls.prefix, sid_orig))


def init_postgres(migrate=False):
    import inspect
    import sys

    for cls_name, cls in inspect.getmembers(sys.modules[__name__], inspect.isclass):
        if issubclass(cls, PostgresBase) and cls is not PostgresBase:
            print("[{}] Initializing...".format(cls_name))
            cls.init()
        if migrate and hasattr(cls, "migrate"):
            print("[{}] Migrating...".format(cls_name))
            cls.migrate()


def init_db():
    """初始化数据库"""
    init_postgres()
