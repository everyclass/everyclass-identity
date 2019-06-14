import redis

from everyclass.identity.config import get_config

config = get_config()
redis = redis.Redis(**config.REDIS)
