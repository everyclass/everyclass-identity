from typing import Dict

import jwt

from everyclass.identity.config import get_config


def generate_token(payload: Dict):
    config = get_config()
    token = jwt.encode(payload, config.JWT_PRIVATE_KEY, algorithm='RS256')

    return token
