import sys

import trafaret as T
from trafaret_config import read_and_validate, ConfigError


def load_config(fname):
    config = load_and_validate(fname)
    return config


def load_and_validate(fname):
    primitive_ip_regexp = r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'

    TRAFARET = T.Dict({
        T.Key('postgres'):
            T.Dict({
                'database': T.String(),
                'user': T.String(),
                'password': T.String(),
                'host': T.String(),
                'port': T.Int(),
                'minsize': T.Int(),
                'maxsize': T.Int(),
            }),
        T.Key('host'): T.String(regex=primitive_ip_regexp),
        T.Key('port'): T.Int(),
    })

    try:
        config = read_and_validate(fname, TRAFARET)
    except ConfigError as e:
        e.output()
        sys.exit(1)
    except FileNotFoundError as e:
        print(type(e).__name__, e)
        sys.exit(1)

    return config
