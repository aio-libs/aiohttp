import sys
import argparse

import trafaret as T
from trafaret_config import commandline


def load_config(fname):
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

    ap = argparse.ArgumentParser()
    commandline.standard_argparse_options(ap, default_config=fname)
    #
    # define your command-line arguments here
    #
    options = ap.parse_args()

    try:
        config = commandline.config_from_options(options, TRAFARET)
    except FileNotFoundError as e:
        print(type(e).__name__, e)
        sys.exit(1)

    return config

