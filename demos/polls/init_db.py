import subprocess

import sqlalchemy as sa
import yaml

from aiohttpdemo_polls.db import question, choice


config_path = 'config/polls.yaml'
with open(config_path) as f:
    data = yaml.load(f)

CONF = data['postgres']

DSN = '{drivername}://{username}:{password}@{host}:{port}/{database}'.format(
    drivername='postgresql',
    username=CONF['user'],
    password=CONF['password'],
    host=CONF['host'],
    port=CONF['port'],
    database=CONF['database'],
)


def recreate_database():
    print('-- Recreate database and roles --')
    subprocess.run(["bash", "sql/recreate_database.sh"])


def create_tables():
    print('-- Create tables --')
    meta = sa.MetaData()
    engine = sa.create_engine(DSN)
    meta.create_all(
        bind=engine,
        tables=[question, choice]
    )


def populate_tables():
    print('-- Populate tables --')
    subprocess.run(["bash", "sql/populate_database.sh"])


if __name__ == '__main__':
    recreate_database()
    create_tables()
    populate_tables()


