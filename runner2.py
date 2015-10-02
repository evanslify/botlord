#!/usr/bin/env python
# encoding: utf-8

import redis
from rq import Worker, Queue, Connection

listen = ['default']

#  redis_url = os.getenv('REDISTOGO_URL', 'redis://localhost:6379')

#  conn = redis.from_url(redis_url)
pw = '1955747fb39e1e6e7175dd6694f14db01280bf0ef4ce09617a7e590f0004998035712f13b3143e51f23c1cc9cea1977e560a3a1b2fd00f706d64e49a280c7ebb'
conn = redis.StrictRedis(password=pw, db=1)

if __name__ == '__main__':
    with Connection(conn):
        worker = Worker(list(map(Queue, listen)))
        worker.work(burst=True)
