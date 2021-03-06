#!/usr/bin/env python
# encoding: utf-8

from rq import get_current_job
import time
import urllib
import urllib2

scrapyd_uri = 'http://localhost:6800/schedule.json'


def add_job(username, domain, project):

    _job = get_current_job()

    payload = {'project': project, 'username': username, 'spider': domain, 'jobid': _job.id}
    req = urllib2.urlopen(scrapyd_uri, data=urllib.urlencode(payload))
    if req.getcode() != 200:
        raise Exception

    while True:
        job = get_current_job()
        print 'job waiting. jobid: %s, meta: %s' % (job.id, job.meta)
        if 'status' in job.meta:
            return
        time.sleep(5)
