#!/usr/bin/env python
# encoding: utf-8

from rq import get_current_job
import time
import urllib
import urllib2

scrapyd_uri = 'http://localhost:6800/schedule.json'

def add_job(username, domain, project):

    payload = {'project': project, 'username': username, 'spider': domain}
    req = urllib2.urlopen(scrapyd_uri, data=urllib.urlencode(payload))
    if req.getcode() != 200:
        raise Exception

    while True:
        job = get_current_job()
        print 'job waiting. jobid: %s, meta: %s' % (job.id, job.meta)
        if 'status' in job.meta:
            print 'meta found!'
            return
        time.sleep(5)
