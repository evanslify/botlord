#!/usr/bin/env python
# encoding: utf-8

import json
import logging
from wsgiref import simple_server

import falcon

from rq import Queue
import control
import redis
import subprocess
import shlex

from misc import loadconfig


class StorageEngine(object):

    def __init__(self):
        self.config = loadconfig()
        redis_pw = self.config.get('redis', 'redis_password')
        redis_port = self.config.get('redis', 'redis_port')
        redis_uri = self.config.get('redis', 'redis_uri')
        redis_db = self.config.get('redis', 'redis_db')

        redis_conn = redis.StrictRedis(
            host=redis_uri, port=redis_port, password=redis_pw, db=redis_db)

        self.q = Queue(connection=redis_conn)  # no args implies the default queue

    def add_job(self, username, domain, project):
        try:
            job = self.q.enqueue_call(
                func=control.add_job,
                args=(username, domain, project),
                timeout=600)
            # runner2 = worker.work(burst=True)
            # -> will destroy itself when job is done :)
            command = 'python ./runner2.py'
            subprocess.Popen(shlex.split(command))
            result = {'status': 'ok', 'jobid': job.id}
        except Exception:
            raise StorageError
        return result

    def job_finished(self, jobid):
        try:
            job = self.q.fetch_job(str(jobid))
            job.meta['status'] = 'done'
            job.save()
            result = {'status': 'ok', 'jobid': job.id}
        except Exception:
            raise StorageError
        return result


class StorageError(Exception):

    @staticmethod
    def handle(ex, req, resp, params):
        description = ('Sorry, couldn\'t write your thing to the '
                       'database. It worked on my box.')

        raise falcon.HTTPError(falcon.HTTP_725,
                               'Database Error',
                               description)


class RequireJSON(object):

    def process_request(self, req, resp):
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable(
                'This API only supports responses encoded as JSON.')

        if req.method in ('POST', 'PUT'):
            if 'application/json' not in req.content_type:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports requests encoded as JSON.')


class JSONTranslator(object):

    def process_request(self, req, resp):
        if req.content_length in (None, 0):
            # Nothing to do
            return

        body = req.stream.read()
        if not body:
            raise falcon.HTTPBadRequest('Empty request body',
                                        'A valid JSON document is required.')

        try:
            req.context['doc'] = json.loads(body.decode('utf-8'))

        except (ValueError, UnicodeDecodeError):
            raise falcon.HTTPError(falcon.HTTP_753,
                                   'Malformed JSON',
                                   'Could not decode the request body. The '
                                   'JSON was incorrect or not encoded as '
                                   'UTF-8.')

    def process_response(self, req, resp, resource):
        if 'result' not in req.context:
            return

        resp.body = json.dumps(req.context['result'])


def max_body(limit):

    def hook(req, resp, resource, params):
        length = req.content_length
        if length is not None and length > limit:
            msg = ('The size of the request is too large. The body must not '
                   'exceed ' + str(limit) + ' bytes in length.')

            raise falcon.HTTPRequestEntityTooLarge(
                'Request body is too large', msg)

    return hook


class ThingsResource(object):

    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger('thingsapp.' + __name__)

    def on_post(self, req, resp):
        jr = req.context['doc']
        username = jr['username']
        domain = jr['domain']
        project = jr.get('project', 'fetch')

        try:
            result = self.db.add_job(username, domain, project)
        except Exception as ex:
            self.logger.error(ex)

            description = ('Aliens have attacked our base! We will '
                           'be back as soon as we fight them off. '
                           'We appreciate your patience.')

            raise falcon.HTTPServiceUnavailable(
                'Service Outage',
                description,
                30)

        # An alternative way of doing DRY serialization would be to
        # create a custom class that inherits from falcon.Request. This
        # class could, for example, have an additional 'doc' property
        # that would serialize to JSON under the covers.
        req.context['result'] = result

        resp.set_header('X-Powered-By', 'Small Furry Creatures')
        resp.status = falcon.HTTP_200


class FinishedJobResource(object):

    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger('thingsapp.' + __name__)

    @falcon.before(max_body(64 * 1024))
    def on_post(self, req, resp):
        jr = req.context['doc']

        jobid = jr['jobid']

        try:
            result = self.db.job_finished(jobid)
        except Exception as ex:
            self.logger.error(ex)

            description = ('Aliens have attacked our base! We will '
                           'be back as soon as we fight them off. '
                           'We appreciate your patience.')

            raise falcon.HTTPServiceUnavailable(
                'Service Outage',
                description,
                30)

        # An alternative way of doing DRY serialization would be to
        # create a custom class that inherits from falcon.Request. This
        # class could, for example, have an additional 'doc' property
        # that would serialize to JSON under the covers.
        req.context['result'] = result

        resp.set_header('X-Powered-By', 'Small Furry Creatures')
        resp.status = falcon.HTTP_200


# Configure your WSGI server to load "things.app" (app is a WSGI callable)
app = falcon.API(middleware=[
    #  AuthMiddleware(),
    RequireJSON(),
    JSONTranslator(),
])

db = StorageEngine()
things = ThingsResource(db)
finished = FinishedJobResource(db)

app.add_route('/lord/finished', finished)
app.add_route('/lord/add', things)

# If a responder ever raised an instance of StorageError, pass control to
# the given handler.
app.add_error_handler(StorageError, StorageError.handle)


# Useful for debugging problems in your API; works with pdb.set_trace()
if __name__ == '__main__':
    httpd = simple_server.make_server('0.0.0.0', 8000, app)
    httpd.serve_forever()
    print('server UP')
