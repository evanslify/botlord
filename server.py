#!/usr/bin/env python
# encoding: utf-8

import json
import logging
from wsgiref import simple_server

import falcon

from rq import Queue
import control
import redis


class StorageEngine(object):

    def __init__(self):
        redis_pw = (
            '1955747fb39e1e6e7175dd6694f14db01280bf0ef4ce09617a7e590f0004998035712f13b3143e51f23c1cc9cea1977e560a3a1b2fd00f706d64e49a280c7ebb')
        redis_conn = redis.StrictRedis(password=redis_pw, db=1)
        self.q = Queue(connection=redis_conn)  # no args implies the default queue

    #  def get_things(self, marker, limit):
        #  return [{'id': str(uuid.uuid4()), 'color': 'green'}]

    #  def add_thing(self, thing):
    def add_job(self, username, domain, project):
        try:
            job = self.q.enqueue_call(
                func=control.add_job,
                args=(username, domain, project),
                timeout=600)
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


#  class SinkAdapter(object):

    #  engines = {
        #  'ddg': 'https://duckduckgo.com',
        #  'y': 'https://search.yahoo.com/search',
    #  }

    #  def __call__(self, req, resp, engine):
        #  url = self.engines[engine]
        #  params = {'q': req.get_param('q', True)}
        #  result = requests.get(url, params=params)

        #  resp.status = str(result.status_code) + ' ' + result.reason
        #  resp.content_type = result.headers['content-type']
        #  resp.body = result.text


#  class AuthMiddleware(object):

    #  def process_request(self, req, resp):
        #  # disabled
        #  token = req.get_header('X-Auth-Token', '1')
        #  project = req.get_header('X-Project-ID', '1')

        #  if token is None:
            #  description = ('Please provide an auth token '
                           #  'as part of the request.')

            #  raise falcon.HTTPUnauthorized('Auth token required',
                                          #  description,
                                          #  href='http://docs.example.com/auth')

        #  if not self._token_is_valid(token, project):
            #  description = ('The provided auth token is not valid. '
                           #  'Please request a new token and try again.')

            #  raise falcon.HTTPUnauthorized('Authentication required',
                                          #  description,
                                          #  href='http://docs.example.com/auth',
                                          #  scheme='Token; UUID')

    #  def _token_is_valid(self, token, project):
        #  return True  # Suuuuuure it's valid...


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
        # req.stream corresponds to the WSGI wsgi.input environ variable,
        # and allows you to read bytes from the request body.
        #
        # See also: PEP 3333
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
        #  marker = req.get_param('marker') or ''
        #  limit = req.get_param_as_int('limit') or 50

        #  username = req.get_param('username')
        #  domain = req.get_param('domain')
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
        #  status = jr['status']
        #  marker = req.get_param('marker') or ''
        #  limit = req.get_param_as_int('limit') or 50

        #  username = req.get_param('username')
        #  domain = req.get_param('domain')

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

# Proxy some things to another service; this example shows how you might
# send parts of an API off to a legacy system that hasn't been upgraded
# yet, or perhaps is a single cluster that all data centers have to share.
#  ink = SinkAdapter()
#  app.add_sink(sink, r'/search/(?P<engine>ddg|y)\Z')

# Useful for debugging problems in your API; works with pdb.set_trace()
if __name__ == '__main__':
    httpd = simple_server.make_server('0.0.0.0', 8000, app)
    httpd.serve_forever()
    print('server UP')
