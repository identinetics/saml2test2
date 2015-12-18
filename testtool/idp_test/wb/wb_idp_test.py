#!/usr/bin/env python3
import os
from wsgiref.simple_server import make_server

from werkzeug.debug import DebuggedApplication
from werkzeug.wsgi import SharedDataMiddleware

from saml2test.idp_test.wsgi import app as testtool

testtool.app.debug = True
testtool.app.secret_key = "abcdef"
testtool.app.wsgi_app = DebuggedApplication(
    SharedDataMiddleware(testtool.app.wsgi_app, {
        '/static': os.path.join(os.path.dirname(__file__), 'site/static')
    }))
# testtool.app.wsgi_app = SharedDataMiddleware(
#     testtool.app.wsgi_app, {
#         '/static': os.path.join(os.path.dirname(__file__), 'site/static')
#     })

print("Serving on port 8087...")
httpd = make_server('', 8087, testtool)
httpd.serve_forever()
