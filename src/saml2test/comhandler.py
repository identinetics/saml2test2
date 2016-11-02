import logging

from aatest.comhandler import ComHandler as aatestComHandler
from saml2.httputil import Redirect as SamlRedirect
from saml2.httputil import Response as SamlResponse
import urllib.request

logger = logging.getLogger(__name__)

class FakeAnResponse(object):
    def __init__(self,saml_response):
        self.url = 'https://samlresponse.generated.by.local.test.driver'
        self.content = ''
        self.saml_response = saml_response

class FakeRedirectResponse(FakeAnResponse):

    def __init__(self,saml_response):
        super(FakeRedirectResponse,self).__init__(saml_response)

        if saml_response.status == '302 Found':
            redirect_url = saml_response.message
            self.status_code = 302
            self.headers = {'location': redirect_url}
        else:
            emsg = "SamlRedirect has an unknown status: {}".format(saml_response.status)
            raise RuntimeError(emsg)

class FakeResponseResponse(FakeAnResponse):
    def __init__(self,saml_response):
        super(FakeResponseResponse,self).__init__(saml_response)

        if saml_response.status == '200 OK':
            self.status_code = 200
        else:
            emsg = "SamlRedirect has an unknown status: {}".format(saml_response.status)
            raise RuntimeError(emsg)

class ComHandler(aatestComHandler):
    def __call__(self, response, target_url='', auto_close_urls=None,
                 conv=None, **kwargs):

        if (isinstance(response, SamlRedirect)):
            http_response = FakeRedirectResponse(response)
        elif (isinstance(response, SamlResponse)):
            http_response = FakeResponseResponse(response)
        else:
            emsg = "ComHandler can not handle object of class {}".format(response.__class__.__name__)
            raise RuntimeError(emsg)

        ret = super(ComHandler,self).__call__(http_response, target_url, auto_close_urls, conv, **kwargs)
        return ret
