import logging

from aatest.comhandler import ComHandler as aatestComHandler
from saml2.httputil import Redirect as SamlRedirect
import urllib.request

logger = logging.getLogger(__name__)

class FakeRedirectResponse(object):
    def __init__(self,saml_response):
        self.saml_response = saml_response
        if saml_response.status == '302 Found':
            redirect_url = saml_response.message
            self.status_code = 302
            self.url = 'https://samlresponse.generated.by.local.test.driver'
            self.content = ''
        else:
            raise RuntimeError("SamlRedirect has an unknown status")

        self.headers = {'location': redirect_url}



class ComHandler(aatestComHandler):
    def __call__(self, response, target_url='', auto_close_urls=None,
                 conv=None, **kwargs):

        if (isinstance(response, SamlRedirect)):
          http_response = FakeRedirectResponse(response)
        else:
            emsg = "ComHandler can not handle object of class {}".format(response.__class__.__name__)
            raise RuntimeError(emsg)

        ret = super(ComHandler,self).__call__(http_response, target_url, auto_close_urls, conv, **kwargs)
        return ret
