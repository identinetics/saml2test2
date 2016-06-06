#from future.standard_library import install_aliases

from PyQt4.QtNetwork import QNetworkRequest, QNetworkAccessManager, QNetworkCookie, QNetworkCookieJar, QNetworkReply
from PyQt4.QtCore import QUrl

try:
    # Python2
    import StringIO
    from PyQt4.QtCore import QString
    from urllib import addinfourl
except ImportError:
    # Python3
    QString = type("")
    from io import StringIO
    from io import BytesIO, SEEK_END
    from urllib.response import addinfourl
    from requests import Response, utils as requests_utils, Request
    from http.client import HTTPResponse as Httplib_HTTPResponse
    from urllib3 import HTTPResponse as Urllib3_HTTPresponse
    from urllib3._collections import HTTPHeaderDict as Urllib3_HTTPHeaderDict


from PyQt4.QtCore import   QTextStream,  QVariant, QTimer, SIGNAL, QByteArray
from PyQt4 import QtCore

from .mockhttprequest import MockSock
from .ebnetwork import EbNetworkRequest, EbNetworkReply

from http.cookiejar import CookieJar
#import mimetools

#install_aliases()

from urllib.request import Request as UrllibRequest
from urllib.response import addinfourl
import email

#from fwclasses import MyHandlerResponse

import pprint
"""
    The pyqt bindings don't care much about our classes, so we have to
    use some trickery to get around that limitations. And there are some
    nasty bugs too:

    InjectedQNetworkRequest adds a magic parameter to the URl, which is
    then used to detect that the QNetworkRequest we get, should have been
    the injected one.

    Having InjectedQNetworkRequest knowing its response (cookies) would
    be the logical way, but because that info is getting lost, we have to
    take care about that in InjectedQNetworkAccessManager. Sucks.

    There is a bug in the binding (no QList) that prevents us from having
    cookie handling in the QNetworkReply, so it's also done on the wrong
    place.

    Most of that will be fixed in the future of PyQt.

    Things named with Qt4 are known to break in Qt5.
"""

"""
    InjectedQNetworkRequest is the request that will NOT be sent to the
    network, but written into the embedded browser. It is initialized by
    an already existing response holding the request
"""
class InjectedQNetworkRequest(QNetworkRequest):
    magic_query_key = QString('magic_injected')
    magic_query_val = QString('4711')

    def __init__(self, start_http_response):
        original_request_url = start_http_response.request.url
        new_url =self.putMagicIntoThatUrlQt4(QUrl(original_request_url))
        super(InjectedQNetworkRequest, self).__init__(new_url)
        return

    def putMagicIntoThatUrlQt4(self,url):
        new_url = url
        new_url.setQueryItems([(self.magic_query_key,self.magic_query_val)])
        return new_url

    @classmethod
    def thatRequestHasMagicQt4(self,eb_request):
        url = eb_request.request.url()
        value = url.queryItemValue(self.magic_query_key)
        if value == self.magic_query_val:
            return True
        return False

"""
    The InjectedNetworkReply will be given to the browser.
"""
class InjectedNetworkReply(QNetworkReply):
    def __init__(self, parent, url, http_response, operation):
        QNetworkReply.__init__(self, parent)
        self.content = http_response.content
        self.offset = 0

        self.http_response = http_response
        self.http_request = http_response.request

        self.setHeader(QNetworkRequest.ContentTypeHeader, "text/html")
        self.setHeader(QNetworkRequest.ContentLengthHeader, len(self.content))

        QTimer.singleShot(0, self, SIGNAL("readyRead()"))
        QTimer.singleShot(0, self, SIGNAL("finished()"))
        self.open(self.ReadOnly | self.Unbuffered)
        self.setUrl(QUrl(url))

    def abort(self):
        pass

    def bytesAvailable(self):
        # NOTE:
        # This works for Win:
        #	  return len(self.content) - self.offset
        # but it does not work under OS X.
        # Solution which works for OS X and Win:
        #	 return len(self.content) - self.offset + QNetworkReply.bytesAvailable(self)
        return len(self.content) - self.offset + QNetworkReply.bytesAvailable(self)

    def isSequential(self):
        return True

    def readData(self, maxSize):
        if self.offset < len(self.content):
            number = min(maxSize, len(self.content) - self.offset)
            data = self.content[self.offset:self.offset + number]
            self.offset += number
            return data
        return None


"""
    The SniffingNetworkReply stores the content.
    TODO: As this is using up twice the mem for the response: make this just store the
    interesting stuff, up to a configurable amount, and just passing thru the rest.
"""

class SniffingNetworkReply(QNetworkReply):
    def __init__(self, parent, request, reply, operation):
        #self.sniffed_data = ""
        #self.sniffed_data = QByteArray()

        QNetworkReply.__init__(self, parent)
        self.open(self.ReadOnly | self.Unbuffered)
        url = request.url()
        self.setUrl(QUrl(url))
        self.setRequest(request)
        self.offset = 0

        reply.finished.connect(self.onReplyFinished)

    def abort(self):
        pass

    def bytesAvailable(self):
        if not self.sniffed_data:
            return 0
        c_bytes = len(self.sniffed_data) - self.offset + QNetworkReply.bytesAvailable(self)
        return c_bytes

    def isSequential(self):
        return True

    def readData(self, maxSize):
        if not self.sniffed_data:
            return QByteArray("")
        if self.offset < len(self.sniffed_data):
            end = min(self.offset + maxSize, len(self.sniffed_data))
            data = self.sniffed_data[self.offset:end]
            self.offset = end
            return data

    def onReplyFinished(self):
        self.reply = self.sender()


        raw_header_pairs = self.reply.rawHeaderPairs()
        for header in raw_header_pairs:
            self.setRawHeader(header[0],header[1])

        http_status = self.reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        self.setAttribute(QNetworkRequest.HttpStatusCodeAttribute, http_status)

        bytes_available = self.reply.bytesAvailable()
        # TODO: Make sniffed_data an object
        self.sniffed_data = self.reply.read(bytes_available + 512)

        self.readyRead.emit()
        self.finished.emit()

"""
    The InjectedQNetworkAccessManager will create a InjectedNetworkReply if
    the Request is an InjectedQNetworkRequest to prefill the browser with
    html data. It will be transparent to normal QNetworkRequests
"""
class InjectedQNetworkAccessManager(QNetworkAccessManager):
    autocloseOk = QtCore.pyqtSignal()
    autocloseFailed = QtCore.pyqtSignal()

    requestFinishing = QtCore.pyqtSignal()

    ## emitted on reload
    requestLocation = QtCore.pyqtSignal(QNetworkRequest)

    def __init__(self, parent = None, ignore_ssl_errors=False):
        super(InjectedQNetworkAccessManager, self).__init__(parent)
        self.ignore_ssl_errors = ignore_ssl_errors
        self.http_cookie_jar = None     # TODO: remove
        """
        self.resp_response holds the response, converted to {Request} when we finished processing
        # TODO: Can we signal that instead of storing it?
        """
        self.rsp_response = None
        self.initial_rsp_response = None

    def setInjectedResponse(self, rsp_response, http_cookie_jar):
        self.initial_rsp_response = rsp_response
        self.http_cookie_jar = http_cookie_jar

    def _qt_cookiejar_from_rsp_cookiejar(self, rsp_cookiejar, default_domain):
        cj = QNetworkCookieJar()
        cookie_attrs = requests_utils.dict_from_cookiejar(rsp_cookiejar)
        qt_cookies = self._parse_cookie_attribs_into_QtCookies_list(cookie_attrs, default_domain)
        cj.setAllCookies(qt_cookies)
        return cj

    def _set_my_cookies_from_reply(self,reply):
        cj = QNetworkCookieJar()
        cookie_list = reply.header(QNetworkRequest.SetCookieHeader)
        if cookie_list:
            cj.setAllCookies(cookie_list)

        self.setCookieJar(cj)

    def _parse_cookie_attribs_into_QtCookies_list(self, cookie_attrs, default_domain):
        #ugly, but works around bugs in parseCookies
        cookies = []

        for cookie_name in cookie_attrs:
            # parsing every attribute on its own because parser seems to be <censored>!
            #tmp_cookie_list = QNetworkCookie.parseCookies(cookie_attr)
            #if tmp_cookie_list:
            #    tmp_cookie = tmp_cookie_list[0]
            cookie_value = cookie_attrs[cookie_name]
            tmp_cookie = QNetworkCookie(QString(cookie_name),QString(cookie_value))
            if not tmp_cookie.domain():
                tmp_cookie.setDomain(QString(default_domain))
            cookies.append(tmp_cookie)



        return cookies

    def _network_reply_from_injected_http_response(self,op,eb_request):
        url = eb_request.request.url()
        r = InjectedNetworkReply(self, url, self.initial_rsp_response, op)
        return r

    def _cookiejar_from_injected_http_response(self,eb_request):
        default_cookie_domain = eb_request.request.url().host()
        cookiejar = self._qt_cookiejar_from_rsp_cookiejar(self.initial_rsp_response.cookies, default_cookie_domain)
        return cookiejar

    def createRequest(self, op, qt_request, device = None):
        eb_request = EbNetworkRequest(qt_request)
        url = eb_request.request.url()
        if InjectedQNetworkRequest.thatRequestHasMagicQt4(eb_request):
            r = self._network_reply_from_injected_http_response(op, eb_request)
            cookiejar = self._cookiejar_from_injected_http_response(eb_request)
            self.setCookieJar(cookiejar)
        else:
            self.rsp_response = None
            original_r = QNetworkAccessManager.createRequest(self, op, eb_request.request, device)
            original_r.sslErrors.connect(self.sslErrorHandler)
            #self._set_my_cookies_from_reply(original_r)
            r = SniffingNetworkReply(self, eb_request.request, original_r, op)

        r.finished.connect(self.requestFinishedActions)

        return r

    def sslErrorHandler(self,errorlist):
        response = self.sender()
        if self.ignore_ssl_errors:
            response.ignoreSslErrors(errorlist)
        else:
            print ("Test aborted because of ssl errors:")
            for error in errorlist:
                print ( error.errorString() )
            self.autocloseFailed.emit()

    def setAutoCloseUrls(self,autocloseurls):
        self.autocloseurls = autocloseurls

    def _create_urllib_data(self, qt_network_reply):
        if isinstance(qt_network_reply, InjectedNetworkReply):
            """
            The injected reply knows its urllib/request data already.
            """
            raise NotImplemented('Do not create urrllib data from injected reply')
        qt_network_request = qt_network_reply.request()

        request_url = qt_network_request.url()
        url = request_url.toEncoded().data()

        """ we don't know anymore if this was a get, but i
        assume it is safe to say so, as this should be used
        just for recreating cookies and other stuff but not
        by the content handler.
        So this is pretty minimal:
        """
        req = Request('GET', url)
        prepared_req = req.prepare()


        response_fp = StringIO()
        raw_header_pairs = qt_network_reply.rawHeaderPairs()
        for header in raw_header_pairs:
            hd_string = '%s: %s' % (header[0], header[1])
            response_fp.write(hd_string)
            response_fp.write("\n")
        response_fp.write(str(qt_network_reply.sniffed_data))

        request_body = str(qt_network_reply.sniffed_data)

        raw_header_pairs = qt_network_reply.rawHeaderPairs()
        headers_dict = {}
        for header in raw_header_pairs:
            headers_dict.update({str(header[0]):str(header[1])})

        try:
            from requests.structures import CaseInsensitiveDict
            from requests.cookies import extract_cookies_to_jar
            from requests.utils import get_encoding_from_headers

            httplib_httpresponse = Httplib_HTTPResponse(MockSock)
            httplib_httpresponse.fp = response_fp
            urllib3_headers = Urllib3_HTTPHeaderDict(headers_dict)
            resp = Urllib3_HTTPresponse(request_body, preload_content=False, headers=urllib3_headers)

            status = qt_network_reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
            resp.status = status

            reason = qt_network_reply.attribute(QNetworkRequest.HttpReasonPhraseAttribute)
            if not reason and status == 200:
                reason = 'OK'
            resp.reason = reason

            response = Response()
            response.status_code = getattr(resp, 'status', None)
            response.headers = CaseInsensitiveDict(getattr(resp, 'headers', {}))
            response.encoding = get_encoding_from_headers(response.headers)
            response.raw = resp
            response.reason = response.raw.reason
            response.url = url
            extract_cookies_to_jar(response.cookies, prepared_req, resp)
            response.request = prepared_req
            response.connection = None

        except Exception as err:
            raise

        self.rsp_response = response
        return

    def requestFinishedActions(self):
        qt_network_reply = self.sender()

        if isinstance(qt_network_reply, InjectedNetworkReply):
            self.requestFinishing.emit()
            return

        status = qt_network_reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)

        self._set_my_cookies_from_reply(qt_network_reply)

        if int(status) in [301, 302, 302]:
            location = qt_network_reply.header(QNetworkRequest.LocationHeader)
            new_request = QNetworkRequest(location)
            self.requestLocation.emit(new_request)

        # replies from within Qt don't have a http_response ... create one
        self._create_urllib_data(qt_network_reply)

        self.requestFinishing.emit()
        self.checkAutoCloseUrls()



    def checkAutoCloseUrls(self):
        sender = self.sender()
        url = sender.url().toString()
        http_status_pre = sender.attribute( QNetworkRequest.HttpStatusCodeAttribute)
        try:
            #python2
            http_status = http_status_pre.toInt()
            http_status_result = http_status[0]
        except AttributeError:
            #python 3
            http_status_result = http_status_pre

        result = self.autocloseurls.check(url, http_status_result)
        if result == 'OK':
            self.autocloseOk.emit()
        if result == 'NOK':
            self.autocloseFailed.emit()

