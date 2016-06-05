import sys
from PyQt4.QtGui import QApplication, QGridLayout, QWidget, QPushButton
from PyQt4.QtWebKit import QWebView

try:
    from PyQt4.QtCore import QString
except ImportError:
    # we are using Python3 so QString is not defined
    QString = type("")

from aatest.cookiejar import CookieJar
import aatest.events

from .injector import InjectedQNetworkRequest, InjectedQNetworkAccessManager
from .gui import UrlInput

import time

from aatest import contenthandler
import pprint
from requests.cookies import extract_cookies_to_jar

"""

    TestAction displays the resonse from urllib and takes over the
    handling in an embedded browser.

    __init__ takes an AutoCloseUrls object, which can hold URLs and
    http status codes, to automagically stop the process returning a
    defined result.

    run takes the response object from urllib2 and the corresponding
    url for that response.

"""


class ContentHandler(contenthandler.ContentHandler):
    def __init__(self, interactions=None, conv=None):
        contenthandler.ContentHandler.__init__(self)
        """
            this content handler does not support automatic interactions
            we make sure it is not set ..
        """
        if interactions:
            raise NotImplementedError

        self.conv = conv
        self.cjar = {}
        self.features = {}
        self.handler = None
        self.auto_close_urls = []
        self.http_request = None
        self.http_response = None

        self.last_response = None

        self.cookie_jar = CookieJar()

        self.start_http_response = None

    def handle_response(self, http_response, auto_close_urls_ok_list, conv=None, verify_ssl=True, cookie_jar=None,
                        outside_html_actions=None):

        #aatest just implemented a list instead of an object in auto_close_urls, so we ...
        self.auto_close_urls = AutoCloseUrls()
        for elem in auto_close_urls_ok_list:
            self.auto_close_urls.add(elem,200,True)

        if cookie_jar:
            self.cookie_jar = cookie_jar

        self.conv = conv
        self.verify_ssl = verify_ssl

        self.start_http_response = http_response
        #TODO: If cookiejar => copy into response (Injected Response will loose cookie_jar)

        return self._run()

    def _run(self):
        self.retval = 'NOK'

        self.handler_response_cache = []

        injected_qt_request = InjectedQNetworkRequest(self.start_http_response)

        self.nam = InjectedQNetworkAccessManager(ignore_ssl_errors=True)
        self.nam.setInjectedResponse(
            self.start_http_response,
            self.cookie_jar
        )
        self.nam.setAutoCloseUrls(self.auto_close_urls)

        self.nam.autocloseOk.connect(self.autoclose_ok)
        self.nam.autocloseFailed.connect(self.autoclose_failed)

        self.nam.requestFinishing.connect(self._update_handler_results)

        self.nam.requestLocation.connect(self._location_requested)

        app = QApplication([])
        grid = QGridLayout()
        self.browser = QWebView()

        page = self.browser.page()
        page.setNetworkAccessManager(self.nam)

        self.browser.load(injected_qt_request, self.nam.GetOperation)

        test_ok_button = QPushButton("Test &OK")
        test_ok_button.clicked.connect(self.button_ok)

        test_failed_button = QPushButton("Test &Failed")
        test_failed_button.clicked.connect(self.button_failed)

        test_abort_button = QPushButton("Abort Test")
        test_abort_button.clicked.connect(self.button_abort)

        self.url_input = UrlInput(self.browser)
        self.url_input.setText(injected_qt_request.url().toString())


        grid.addWidget(test_ok_button, 1, 0)
        grid.addWidget(test_failed_button, 1, 1)
        grid.addWidget(test_abort_button, 1, 2)
        grid.addWidget(self.url_input, 2, 0, 1, 3)
        grid.addWidget(self.browser, 4, 0, 1, 3)

        main_frame = QWidget()
        main_frame.setLayout(grid)
        main_frame.show()

        app.exec_()

        processed = False
        if self.retval == 'OK' or self.retval == 'NOK':
            processed = True

        return self.retval

    def _location_requested(self,location):
        self.browser.load(location, self.nam.GetOperation)

    def _update_handler_results(self):
        """ This is called on every finished request-response in the browser """
        self._update_cookie_jar()
        self._event_log_responses()

    def _update_cookie_jar(self):
        if self.nam.rsp_response:
            extract_cookies_to_jar(self.cookie_jar, self.nam.rsp_response.request, self.nam.rsp_response)
        return

    def _event_log_responses(self):
        if self.nam.rsp_response:
            self.conv.events.store(aatest.events.EV_HTTP_RESPONSE, self.nam.rsp_response)
        return

    def _write_event_log_cache(self,retval):

        self.conv.events.store(aatest.events.EV_HANDLER_RESPONSE, "result: %s" %(retval,))
        if retval == 'OK':
            return contenthandler.HandlerResponse(True, 'OK', urllib_response=self.http_response)
        if retval == 'NOK':
            return contenthandler.HandlerResponse(False, urllib_response=self.http_response)
        if retval == 'aborted':
            return contenthandler.HandlerResponse(False, urllib_response=self.http_response)

        raise NotImplemented('unknown status')


    def autoclose_ok(self):
        self.retval = 'OK'
        self._write_event_log_cache(self.retval)
        QApplication.quit()

    def autoclose_failed(self):
        self.retval = 'NOK'
        self._write_event_log_cache(self.retval)
        QApplication.quit()

    def button_ok(self):
        self.retval = 'OK'
        self._write_event_log_cache(self.retval)
        QApplication.quit()

    def button_failed(self):
        self.retval = 'NOK'
        self._write_event_log_cache(self.retval)
        QApplication.quit()

    def button_abort(self):
        self.retval = 'aborted'
        self._write_event_log_cache(self.retval)
        QApplication.quit()


"""
    AutoCloseUrls will be evaluated on every response the embedded
    browser gets. If the path (with beginsWith) and the http status
    match, the browser will be closed to end the test.

    If result is set to false, the test will end as failed, instead
    as OK.
"""


class AutoCloseUrl(object):
    def __init__(self, path, status, result=True):
        self.path = path
        self.status = status
        self.result = result


class AutoCloseUrls(object):
    def __init__(self):
        self.urls = []

    def add(self, path, status, result):
        u = AutoCloseUrl(path, status, result)
        self.urls.append(u)

    def _url_is_equal(self, url, path, status):
        try:
            # python2
            if path.startsWith(url.path) and url.status == status:
                return True
        except AttributeError:
            # python3
            if path.startswith(url.path) and url.status == status:
                return True

        return False

    def check(self, path, status):
        for u in self.urls:
            # print ("check (%s ? %s + %s ? %s)" % ( u.path, path, u.status, status ))
            if self._url_is_equal(u, path, status):
                if u.result:
                    return "OK"
                else:
                    return "NOK"
        return None
