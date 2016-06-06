from PyQt4.QtNetwork import QNetworkRequest, QNetworkAccessManager, QNetworkCookie, QNetworkCookieJar, QNetworkReply

class EbNetworkReply(QNetworkReply):
    pass

"""
Wrapper around QNetworkRequest
"""
class EbNetworkRequest(object):

    def __init__(self,qn_request):
        self.qn_request = qn_request

    @property
    def request(self):
        return self.qn_request