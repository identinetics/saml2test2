# Mock out a HTTP Request that does enough to make it through urllib3's
# read() and close() calls, and also exhausts and underlying file
# object.
#
# bio = BytesIO(b'foo')
# fp = MockHTTPRequest()
# fp.fp = bio
# resp = HTTPResponse(fp, preload_content=False)

class MockHTTPRequest(object):
    def read(self, amt):
        data = self.fp.read(amt)
        if not data:
            self.fp = None

        return data

    def close(self):
        self.fp = None

class MockSock(object):
    @classmethod
    def makefile(cls, *args, **kwargs):
        return