import os

from aatest import prof_util
from aatest.log import with_or_without_slash
from future.backports.urllib.parse import quote_plus
from saml2.time_util import utc_now

__author__ = 'roland'


class ProfileHandler(prof_util.ProfileHandler):
    def get_profile_info(self, test_id=None):
        try:
            _conv = self.session["conv"]
        except KeyError:
            res = {}
        else:
            try:
                md = list(_conv.entity.metadata.metadata.values())[0]
                iss = list(md.entity.keys())[0]
            except TypeError:
                iss = ""

            profile = self.to_profile("list")

            if test_id is None:
                try:
                    test_id = self.session["testid"]
                except KeyError:
                    return {}

            res = {
                "Issuer": iss,
                "Profile": profile,
                "Test ID": test_id,
                "Test description": self.session["flow"]['desc'],
                "Timestamp": utc_now()
            }

        return res

    def to_profile(self, representation="list"):
        return self.session["profile"]

    def log_path(self, test_id=None):
        _conv = self.session["conv"]

        try:
            iss = _conv.entity_id
        except (TypeError, KeyError):
            return ""
        else:
            qiss = quote_plus(iss)

        path = with_or_without_slash(os.path.join("log", qiss))
        if path is None:
            path = os.path.join("log", qiss)

        prof = ".".join(self.to_profile())

        if not os.path.isdir("{}/{}".format(path, prof)):
            os.makedirs("{}/{}".format(path, prof))

        if test_id is None:
            test_id = self.session["testid"]

        return "{}/{}/{}".format(path, prof, test_id)