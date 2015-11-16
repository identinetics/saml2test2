from aatest import prof_util
from aatest.time_util import in_a_while

__author__ = 'roland'


class ProfileHandler(prof_util.ProfileHandler):
    def get_profile_info(self, test_id=None):
        try:
            _conv = self.session["conv"]
        except KeyError:
            pass
        else:
            try:
                md = list(_conv.client.metadata.metadata.values())[0]
                iss = list(md.entity.keys())[0]
            except TypeError:
                iss = ""

            profile = self.to_profile("dict")

            if test_id is None:
                try:
                    test_id = self.session["testid"]
                except KeyError:
                    return {}

            return {"Issuer": iss, "Profile": profile,
                    "Test ID": test_id,
                    "Test description": self.session["node"].desc,
                    "Timestamp": in_a_while()}

        return {}

    def to_profile(self, representation="list"):
        return None
