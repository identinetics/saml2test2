import inspect
from aatest import check, Unknown
from aatest.check import CRITICAL, Check
import sys

__author__ = 'roland'


class VerifySubject(Check):
    cid = 'verify_subject'

    def __call__(self, conv=None, output=None):
        response = conv.protocol_response[-1].response
        # Assumes only one assertion
        # TODO deal with more then one assertion if necessary
        subj = response.assertion[0].subject
        request = conv.protocol_request[-1]

        res = {}
        # Nameid format
        nformat = sp_name_qualifier = ''
        if "name_id.format" in self._kwargs:
            nformat = self._kwargs["name_id.format"]
        else:
            if request.name_id_policy:
                nformat = request.name_id_policy.format
                sp_name_qualifier = request.name_id_policy.sp_name_qualifier

        if request.name_id_policy:
            sp_name_qualifier = request.name_id_policy.sp_name_qualifier

        if nformat:
            try:
                assert subj.name_id.format == nformat
                if sp_name_qualifier:
                    assert subj.name_id.sp_name_qualifier == sp_name_qualifier
            except AssertionError:
                res['message'] = "The IdP returns wrong NameID format"
                res['status'] = CRITICAL

        return res


CLASS_CACHE = {}


def factory(cid, classes=CLASS_CACHE):
    if len(classes) == 0:
        check.factory(cid, classes)
        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if inspect.isclass(obj):
                try:
                    classes[obj.cid] = obj
                except AttributeError:
                    pass

    if cid in classes:
        return classes[cid]
    else:
        raise Unknown("Couldn't find the check: '%s'" % cid)
