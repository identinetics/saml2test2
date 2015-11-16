import inspect
from aatest import check
from aatest import Unknown
from aatest.check import CRITICAL
from aatest.check import Check
import sys
from saml2.response import AuthnResponse
from saml2.samlp import Response, AuthnRequest

__author__ = 'roland'


def get_message(msgs, msgcls):
    for msg in reversed(msgs):
        if isinstance(msg, msgcls):
            return msg
    return None


class VerifySubject(Check):
    """Verify that the correct named.format and sp_name_qualifier
    was returned """

    cid = 'verify_subject'

    def __call__(self, conv=None, output=None):
        response = get_message(conv.protocol_response, AuthnResponse).response
        # Assumes only one assertion
        # TODO deal with more then one assertion if necessary
        subj = response.assertion[0].subject
        request = get_message(conv.protocol_request, AuthnRequest)

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


class VerifyAttributes(Check):
    """Verify that the correct attributes where returned"""

    cid = 'verify_attributes'

    def __call__(self, conv=None, output=None):
        ava = get_message(conv.protocol_response, AuthnResponse).ava

        conf = conv.client.config
        entcat = conv.extra_args["entcat"]

        # Do I really care about optional attributes ?
        op_attr = conf.getattr('optional_attributes', 'sp')
        req_attr = conf.getattr('required_attributes', 'sp')

        ec_attr = []
        for ec in conf.entity_category:
            ec_attr.extend(entcat[ec])

        # I would expect IdPs to release attributes that I'm allowed
        # to receive according to the ent cat classification and
        # I require them
        missing = []
        if req_attr:
            for attr in req_attr:
                if attr in ec_attr and attr not in ava:
                    missing.append(attr)

        if missing:
            res = {
                "message":
                    "Attributes I expected but not received: {}".format(
                        missing),
                'status': CRITICAL
            }
        else:
            res = {}

        return res


class VerifyEntityCategory(Check):
    """ Verify Entity Category Compliance """

    cid = 'verify_entity_category'

    # Excerpt from https://refeds.org/category/research-and-scholarship
    # The following attributes constitute a minimal subset of the R&S attribute
    # bundle:
    #
    # - eduPersonPrincipalName
    # - mail
    # - displayName OR (givenName AND sn)
    # For the purposes of access control, a non-reassigned persistent identifier is
    # required. If your deployment of eduPersonPrincipalName is non-reassigned, it
    # will suffice. Otherwise you MUST release eduPersonTargetedID (which is
    # non-reassigned by definition) in addition to eduPersonPrincipalName. In any
    # case, release of both identifiers is RECOMMENDED.


    def verify_rs_compliance(ava):
        for attr in ['eduPersonPrincipalName', 'mail']:
            if attr not in ava:
                return False

        if 'displayName' not in ava:
            if 'givenName' in ava and 'sn' in ava:
                pass
            else:
                return False

        return True

    def __call__(self, conv=None, output=None):
        conf = conv.client.config
        ava = get_message(conv.protocol_response, AuthnResponse).ava

        for ec in conf.entity_category:



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
