from enum import IntEnum
import sys
import inspect

from aatest.check import Check
from aatest.check import TestResult

from saml2.entity_category.edugain import COCO
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.entity_category.swamid import SFS_1993_1153
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION
from saml2.entity_category.swamid import EU
from saml2.entity_category.swamid import NREN
from saml2.entity_category.swamid import HEI
from saml2.response import AuthnResponse


class TestStatus(IntEnum):
    ok = 1
    too_few = 2
    too_many = 3
    too_few_too_many = 4


class EntityCategoryTestStatus:
    def __init__(self, status):
        self._status = status
        self.short_text = {
            TestStatus.ok: "OK",
            TestStatus.too_few: "Too few",
            TestStatus.too_many: "Too many",
            TestStatus.too_few_too_many: "Too few & too many",
        }[status]

    @property
    def value(self):
        return self._status.value


class EntityCategoryTestResult(TestResult):
    def __init__(self, test_id, status, name, mti=False, specifics=None):
        TestResult.__init__(self, test_id, status, name, mti=mti)
        self.specifics = specifics or []

    def __str__(self):
        _str = [TestResult.__str__(self)]
        for spec in self.specifics:
            _str.append('{}'.format(spec))
        return '\n'.join(_str)


class Result(object):
    def __init__(self, ent_cat='', missing=None, extra=None):
        self.ent_cat = ent_cat
        self.missing = missing or []
        self.extra = extra or []

    def __len__(self):
        return len(self.missing) + len(self.extra)

    def __repr__(self):
        if self.missing and self.extra:
            return "{}: missing={}, extra={}".format(self.ent_cat, self.missing,
                                                     self.extra)
        elif self.missing:
            return "{}: missing={}".format(self.ent_cat, self.missing)
        elif self.extra:
            return "{}: extra={}".format(self.ent_cat, self.extra)
        else:
            return "{}: -".format(self.ent_cat)

    @property
    def message(self):
        if len(self) == 0:
            return EntityCategoryTestStatus(TestStatus.ok)
        elif len(self.missing) > 0 and len(self.extra) > 0:
            return EntityCategoryTestStatus(TestStatus.too_few_too_many)
        elif len(self.missing) > 0:
            return EntityCategoryTestStatus(TestStatus.too_few)
        elif len(self.extra) > 0:
            return EntityCategoryTestStatus(TestStatus.too_many)


def verify_rs_compliance(ec, ava, req, ec_attr):
    """
    Excerpt from https://refeds.org/category/research-and-scholarship
    The following attributes constitute a minimal subset of the R&S attribute
    bundle:

    - eduPersonPrincipalName
    - mail
    - displayName OR (givenName AND sn)
    For the purposes of access control, a non-reassigned persistent identifier
    is required. If your deployment of eduPersonPrincipalName is non-reassigned,
    it will suffice. Otherwise you MUST release eduPersonTargetedID (which is
    non-reassigned by definition) in addition to eduPersonPrincipalName. In any
    case, release of both identifiers is RECOMMENDED.

    :param ava: Attribute - Value assertion from response
    :param req: Required Attributes - not used presently
    :param ec_attr: The entity category attribute bundle
    :return: Dictionary with two keys 'missing' and 'extra' who's values are
        lists of attribute names.
    """

    res = Result(ent_cat=ec)

    # Verifying the minimal subset
    for attr in ['eduPersonPrincipalName', 'mail']:
        if attr not in ava:
            res.missing.append(attr)

    if 'displayName' not in ava:
        if 'givenName' in ava and 'sn' in ava:
            pass
        elif 'givenName' in ava:
            res.missing.append('sn')
        elif 'sn' in ava:
            res.missing.append('givenName')
        else:
            res.missing.extend(['displayName', 'givenName', 'sn'])

    for attr in ava:
        if attr not in ec_attr:
            res.extra.append(attr)

    return res


def verify_coco_compliance(ec, ava, req, ec_attr):
    """
    Release only attributes that are required by the SP and part of the
    CoCo set of attributes.

    :param ava: Attribute - Value assertion
    :param req: Required attributes
    :param req: Attribute bundle belonging to entity category
    :return: Dictionary with missing or excessive attribute
    """

    res = Result(ent_cat=ec)

    for attr in ec_attr:
        if attr in req:
            if attr not in ava:
                res.missing.append(attr)
        else:
            if attr in ava:
                res.extra.append(attr)

    return res


def verify_ec_compliance(ec, ava, req, ec_attr):
    """
    Release all attributes that are part of the entity category set of
    attributes.

    :param ava: Attribute - Value assertion
    :param req: Required attributes - not used
    :param req: Attribute bundle belonging to entity category
    :return: Dictionary with missing or excessive attribute
    """

    res = Result(ent_cat=ec)

    for attr in ec_attr:
        if attr not in ava:
            res.missing.append(attr)

    for attr in ava:
        if attr not in ec_attr:
            res.extra.append(attr)

    return res


VERIFY = {
    RESEARCH_AND_SCHOLARSHIP: verify_rs_compliance,
    COCO: verify_coco_compliance,
    SFS_1993_1153: verify_ec_compliance,
    (RESEARCH_AND_EDUCATION, EU): verify_ec_compliance,
    (RESEARCH_AND_EDUCATION, NREN): verify_ec_compliance,
    (RESEARCH_AND_EDUCATION, HEI): verify_ec_compliance
}


class VerifyEntityCategory(Check):
    """ Verify Entity Category Compliance """

    cid = 'verify_entity_category'
    test_result_cls = EntityCategoryTestResult

    def __call__(self, conv=None, output=None):
        conf = conv.client.config
        ava = conv.events.get_message('protocol_response', AuthnResponse).ava
        req_attr = conf.getattr('required_attributes', 'sp')
        entcat = conv.extra_args["entcat"]

        self.ec = conf.entity_category
        result = {'missing': [], 'extra': []}

        non_compliant = []
        if self.ec:
            if RESEARCH_AND_EDUCATION in self.ec:  # find the other
                for _ec in [EU, NREN, HEI]:
                    if _ec in self.ec:
                        self.ec.remove(_ec)
                        self.ec.append((RESEARCH_AND_EDUCATION, _ec))

            for ec in self.ec:
                _res = VERIFY[ec](ec, ava, req_attr, entcat[ec])
                if len(_res):
                    non_compliant.append(_res)

        if non_compliant:
            res = {'message': 'Non compliant', 'status': Warning,
                   'specifics': non_compliant}
        else:
            res = {}

        return res


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
