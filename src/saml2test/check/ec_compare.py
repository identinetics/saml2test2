import logging
import sys
import inspect

from aatest.check import Check
from aatest.check import State
from aatest.events import EV_PROTOCOL_RESPONSE

from saml2.entity_category.edugain import COCO
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.entity_category.swamid import SFS_1993_1153
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION
from saml2.entity_category.swamid import EU
from saml2.entity_category.swamid import NREN
from saml2.entity_category.swamid import HEI
from saml2.response import AuthnResponse

logger = logging.getLogger(__name__)

OK = 0
MISSING = 1
EXTRA = 2


class EntityCategoryTestStatus:
    def __init__(self, status):
        self._status = status
        self.short_text = {
            OK: "OK", MISSING: "Too few", EXTRA: "Too many",
            MISSING+EXTRA: "Too few & too many",
        }[status]

    @property
    def value(self):
        return self._status.value


class EntityCategoryTestResult(State):
    name = 'entity_category_test_result'

    def __init__(self, test_id, status, name, mti=False, specifics=None):
        State.__init__(self, test_id, status, name, mti=mti)
        self.specifics = specifics or []

    def __str__(self):
        _str = [State.__str__(self)]
        for spec in self.specifics:
            _str.append('{}'.format(spec))
        return '\n'.join(_str)


class Result(object):
    def __init__(self, ent_cat='', missing=None, extra=None, expected=None):
        self.ent_cat = ent_cat
        self.missing = missing or []
        self.extra = extra or []
        self.expected = expected or []

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
    def status(self):
        if len(self) == 0:
            return OK
        elif len(self.missing) > 0 and len(self.extra) > 0:
            return MISSING+EXTRA
        elif len(self.missing) > 0:
            return MISSING
        elif len(self.extra) > 0:
            return EXTRA

    @property
    def message(self):
        return EntityCategoryTestStatus(self.status)

    @property
    def short_status_text(self):
        return EntityCategoryTestStatus(self.status).short_text

    def received(self, ava, ec_attr):
        for attr in ec_attr:
            if attr in ava:
                self.expected.append(attr)

    @staticmethod
    def _and_list(list_a, list_b):
        """
        Create a new list which contains all unique elements in the two lists
        given
        :param list_a: list one
        :param list_b: list two
        :return: A list
        """
        _a = set(list_a)
        _a.update(list_b)
        return list(_a)

    @staticmethod
    def _not_in(list_a, list_b):
        _a = set(list_a)
        _a.difference_update(list_b)
        return list(_a)

    def union(self, other):
        """
        Create new set with elements from self and other

        :param other: Another Result instance
        :return: A newly minted Result representing the combination of self
            and other.
        """
        assert isinstance(other, Result)
        res = Result()
        res.ent_act = '{} and {}'.format(self.ent_cat, other.ent_cat)
        res.missing = self._and_list(self.missing, other.missing)
        res.expected = self._and_list(self.expected, other.expected)
        res.extra = self._not_in(self.extra, other.expected)
        return res


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
    res.received(ava, ec_attr)

    # Verifying the minimal subset
    for attr in ['eduPersonPrincipalName', 'mail', 'eduPersonTargetedID']:
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
    res.received(ava, ec_attr)

    for attr in ec_attr:
        if attr in req or attr == 'eduPersonTargetedID':
            if attr not in ava:
                res.missing.append(attr)

    for attr in ava:
        if attr == 'eduPersonTargetedID':
            continue
        if attr not in req:
            res.extra.append(attr)

    return res


def verify_ec_compliance(ec, ava, req, ec_attr):
    """
    Release all attributes that are part of the entity category set of
    attributes disregarding which are required.

    :param ava: Attribute - Value assertion
    :param req: Required attributes - not used
    :param req: Attribute bundle belonging to entity category
    :return: Dictionary with missing or excessive attribute
    """

    res = Result(ent_cat=ec)
    res.received(ava, ec_attr)

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
        conf = conv.entity.config
        ava = conv.events.get_message(EV_PROTOCOL_RESPONSE, AuthnResponse).ava
        req_attr = conf.getattr('required_attributes', 'sp')
        entcat = conv.extra_args["entcat"]

        self.ec = conf.entity_category

        non_compliant = []
        if self.ec:
            # This is a specific demand that SWAMID has placed
            # R&E MUST NOT appear on its own
            if RESEARCH_AND_EDUCATION in self.ec:
                must = False
                for _ec in [EU, NREN, HEI]:
                    if _ec in self.ec:
                        must = True
                        self.ec.remove(_ec)
                        self.ec.append((RESEARCH_AND_EDUCATION, _ec))

                if must:
                    self.ec.remove(RESEARCH_AND_EDUCATION)
                else:
                    self._message = 'Research and Education must be combined ' \
                                    'with another entity category from the ' \
                                    'SWAMID list'
                    self._status = Warning
                    return {}

            non_compliant = None
            logger.info('Entity_categories: {}'.format(self.ec))
            for ec in self.ec:
                _res = VERIFY[ec](ec, ava, req_attr, entcat[ec])
                if len(_res):
                    if non_compliant is None:
                        non_compliant = _res
                    else:
                        non_compliant = non_compliant.union(_res)

        if non_compliant:
            self._message = 'Non compliant'
            self._status = Warning
            return {'test_result': non_compliant}

        return {}


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
