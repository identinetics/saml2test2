from enum import IntEnum
from aatest.check import Check
from aatest.check import WARNING
from saml2.entity_category.edugain import COCO
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.entity_category.swamid import SFS_1993_1153
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION
from saml2.entity_category.swamid import EU
from saml2.entity_category.swamid import NREN
from saml2.entity_category.swamid import HEI
from saml2.response import AuthnResponse
from saml2test.check import get_message


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


class EntityCategoryTestResult:
    def __init__(self, missing, extra, test_id=None):
        self.missing_attributes = frozenset(missing)
        self.extra_attributes = frozenset(extra)
        self.test_id = test_id

        if len(self) == 0:
            self.status = EntityCategoryTestStatus(TestStatus.ok)
        elif len(missing) > 0 and len(extra) > 0:
            self.status = EntityCategoryTestStatus(TestStatus.too_few_too_many)
        elif len(missing) > 0:
            self.status = EntityCategoryTestStatus(TestStatus.too_few)
        elif len(extra) > 0:
            self.status = EntityCategoryTestStatus(TestStatus.too_many)

    def __eq__(self, other):
        return self.missing_attributes == other.missing_attributes and \
               self.extra_attributes == other.extra_attributes and \
               self.test_id == other.test_id

    def __len__(self):
        return len(self.missing_attributes) + len(self.extra_attributes)

    def __repr__(self):
        return "{}(missing={}, extra={})".format(type(self).__name__,
                                                 self.missing_attributes,
                                                 self.extra_attributes)

    def __hash__(self):
        return hash(
            (self.test_id, self.missing_attributes, self.extra_attributes))


# class EntityCategoryComparison:
#     def __init__(self, attribute_release_policy):
#         self.policy = attribute_release_policy
#
#     def __call__(self, entity_categories, attributes):
#         expected_attributes = get_expected_attributes(self.policy,
#                                                       entity_categories)
#         lowercase_attribute_names = [k.lower() for k in attributes.keys()]
#
#         missing = []
#         for key in expected_attributes:
#             if key.lower() not in lowercase_attribute_names:
#                 missing.append(key)
#
#         extra = []
#         for key in lowercase_attribute_names:
#             if key not in expected_attributes:
#                 extra.append(key)
#         return EntityCategoryTestResult(missing, extra)
#
#
# def get_expected_attributes(attribute_release_policy, entity_categories):
#     def expected_attributes_for_entity_categories(ec_maps, entity_categories,
#                                                   **kwargs):
#         entity_categories_set = set(entity_categories)
#         expected_attributes = set()
#         for ec_map in ec_maps:
#             for ec, released_attributes in ec_map.items():
#                 always_released = ec == ""
#                 covers_ec_combo = isinstance(
#                     ec, tuple) and entity_categories_set.issuperset(ec)
#                 # specified entity categories includes at least the
#                 # release policies entity categories
#                 if ec in entity_categories or always_released or \
#                         covers_ec_combo:
#                     expected_attributes.update(released_attributes)
#
#         return expected_attributes
#
#     return attribute_release_policy.get(
#         "entity_categories", None,
#         post_func=expected_attributes_for_entity_categories,
#         entity_categories=entity_categories)


def verify_rs_compliance(ava, req, ec_attr, *args):
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
    missing = []
    extra = []

    # Verifying the minimal subset
    for attr in ['eduPersonPrincipalName', 'mail']:
        if attr not in ava:
            missing.append(attr)

    if 'displayName' not in ava:
        if 'givenName' in ava and 'sn' in ava:
            pass
        elif 'givenName' in ava:
            missing.append('sn')
        elif 'sn' in ava:
            missing.append('givenName')
        else:
            missing.extend(['displayName', 'givenName', 'sn'])

    for attr in ava:
        if attr not in ec_attr:
            extra.append(attr)

    return EntityCategoryTestResult(missing, extra)


def verify_coco_compliance(ava, req, ec_attr, *args):
    """
    Release only attributes that are required by the SP and part of the
    CoCo set of attributes.

    :param ava: Attribute - Value assertion
    :param req: Required attributes
    :param req: Attribute bundle belonging to entity category
    :return: Dictionary with missing or excessive attribute
    """

    missing = []
    excess = []

    for attr in ec_attr:
        if attr in req:
            if attr not in ava:
                missing.append(attr)
        else:
            if attr in ava:
                excess.append(attr)

    if missing:
        return False

    return True


def verify_ec_compliance(ava, req, ec_attr, *attr):
    """
    Release all attributes that are part of the entity category set of
    attributes.

    :param ava: Attribute - Value assertion
    :param req: Required attributes - not used
    :param req: Attribute bundle belonging to entity category
    :return: Dictionary with missing or excessive attribute
    """

    missing = []
    extra = []

    for attr in ec_attr:
        if attr not in ava:
            missing.append(attr)

    for attr in ava:
        if attr not in ec_attr:
            extra.append(attr)

    return EntityCategoryTestResult(missing, extra)


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

    def __call__(self, conv=None, output=None):
        conf = conv.client.config
        ava = get_message(conv.protocol_response, AuthnResponse).ava
        req_attr = conf.getattr('required_attributes', 'sp')
        entcat = conv.extra_args["entcat"]

        self.ec = conf.entity_category
        non_compliant = []
        if self.ec:
            if RESEARCH_AND_EDUCATION in self.ec:  # find the other
                for _ec in [EU, NREN, HEI]:
                    if _ec in self.ec:
                        self.ec.remove(_ec)
                        self.ec.append((RESEARCH_AND_EDUCATION, _ec))

            for ec in self.ec:
                result = VERIFY[ec](ava, req_attr, entcat[ec])
                if result.status.value != TestStatus.ok:
                    non_compliant.append("{}:{}".format(ec, result))

        if non_compliant:
            res = {
                'message': "Not compliant with entity categories: {}".format(
                    non_compliant
                ),
                'status': Warning
            }
        else:
            res = {}

        return res


