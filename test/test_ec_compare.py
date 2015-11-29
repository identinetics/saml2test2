from saml2test.check.ec_compare import Result
from saml2test.check.ec_compare import EntityCategoryTestResult
from saml2test.check.ec_compare import verify_rs_compliance
from saml2test.check.ec_compare import verify_coco_compliance
from saml2.entity_category import refeds
from saml2.entity_category import edugain

__author__ = 'roland'


def list_eq(l1, l2):
    return set(l1) == set(l2)


def test_result():
    res = Result('R&S')
    res.missing.append('mail')
    assert len(res) == 1
    _str = '{}'.format(res)
    assert _str == "R&S: missing=['mail']"
    res.missing.append("cn")
    assert len(res) == 2
    _str = '{}'.format(res)
    assert _str == "R&S: missing=['mail', 'cn']"
    res.extra.append('ou')
    assert len(res) == 3
    _str = '{}'.format(res)
    assert _str == "R&S: missing=['mail', 'cn'], extra=['ou']"


def test_entity_category_test_result():
    res = Result('R&S')
    res.missing.append('mail')
    res.extra.append('ou')

    tr = EntityCategoryTestResult('test_id', 2, 'name', specifics=[res])
    tr.message = "Non conformant"

    assert tr.status == 2
    _str = '{}'.format(tr)
    assert _str == "test_id: status=WARNING, message=Non conformant\nR&S: " \
                   "missing=['mail'], extra=['ou']"


def test_entity_category_test_result_comb():
    ec_attr_rs = refeds.RELEASE[refeds.RESEARCH_AND_SCHOLARSHIP]
    ec_attr_rs.extend(refeds.RELEASE[''])
    ec_attr_coco = edugain.RELEASE[edugain.COCO]
    ec_attr_coco.extend(edugain.RELEASE[''])

    ava = {
        'eduPersonPrincipalName': 'foo@example.com',
        'eduPersonTargetedID': 'foovar',
        'location': 'earth'
    }

    requested_attributes = ['eduPersonPrincipalName',
                            'eduPersonScopedAffiliation',
                            'mail']

    res_rs = verify_rs_compliance('R&S', ava, requested_attributes, ec_attr_rs)
    assert list_eq(res_rs.missing, ['mail', 'displayName', 'givenName', 'sn'])
    assert list_eq(res_rs.expected,
                   ['eduPersonPrincipalName', 'eduPersonTargetedID'])
    assert res_rs.extra == ['location']

    res_coco = verify_coco_compliance('CoCo', ava, requested_attributes,
                                      ec_attr_coco)

    assert list_eq(res_coco.missing, ['eduPersonScopedAffiliation', 'mail'])
    assert list_eq(res_coco.expected, ['eduPersonPrincipalName',
                                       'eduPersonTargetedID'])
    assert res_coco.extra == ['location']

    res = res_rs.union(res_coco)

    assert list_eq(res.missing, ['displayName', 'givenName',
                                 'eduPersonScopedAffiliation', 'sn', 'mail'])
    assert list_eq(res.expected,
                   ['eduPersonPrincipalName', 'eduPersonTargetedID'])
    assert res.extra == ['location']
