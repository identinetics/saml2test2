from saml2test.check.ec_compare import Result, EntityCategoryTestResult

__author__ = 'roland'


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
    assert _str == "test_id: status=WARNING, message=Non conformant\nR&S: missing=['mail'], extra=['ou']"