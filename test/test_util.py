from saml2test import util

__author__ = 'roland'


def test_get_check():
    chk = util.get_check('verify_entity_category')
    assert chk

    chk = util.get_check('eurythmics')
    assert chk is None
