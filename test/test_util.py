from saml2test import util
from saml2test.util import collect_ec

__author__ = 'roland'


def test_get_check():
    chk = util.get_check('verify_entity_category')
    assert chk

    chk = util.get_check('eurythmics')
    assert chk is None


def test_collect_ec():
    ec = collect_ec()
    assert ec