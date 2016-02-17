from aatest.parse_cnf import parse_json_conf, sort
from saml2test import operation
from saml2test.idp_test import func
from saml2test.idp_test import cl_request
from saml2test.idp_test import wb_request

__author__ = 'roland'


def test_1():
    cls_factories = {
        '': operation.factory,
        'cl': cl_request.factory,
        'wb': wb_request.factory,
    }
    func_factory = func.factory
    x = parse_json_conf('flows.json', cls_factories, func_factory, 'cl')
    assert len(x['Flows']) == 16


def test_2():
    cls_factories = {
        '': operation.factory,
        'cl': cl_request.factory,
        'wb': wb_request.factory,
    }
    func_factory = func.factory
    x = parse_json_conf('flows.json', cls_factories, func_factory, 'cl')

    flows = sort(x['Order'], x['Flows'])
    assert [f.name for f in flows] == ['IDP-Metadata-verify',
                                       'IDP-AuthnRedirect-verify',
                                       'IDP-AuthnRedirect-nid_email',
                                       'IDP-AuthnRedirect-nid_transient',
                                       'IDP-AuthnRedirect-nid_unspecified',
                                       'IDP-AuthnRedirect-no_nid',
                                       'IDP-AuthnPost-verify',
                                       'IDP-AuthnPost-nid_transient',
                                       'IDP-EntityCategory-coco',
                                       'IDP-EntityCategory-re_eu',
                                       'IDP-EntityCategory-re_hei',
                                       'IDP-EntityCategory-re_hei_sfs',
                                       'IDP-EntityCategory-re_nren',
                                       'IDP-EntityCategory-re_nren_sfs',
                                       'IDP-EntityCategory-rs',
                                       'IDP-Logout-soap']

