from saml2test.idp_test.setup import load_flows

__author__ = 'roland'


def test():
    fdef = {'Flows':{}, 'Desc': {}, 'Order': []}
    fdef = load_flows(fdef, 'flows.json', 'cl')

    assert fdef