from aatest.session import SessionHandler as AAtestSessionHandler
from aatest.parse_cnf import sort
#from aatest.session import Node
from saml2test.jatnode import JatNode

class SessionHandler(AAtestSessionHandler):

    def init_session(self, profile=None):
        _flows = sort(self.order, self.test_flows)
        self["flow_names"] = [f.name for f in _flows]

        _tests =[]
        for k in self["flow_names"]:
            try:
                kwargs = {"mti": self.test_flows[k]["mti"]}
            except KeyError:
                kwargs = {}
            new_test_node = JatNode(k, self.test_flows[k], **kwargs)
            _tests.append(new_test_node)

        self["tests"] = _tests
        self["test_info"] = {}
        self["profile"] = profile or self.profile
        return self._dict