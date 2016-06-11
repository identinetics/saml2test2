from aatest.session import SessionHandler as AAtestSessionHandler

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
            _tests.append(Node(k, self.test_flows[k]["desc"], **kwargs))

        self["tests"] = _tests
        self["test_info"] = {}
        self["profile"] = profile or self.profile
        return self._dict