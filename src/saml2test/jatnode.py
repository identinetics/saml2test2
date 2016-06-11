"""
Just another test node
"""
from aatest.session import Node
class JatNode(Node):
    def __init__(self, name, test_flow):
        desc = test_flow["desc"]
        super(JatNode,self).__init__(name, desc, mti=None)
        self.tc_id = test_flow['tc_id']
        return