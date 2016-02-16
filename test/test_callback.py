from saml2 import saml
from saml2test.idp_test.callback import Callback

TEST_ATTRIBUTE_STATEMENT = """<?xml version="1.0" encoding="utf-8"?>
<AttributeStatement xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <Attribute Name="testAttribute"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
    FriendlyName="test attribute">
    <AttributeValue >value1 of test attribute</AttributeValue>
    <AttributeValue >value2 of test attribute</AttributeValue>
  </Attribute>
  <Attribute Name="http://www.example.com/testAttribute2"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    FriendlyName="test attribute2">
    <AttributeValue >value1 of test attribute2</AttributeValue>
    <AttributeValue >value2 of test attribute2</AttributeValue>
  </Attribute>
</AttributeStatement>
"""


def test_callback():
    cb = Callback()

    attr_statem = saml.attribute_statement_from_string(TEST_ATTRIBUTE_STATEMENT)
    msg = cb(attr_statem)

    assert msg
