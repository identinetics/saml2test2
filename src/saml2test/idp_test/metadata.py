from saml2test.util import read_multi_conf
from saml2.metadata import entity_descriptor
from saml2.metadata import entities_descriptor
from saml2.config import Config
from saml2.sigver import security_context
from saml2.validate import valid_instance
from saml2.metadata import metadata_tostring_fix


class MyMetadata(object):
    def __init__(self, cargs, kwargs):
        self.nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}

        _cnf = kwargs['conf']
        res = read_multi_conf(_cnf, True)
        eds = []
        for key, cnf in res.items():
            eds.append(entity_descriptor(cnf))

        valid_for = 0

        """
            Setting things to None here that are now unused, but might be useful someday
        """
        conf = Config()
        conf.key_file = None
        conf.cert_file = None
        conf.debug = 1
        conf.xmlsec_binary = None
        args_name = None
        args_id = None
        args_sign = None
        secc = security_context(conf)

        desc, xmldoc = entities_descriptor(eds, valid_for, args_name, args_id,
                                           args_sign, secc)
        valid_instance(desc)

        self.desc = desc
        self.xmldoc = xmldoc

    def get_xml_output(self):
        xmldoc = metadata_tostring_fix(self.desc, self.nspair, self.xmldoc)
        output = xmldoc.decode("utf-8")
        return output

