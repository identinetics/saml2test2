import inspect
from aatest.check import WARNING
from aatest.check import Check
from aatest.operation import Operation
from saml2.saml import NAMEID_FORMAT_TRANSIENT
import sys

__author__ = 'roland'


class Metadata(Operation):
    pass


class CheckSaml2IntMetaData(Metadata):
    """
    Checks that the Metadata follows the Saml2Int profile
    """

    def __call__(self):
        mdict = self.conv.client.metadata.metadata
        # Should only be one of each
        md = list(mdict.values())[0]
        ed = list(md.entity.values())[0]
        res = {}

        assert len(ed["idpsso_descriptor"])
        idpsso = ed["idpsso_descriptor"][0]

        # contact person
        if "contact_person" not in idpsso and "contact_person" not in ed:
            res[
                'message'] = "Metadata should contain contact person " \
                             "information"
            res['status'] = WARNING
            return res
        else:
            item = []
            if "contact_person" in idpsso:
                for contact in idpsso["contact_person"]:
                    item.append(contact["contact_type"])
            if "contact_person" in ed:
                for contact in ed["contact_person"]:
                    item.append(contact["contact_type"])

            if "support" in item and "technical" in item:
                pass
            elif "support" not in item and "technical" not in item:
                res['message'] = \
                    "Missing technical and support contact information"
                res['status'] = WARNING
            elif "technical" not in item:
                res['message'] = "Missing technical contact information"
                res['status'] = WARNING
            elif "support" not in item:
                res['message'] = "Missing support contact information"
                res['status'] = WARNING

            if res:
                return res

        # NameID format
        if "name_id_format" not in idpsso:
            res['message'] = "Metadata should specify NameID format support"
            res['status'] = WARNING
            return res
        else:
            # should support Transient
            id_formats = []
            for nformat in idpsso["name_id_format"]:
                id_formats.append(nformat["text"])

            if NAMEID_FORMAT_TRANSIENT not in id_formats:
                res['message'] = "IdP should support Transient NameID Format"
                res['status'] = WARNING
                return res


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
