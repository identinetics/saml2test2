"""
Abstract Test configuration.

This configuration should be subclassed by a config.py file to be changed.
"""
from config_testdriver import Config as TestdriverConfig

class Config(TestdriverConfig):

    def config(self):
        super(Config,self).config()

        self.FLOWS = [
            "flows.yaml",
        ]
        self.FLOWS_PROFILES = [
            "saml2int",
        ]

        self.IDP_BASE = "https://testidp01.samltest.fed-lab.org"
        self.ENTITY_ID = "%s/idp/shibboleth" % self.IDP_BASE
        self.CONTENT_HANDLER_TRIGGER = {
            # To trigger the robobrowser content handler add combinations of test-id and url(s):
            'IDP-AuthnRedirect-nid_unspecified': ["%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE],
        }

        self.CONTENT_HANDLER_INTERACTION = [
            # --
            # Interactions below are older examples, not used for the idp1.test.wpv.portalverbund.at
            {
                "matches": {
                    "url": "%s/sso/post" % self.IDP_BASE,
                    "title": 'IDP test login'
                },
                "page-type": "login",
                "control": {
                    "type": "form",
                    "set": {"login": "admin", "password": "admin"}
                }
            },
            {
                "matches": {
                    "url": "%s/sso/redirect" % self.IDP_BASE,
                    "title": "SAML 2.0 POST"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                }
            },
            {
                "matches": {
                    "url": "%s/sso/post" % self.IDP_BASE,
                    "title": "SAML 2.0 POST"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                    "set": {}
                }
            },
            {
                "matches": {
                    "url": "%s/slo/soap" % self.IDP_BASE,
                    # "title": "SAML 2.0 POST"
                },
                "page-type": "other",
                "control": {
                    "type": "response",
                    "pick": {"form": {"action": "%s/sls" % self.IDP_BASE}}
                }
            },
        ]