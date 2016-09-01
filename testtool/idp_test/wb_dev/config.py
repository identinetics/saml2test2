"""
This file serves as an example on how to derive a configuration from the config_abstract.py

"""
from config_abstract import Config as Abstractconfig

# ... this class name has to be Config.
class Config(Abstractconfig):

    """
    Parameters are set in the config() method. Make sure you call the Superclass config() first to have the
    defaults initialized.
    """

    def config(self):
        super(Config, self).config()

        self.IDP_BASE = "https://testidp01.samltest.fed-lab.org"
        self.ENTITY_ID = "%s/idp/shibboleth" % self.IDP_BASE
        self.CONTENT_HANDLER_TRIGGER = {
            # To trigger the robobrowser content handler add combinations of test-id and url(s):
            'IDP-AuthnRedirect-nid_unspecified': ["%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE],
        }
        self.CONTENT_HANDLER_INTERACTION = [
            {  # This interaction fills out the login form
                "matches": {
                    # 'Trigger this interaction on the URL and title
                    "url": "%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE,
                    "title": 'Web Login Service'
                },
                # TODO: Documentation about parameter page-type
                "page-type": "login",
                "control": {
                    "type": "form",
                    # Parameters to be set on submitting the form
                    "set": {"j_username": "tester@testinetics.at", "j_password": "test", "_eventId_proceed": ''}
                }
            },
            {  # After the login, the IDP shows a result page, which needs a button clicked for getting the redirect
                # back to the SP: This interaction is just pressing the button.
                "matches": {
                    "url": "%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE,
                    "content": "you must press the Continue button"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                    # Empty set: No parameters, just press the submit button
                    "set": {}
                }

            },
            {  # After the login, the IDP also shows a result page, for some options
                "matches": {
                    "url": "%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE,
                    "content": "You are about to access the service"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                    # Empty set: No parameters, just press the submit button
                    "set": {},
                    # multiple submits on that page ... choose which one to send
                    "submit": "_eventId_proceed"
                }

            },
        ]
