import sys, os, urllib, logging
from socket import timeout

class ConfigFileNotReadable(EnvironmentError):
    pass

class ConfigUrlNotReadable(Exception):
    pass

logger = logging.getLogger(__name__)

"""
Config Error exception.
Takes the error exceptions and a message.
"""
class ConfigError(Exception):

    def __init__(self, errors, message=None):
        if not message:
            message = 'Configuration Error'
        super(ConfigError, self).__init__(message)
        self.errors = errors

    def error_details_as_string(self):
        errstr = []
        for e in self.errors:
            try:
                errstr.append('Errno:{}: {}: "{}"'.format(e.errno, e.strerror, e.filename))
            except AttributeError:
                errstr.append('Error:{}'.format(e))

        r = "\n".join(errstr)
        return r




class CheckedConfig(object):
    def __init__(self):
        self.config_errors = []
        self.config_infos = []
        self.set_initial_parameters()
        self.config()
        self.run_checks()
        if self.config_errors:
            raise ConfigError(self.config_errors)
        return

    def param_base(self):
        return 'http://localhost:8087/'

    def set_initial_parameters(self):
        self.BASE = self.param_base()

    def run_checks(self):
        self.check_flows()
        self.check_metadata()
        self.check_config()

    def check_flows(self):
        key = 0
        while key < len(self.FLOWS):
            flow_file = self.FLOWS[key]
            try:
                selected_flow_file = self.test_file_read(flow_file)
            except ConfigFileNotReadable as e:
                self.config_errors.append(e)
            else:
                if selected_flow_file != flow_file:
                    self.config_infos.append('{} was selected for {}'.format (selected_flow_file, flow_file))
                    self.FLOWS[key] =selected_flow_file

            key = key + 1

        return

    def check_metadata(self):
        # Note: That's a little bit educated guessing: The structure of the config is from saml2.
        # TODO: Do we really need multiple metadata files?
        md_ix = 0
        while md_ix < len(self.METADATA):
            md = self.METADATA[md_ix]
            file_list_ix = 0
            klass = self.METADATA[md_ix]['class']
            if klass == 'saml2.mdstore.MetaDataFile':
                while file_list_ix < len(self.METADATA[md_ix]['metadata']):
                    metadata_file = self.METADATA[md_ix]['metadata'][file_list_ix][0]
                    try:
                        selected_metadata_file = self.test_file_read(metadata_file)
                    except ConfigFileNotReadable as e:
                        self.config_errors.append(e)
                    else:
                        if selected_metadata_file != metadata_file:
                            self.config_infos.append('{} was found for {}'.format(selected_metadata_file, metadata_file))
                            tuple_as_list = list(self.METADATA[md_ix]['metadata'][file_list_ix])
                            tuple_as_list[0] = selected_metadata_file
                            tuple_as_tuple = tuple(tuple_as_list)
                            self.METADATA[md_ix]['metadata'][file_list_ix] = tuple_as_tuple

                    file_list_ix = file_list_ix + 1
            elif klass == 'saml2.mdstore.MetaDataExtern':
                urls_list = self.METADATA[md_ix]['metadata']
                for url_md in urls_list:
                    for url in url_md:
                        try:
                            url = str(url)
                            resp = urllib.request.urlopen(url, timeout=5).read()
                        except( urllib.error.HTTPError, urllib.error.URLError) as err:
                            msg = 'Error with URL {}: {}'.format(url,err)
                            e = ConfigUrlNotReadable(msg)
                            self.config_errors.append(e)
                            #logging.error(msg)
                        except( timeout ):
                            msg = 'Timeout with URL {}'.format(url)
                            e = ConfigUrlNotReadable(msg)
                            self.config_errors.append(e)
                            #logging.error(msg)


            else:
                # do nothing if klass is not a known klass
                pass

            md_ix = md_ix + 1

        return

    def check_config(self):
        mandatory_keys = {'CONF_NAME', 'ENTITY_ID', 'FLOWS', 'FLOWS_PROFILES', 'IDP_BASE',
                          'METADATA', 'PORT', 'SERVER_TLS'}
        actual_keys = set()
        for attr in dir(self):
            if not attr.startswith('_'):
                actual_keys.add(attr)
        if (mandatory_keys - actual_keys) != set():
            errmsg = 'Missing mandatory key(s) in config: ' + str(mandatory_keys - actual_keys)
            logging.error(errmsg)
            raise ValueError(errmsg)

        for config_key in self.CONFIG:
            config = self.CONFIG[config_key]
            for key in ('cert_file', 'key_file'):
                key_file = config[key]
                try:
                    selected_key_file = self.test_file_read(key_file)
                except ConfigFileNotReadable as e:
                    self.config_errors.append(e)
                    continue
                else:
                    if selected_key_file != key_file:
                        self.config_infos.append('{} was selected for {}'.format(selected_key_file, key_file))
                        self.CONFIG[config_key][key] = selected_key_file

        return

    def test_file_read(self, filep):
        try:

            open(filep)
            return filep

        except FileNotFoundError as e:

            test_filep = os.path.join( self.CONFIG_SRC_DIR, filep )
            try:
                open (test_filep)
            except (FileNotFoundError, NotADirectoryError):
                pass
            else:
                return test_filep

            for try_dir in sys.path:
                test_filep = os.path.join( try_dir , filep )
                try:
                    open (test_filep)
                except ( FileNotFoundError, NotADirectoryError ):
                    continue
                else:
                    return test_filep

            raise ConfigFileNotReadable(e.errno, e.strerror, e.filename)
        return


