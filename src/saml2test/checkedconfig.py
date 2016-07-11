class ConfigFileNotReadable(EnvironmentError):
    pass

class ConfigError(Exception):
    def __init__(self, errors):
        message = 'Configuration Error'
        super(ConfigError, self).__init__(message)
        self.errors = errors

    def errors_as_string(self):
        errstr = []
        for e in self.errors:
            errstr.append('Errno:{}: {}: "{}"'.format(e.errno, e.strerror, e.filename))

        r = "\n".join(errstr)
        return r

class CheckedConfig(object):

    def __init__(self):
        self.config_errors = []
        self.config()
        self.run_checks()
        if self.config_errors:
            raise ConfigError(self.config_errors)
        return

    def run_checks(self):
        self.check_flows()
        self.check_metadata()
        self.check_config()

    def check_flows(self):
        for flow_file in self.FLOWS:
            try:
                self.test_file_read(flow_file)
            except ConfigFileNotReadable as e:
                self.config_errors.append(e)
        return

    def check_metadata(self):
        # Note: That's a little bit educated guessing: We'll have to clean up the config.
        for md in self.METADATA:
            file_list_tuple = md['metadata']
            for file_list in file_list_tuple:
                for metadata_file in file_list:
                    try:
                        self.test_file_read(metadata_file)
                    except ConfigFileNotReadable as e:
                        self.config_errors.append(e)
        return

    def check_config(self):
        for config_key in self.CONFIG:
            config = self.CONFIG[config_key]
            for key in ('cert_file', 'key_file'):
                metadata_file = config[key]
                try:
                    self.test_file_read(metadata_file)
                except ConfigFileNotReadable as e:
                    self.config_errors.append(e)

        return

    def test_file_read(self, filep):
        try:
            open(filep)
        except Exception as e:
            raise ConfigFileNotReadable(e.errno, e.strerror, e.filename)
        return


