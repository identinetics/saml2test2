class Unknown(Exception):
    pass


class Callback(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __call__(self, msg):
        for path, val in self.kwargs.items():
            node = msg
            _p = path.split('.')
            for p in _p[:-1]:
                _node = getattr(node, p)
                if _node:
                    node = _node
                else:
                    raise Unknown('path {} not in message'.format(path))