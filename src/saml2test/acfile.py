import yaml

class WebUserAccessControlFile(object):
    def __init__(self, filename):
        with open(filename,'r') as stream:
            self.data = yaml.load(stream)

    def test(self,github_repo,email):
        github_name = github_repo.partition('/')[0]
        try:
            if self.data[github_name] == email:
                return True
            else:
                return False
        except KeyError as e:
            return False