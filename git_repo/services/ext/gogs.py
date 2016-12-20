#!/usr/bin/env python

import logging
log = logging.getLogger('git_repo.gogs')

from ..service import register_target, RepositoryService, os
from ...exceptions import ResourceError, ResourceExistsError, ResourceNotFoundError

import requests
from urllib.parse import urlparse, urlunparse
import functools

from git import config as git_config
from git.exc import GitCommandError

@register_target('gg', 'gogs')
class GoGSService(RepositoryService):
    fqdn = 'try.gogs.io'

    @classmethod
    def _url_parse(cls, url):
        if '://' not in url:
            url = 'https://'+url
        parse = urlparse(url)
        url_base = urlunparse((parse.scheme, parse.netloc)+('',)*4)
        fqdn = parse.hostname
        return url_base, fqdn

    #@property
    #def git_user(self):
    #    return self.username

    @property
    def url_ro(self):
        return self.url_base

    @property
    def url_rw(self):
        url = self.ssh_url
        if '@' in url:
            return url
        return '@'.join([self.git_user, url])

    def url_api(self, rest):
        return '{}/api/v1/{}'.format(self.url_base, rest)

    @classmethod
    def get_auth_token(cls, login, password, prompt=None):
        import platform
        name = 'git-repo2 token used on {}'.format(platform.node()),
        if '/' in login:
            url, login = login.rsplit('/', 1)
        else:
            url = input('URL [{}]> '.format(cls.fqdn))
        url_base, fqdn = cls._url_parse(url)
        url_api = functools.partial('{}/api/v1/{}'.format, url_base)
        r = requests.get(url_api('users/{}/tokens'.format(login)), auth=(login, password), verify=False)
        r.raise_for_status()
        tokens = r.json()
        tokens = dict((o['name'], o['sha1']) for o in tokens)
        if name in tokens:
            return tokens[name]
        if 'git-repo2 token' in tokens:
            return tokens['git-repo2 token']
        r = requests.get(url_api('users/{}/tokens'.format(login)), auth=(login, password), verify=False)
        r.raise_for_status()
        token = r.json()
        return token['sha1']

    @property
    def user(self):
        r = self.session.get(self.url_api('user'))
        r.raise_for_status()
        user = r.json()
        return user['username']

    def orgs(self):
        r  = self.session.get(self.url_api('user/orgs'))
        r.raise_for_status()
        return [o['username'] for o in r.json()]

    def connect(self):
        self.url_base, self.fqdn = self._url_parse(self.fqdn)
        verify = self.fqdn == 'try.gogs.io'
        #verify = True
        verify = self.config.get('verify', ['no','yes'][verify])
        if verify.lower().strip() in ('0','no','false',''):
            verify = False
        elif verify.lower().strip() in ('1','yes','true'):
            verify = True
        self.default_private = self.config.get('default_private', 'true').lower() not in ('0','no','false')
        self.ssh_url = self.config.get('ssh-url', None) or self.fqdn
        if not self.repository:
            config = git_config.GitConfigParser(os.path.join(os.environ['HOME'], '.gitconfig'), True)
        else:
            config = self.repository.config_reader()
        proxies = {}
        for scheme in 'http https'.split():
            proxy = config.get_value(scheme, 'proxy', '')
            if proxy:
                proxies[scheme] = proxy
        try:
            self.session = requests.Session()
            self.session.verify = verify
            self.session.proxies.update(proxies)
            if not verify:
                try:
                    import urllib3
                    urllib3.disable_warnings()
                except ImportError:
                    pass
            self.session.headers.update({'Authorization': 'token '+self._privatekey})
            self.username = self.user
        except requests.HTTPError as err:
            if err.response and err.response.status_code == 401:
                if not self._privatekey:
                    raise ConnectionError('Could not connect to GoGS. '
                                          'Please configure .gitconfig '
                                          'with your github private key.') from err
                else:
                    raise ConnectionError('Could not connect to GoGS. '
                                          'Check your configuration and try again.') from err
            else:
                raise err

    def create(self, user, repo, add=False):
        print('create(%r,%r,%r)' % (user, repo, add))
        args = dict(name=repo, private=self.default_private)
        try:
            if user != self.username:
                if user in self.orgs():
                    r = self.session.post(self.url_api('org/{}/repos'.format(user)), json=args)
                else:
                    raise ResourceNotFoundError("Namespace {} neither an organization or current user.".format(user))
            else:
                r = self.session.post(self.url_api('user/repos'), json=args)
        except requests.HTTPError as err:
            if err.response and err.response.status_code == 422:
                raise ResourceExistsError("Project already exists.") from err
            else: # pragma: no cover
                raise ResourceError("Unhandled error.") from err
        if add:
            self.add(user=self.username, repo=repo, tracking=self.name)

    def fork(self, user, repo):
        raise NotImplementedError

    def delete(self, repo, user=None):
        if not user:
            user = self.username
        r = self.session.delete(self.url_api('repos/{}/{}'.format(user, repo)))
        r.raise_for_status()

    def list(self, user, _long=False):
        import shutil, sys
        from datetime import datetime
        term_width = shutil.get_terminal_size((80, 20)).columns
        def col_print(lines, indent=0, pad=2):
            # prints a list of items in a fashion similar to the dir command
            # borrowed from https://gist.github.com/critiqjo/2ca84db26daaeb1715e1
            n_lines = len(lines)
            if n_lines == 0:
                return
            col_width = max(len(line) for line in lines)
            n_cols = int((term_width + pad - indent)/(col_width + pad))
            n_cols = min(n_lines, max(1, n_cols))
            col_len = int(n_lines/n_cols) + (0 if n_lines % n_cols == 0 else 1)
            if (n_cols - 1) * col_len >= n_lines:
                n_cols -= 1
            cols = [lines[i*col_len : i*col_len + col_len] for i in range(n_cols)]
            rows = list(zip(*cols))
            rows_missed = zip(*[col[len(rows):] for col in cols[:-1]])
            rows.extend(rows_missed)
            for row in rows:
                print(" "*indent + (" "*pad).join(line.ljust(col_width) for line in row))

        if user == self.username:
            r = self.session.get(self.url_api('user/repos'))
        elif user in self.orgs():
            r = self.session.get(self.url_api('orgs/{}/repos'.format(user)))
        else:
            raise ResourceNotFoundError("User {} does not exists.".format(user))

        r.raise_for_status()
        repositories = r.json()
        if not _long:
            repositories = list(repositories)
            col_print([repo['full_name'] for repo in repositories])
        else:
            print('Status\tCommits\tReqs\tIssues\tForks\tCoders\tWatch\tLikes\tLang\tModif\t\t\t\tName', file=sys.stderr)
            for repo in repositories:
                status = ''.join([
                    'F' if repo['fork'] else ' ',          # is a fork?
                    'P' if repo['private'] else ' ',       # is private?
                ])
                try:
                    r = self.session.get(self.url_api('repos/{}/issues'.format(repo['full_name'])))
                    issues = r.json()
                except Exception:
                    issues = []
                print('\t'.join([
                    # status
                    status,
                    # stats
                    str(len(list(()))),                    # number of commits
                    str(len(list(()))),                    # number of pulls
                    str(len(list(issues))),                # number of issues
                    str(repo.get('forks_count') or 0),     # number of forks
                    str(len(list(()))),                    # number of contributors
                    str(repo.get('watchers_count') or 0),  # number of subscribers
                    str(repo.get('stars_count') or 0),     # number of ♥
                    # info
                    repo.get('language') or '?',           # language
                    repo['updated_at'],                    # date
                    repo['full_name'],                     # name
                ]))

    def get_repository(self, user, repo):
        r = self.session.get(self.url_api('repos/{}/{}'.format(user, repo)))
        r.raise_for_status()
        repository = r.json()
        if not repository:
            raise ResourceNotFoundError('Repository {}/{} does not exists.'.format(user, repo))
        return repository

    def gist_list(self, gist=None):
        raise NotImplementedError

    def gist_fetch(self, gist, fname=None):
        raise NotImplementedError

    def gist_clone(self, gist):
        raise NotImplementedError

    def gist_create(self, gist_pathes, description, secret=False):
        raise NotImplementedError

    def gist_delete(self, gist_id):
        raise NotImplementedError

    def request_create(self, user, repo, local_branch, remote_branch, title, description=None):
        raise NotImplementedError

    def request_list(self, user, repo):
        raise NotImplementedError

    def request_fetch(self, user, repo, request, pull=False):
        raise NotImplementedError
