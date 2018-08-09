"""
Custom Authenticator to use Globus OAuth2 with JupyterHub
"""
import os, sys, subprocess, re
import pickle
import base64

from tornado import gen, web
from tornado.auth import OAuth2Mixin
from tornado.web import HTTPError

from traitlets import List, Unicode, Bool, Instance, Any
from jupyterhub.handlers import LogoutHandler
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthenticator


try:
    import globus_sdk
except:
    raise ImportError('globus_sdk is not installed, please see '
                      '"globus-requirements.txt" for using Globus oauth.')


class GlobusMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = 'https://auth.globus.org/v2/oauth2/authorize'


class GlobusLoginHandler(OAuthLoginHandler, GlobusMixin):
    pass


class GlobusLogoutHandler(LogoutHandler):
    """
    Handle custom logout URLs and token revocation. If a custom logout url
    is specified, the 'logout' button will log the user out of that identity
    provider in addition to clearing the session with Jupyterhub, otherwise
    only the Jupyterhub session is cleared.
    """
    @gen.coroutine
    def get(self):
        user = self.get_current_user()
        if user:
            if self.authenticator.revoke_tokens_on_logout:
                self.clear_tokens(user)
            self.clear_login_cookie()
        if self.authenticator.logout_redirect_url:
            self.redirect(self.authenticator.logout_redirect_url)
        else:
            super().get()

    @gen.coroutine
    def clear_tokens(self, user):
        if not self.authenticator.revoke_tokens_on_logout:
            return

        state = yield user.get_auth_state()
        if state:
            self.authenticator.revoke_service_tokens(state.get('tokens'))
            self.log.info('Logout: Revoked tokens for user "{}" services: {}'
                          .format(user.name, ','.join(state['tokens'].keys())))
            state['tokens'] = ''
            user.save_auth_state(state)


class GlobusOAuthenticator(OAuthenticator):
    """The Globus OAuthenticator handles both authorization and passing
    transfer tokens to the spawner. """


    login_service = 'Globus'
    login_handler = GlobusLoginHandler
    logout_handler = GlobusLogoutHandler

    identity_provider = Unicode(help="""Restrict which institution a user
    can use to login (GlobusID, University of Hogwarts, etc.). This should
    be set in the app at developers.globus.org, but this acts as an additional
    check to prevent unnecessary account creation.""").tag(config=True)

    def _identity_provider_default(self):
        return os.getenv('IDENTITY_PROVIDER', 'globusid.org')

    exclude_tokens = List(
        help="""Exclude tokens from being passed into user environments
        when they start notebooks, Terminals, etc."""
    ).tag(config=True)

    def _exclude_tokens_default(self):
        return ['auth.globus.org']

    def _scope_default(self):
        return [
            'openid',
            'profile',
            'email'
        ]

    allow_refresh_tokens = Bool(
        help="""Allow users to have Refresh Tokens. If Refresh Tokens are not
        allowed, users must use regular Access Tokens which will expire after
        a set time. Set to False for increased security, True for increased
        convenience."""
    ).tag(config=True)

    def _allow_refresh_tokens_default(self):
        return True

    globus_local_endpoint = Unicode(help="""If Jupyterhub is also a Globus
    endpoint, its endpoint id can be specified here.""").tag(config=True)

    def _globus_local_endpoint_default(self):
        return os.getenv('GLOBUS_LOCAL_ENDPOINT', '')

    logout_redirect_url = \
        Unicode(help="""URL for logging out.""").tag(config=True)

    def _logout_redirect_url_default(self):
        return os.getenv('LOGOUT_REDIRECT_URL', '')

    revoke_tokens_on_logout = Bool(
        help="""Revoke tokens so they cannot be used again. Single-user servers
        MUST be restarted after logout in order to get a fresh working set of
        tokens."""
    ).tag(config=True)

    def _revoke_tokens_on_logout_default(self):
        return True

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Add tokens to the spawner whenever the spawner starts a notebook.
        This will allow users to create a transfer client:
        globus-sdk-python.readthedocs.io/en/stable/tutorial/#tutorial-step4
        """
        spawner.environment['GLOBUS_LOCAL_ENDPOINT'] = \
            self.globus_local_endpoint
        state = yield user.get_auth_state()
        if state:
            globus_data = base64.b64encode(
                pickle.dumps(state)
            )
            spawner.environment['GLOBUS_DATA'] = globus_data.decode('utf-8')

    
    globus_authorizer = Any(
        help="""Define which authorizer to use in order to generate client.
        For ex: RefreshTokenAuth for when using VC3 client specific."""
    ).tag(config=True)

    def _globus_authorizer_default(self):
        return globus_sdk.RefreshTokenAuthorizer("TEST", self.globus_portal_client())

    def globus_portal_client(self):
        return globus_sdk.ConfidentialAppAuthClient(
            self.client_id,
            self.client_secret)


    def getUsername(self, sub):
        cmd = 'vc3-client user-list | grep ' + sub
        proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
        out, err = proc.communicate()

        if (out == ""): 
            print("Invalid user", file=sys.stderr)
        else:
            out = out.decode('utf-8')
            username = re.search('\sname=([^\s]+)', out).group(1)
            return username

    def getRefreshToken(self, username):
        cmd = 'vc3-client user-list | grep ' + username
        proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
        out, err = proc.communicate()

        if (out == ""): 
            print("Invalid user", file=sys.stderr)
        else:
            out = out.decode('utf-8')
            refresh_token = re.search('\surl=([^\s]+)', out).group(1)
            return refresh_token

    def isUserInProject(self, user, project):

        cmd = 'vc3-client project-list | grep ' + project
        proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
        out, err = proc.communicate()

        if (out == ""): 
            print("Invalid project", file=sys.stderr)
        else:
            out = out.decode('utf-8')
            members = re.search('\smembers=([^\s]+)', out).group(1)
           
            if user in members:
                return True

            return False


    @gen.coroutine
    def authenticate(self, handler, data=None):
        """
        Authenticate with globus.org. Usernames (and therefore Jupyterhub
        accounts) will correspond to a Globus User ID, so foouser@globusid.org
        will have the 'foouser' account in Jupyterhub.
        """

        vc3_token = False
        if (vc3_token):
            internal_auth_client = self.globus_portal_client()
            #refresh_authorizer = globus_sdk.RefreshTokenAuthorizer(self.getRefreshToken(), conf_client)
            REFRESH_TOKEN = "AgzX2xzmxObyzdd6YVrlJdpkyqE5xNJExXEvVXKNa4PjPjwWmWTyUQVKkavKx5Gar7d9yDVb7elb5MG6pNr3XwrnWzWk4"
            refresh_authorizer = self.globus_authorizer(REFRESH_TOKEN, internal_auth_client)
            
            client = globus_sdk.AuthClient(authorizer=refresh_authorizer)
           
            info = client.oauth2_userinfo()
            sub = info['sub']

            username = self.getUsername(sub)
            
            if self.isUserInProject(username, "vc3"):
                return username
            else: 
                raise HTTPError(
                    403,
                    'This site is restricted to accounts that belong to VC3 project'
                )
                
        else: 
            code = handler.get_argument("code")
            redirect_uri = self.get_callback_url(self)

            client = self.globus_portal_client()
            client.oauth2_start_flow(
                redirect_uri,
                requested_scopes=' '.join(self.scope),
                refresh_tokens=True
            )

            self.log.info("request refresh token %s" % self.allow_refresh_tokens)
            
            # Doing the code for token for id_token exchange
            tokens = client.oauth2_exchange_code_for_tokens(code)
            id_token = tokens.decode_id_token(client)
            # It's possible for identity provider domains to be namespaced
            # https://docs.globus.org/api/auth/specification/#identity_provider_namespaces # noqa
            username, domain = id_token.get('preferred_username').split('@', 1)

            print("\n tokens: {}".format(str(tokens)), file=sys.stdout)

            if self.identity_provider and domain != self.identity_provider:
                raise HTTPError(
                    403,
                    'This site is restricted to {} accounts. Please link your {}'
                    ' account at {}.'.format(
                        self.identity_provider,
                        self.identity_provider,
                        'globus.org/app/account'
                        )
                )
            return {
                'name': username,
                'auth_state': {
                    'client_id': self.client_id,
                    'tokens': {
                        tok: v for tok, v in tokens.by_resource_server.items()
                        if tok not in self.exclude_tokens
                    },
                }
            }

    def revoke_service_tokens(self, services):
        """Revoke live Globus access and refresh tokens. Revoking inert or
        non-existent tokens does nothing. Services are defined by dicts
        returned by tokens.by_resource_server, for example:
        services = { 'transfer.api.globus.org': {'access_token': 'token'}, ...
            <Additional services>...
        }
        """
        client = self.globus_portal_client()
        for service_data in services.values():
            client.oauth2_revoke_token(service_data['access_token'])
            client.oauth2_revoke_token(service_data['refresh_token'])

    def get_callback_url(self, handler=None):
        """
        Getting the configured callback url
        """
        if self.oauth_callback_url is None:
            raise HTTPError(500,
                            'No callback url provided. '
                            'Please configure by adding '
                            'c.GlobusOAuthenticator.oauth_callback_url '
                            'to the config'
                            )
        return self.oauth_callback_url

    def logout_url(self, base_url):
        return url_path_join(base_url, 'logout')

    def get_handlers(self, app):
        return super().get_handlers(app) + [(r'/logout', self.logout_handler)]


class LocalGlobusOAuthenticator(LocalAuthenticator, GlobusOAuthenticator):
    """A version that mixes in local system user creation"""
    pass