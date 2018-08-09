from requests_oauthlib import OAuth2Session
from tornado import gen
from jupyterhub.auth import Authenticator
from globus_sdk import ConfidentialAppAuthClient
from jupyterhub.handlers import LogoutHandler
from traitlets import List, Unicode, Bool

import json
import sys, subprocess
import re
import globus_sdk

from oauthenticator.globus import LocalGlobusOAuthenticator
c.JupyterHub.authenticator_class = LocalGlobusOAuthenticator
c.LocalGlobusOAuthenticator.enable_auth_state = True
c.LocalGlobusOAuthenticator.oauth_callback_url = 'https://128.135.158.176:8080/hub/oauth_callback'
c.LocalGlobusOAuthenticator.client_id = "d1b57f33-a45c-46e1-9a0c-f5420940dacf"
c.LocalGlobusOAuthenticator.client_secret = "YfcI+zz7YamlUI7Rjgh/WnM9ygaa1RTUGJZbkpWw3JI="

c.LocalGlobusOAuthenticator.create_system_users = True
c.LocalGlobusOAuthenticator.add_user_cmd = ['adduser', '-m', '-c', '""']

c.LocalGlobusOAuthenticator.globus_authorizer = globus_sdk.RefreshTokenAuthorizer
c.JupyterHub.extra_log_file = '/var/log/jupyterhub.log'