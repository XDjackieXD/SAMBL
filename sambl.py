#!/usr/bin/python
import sys
import os

from werkzeug.middleware.proxy_fix import ProxyFix

from flask import Flask, url_for
from flask_saml2.sp import ServiceProvider
from flask_saml2.sp.idphandler import IdPHandler
from flask_saml2.utils import certificate_from_string, private_key_from_string
import urllib.parse as urlparse
from urllib.parse import parse_qs
from typing import Optional

import getpass
import ldb
from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.dcerpc.security import dom_sid
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

#def _force_https():
#    from flask import _request_ctx_stack
#    if _request_ctx_stack is not None:
#        reqctx = _request_ctx_stack.top
#        reqctx.url_adapter.url_scheme = 'https'


class SamblServiceProvider(ServiceProvider):
    def get_logout_return_url(self):
        return url_for('index', _external=True)

    def get_default_login_return_url(self):
        return url_for('index', _external=True)

class SamblIdPHandler(IdPHandler):
    def make_login_request_url(self, relay_state: Optional[str] = None) -> str:
        """Make a LoginRequest url and query string for this IdP."""
        authn_request = self.get_authn_request()
        saml_request = self.encode_saml_string(authn_request.get_xml_string())

        parameters = [('SAMLRequest', saml_request)]
        parsed = urlparse.urlparse(self.get_idp_sso_url())
        for key,values in parse_qs(parsed.query).items():
            for value in values:
                parameters.append((key, value))
        if relay_state is not None:
            parameters.append(('RelayState', relay_state))

        url = parsed.scheme + "://" + parsed.netloc + parsed.path
        return self._make_idp_request_url(url, parameters)

sp = SamblServiceProvider()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1)
#app.before_request(_force_https)
app.config.from_envvar('SAMBL_SETTINGS')

app.config['SAML2_SP'] = {
    'certificate': certificate_from_string(app.config["SAML2_SP_CERTIFICATE"]),
    'private_key': private_key_from_string(app.config["SAML2_SP_PRIVATE_KEY"]),
}

app.config['SAML2_IDENTITY_PROVIDERS'] = [
    {
        'CLASS': 'sambl.SamblIdPHandler',
        'OPTIONS': {
            'display_name': app.config["SAML2_IDP_DISPLAY_NAME"],
            'entity_id': app.config["SAML2_IDP_ENTITY_ID"],
            'sso_url': app.config["SAML2_IDP_SSO_URL"],
            'slo_url': app.config["SAML2_IDP_SLO_URL"],
            'certificate': certificate_from_string(app.config["SAML2_IDP_CERTIFICATE"]),
        },
    },
]

#lp = LoadParm()
#creds = Credentials()
#creds.guess(lp)
#creds.set_username(app.config["SAMBA_USER"])
#creds.set_password(app.config["SAMBA_PASSWORD"])

#try:
#    samdb = SamDB(url=app.config["SAMBA_URL"], session_info=system_session(),credentials=creds, lp=lp)
#except ldb.LdbError as e:
#    print(e)

#except Exception as e:
#    exc_type, exc_obj, exc_tb = sys.exc_info()
#    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
#    print(exc_type, fname, exc_tb.tb_lineno)

#sambl.samdb.newuser(username="test", password="Changeme!", surname="testsn", givenname="testgiven", mailaddress="test@racing.tuwien.ac.at")
#samdb.connect(url=sambl.config.url)


@app.route('/')
def index():
    if sp.is_user_logged_in():
        auth_data = sp.get_auth_data_in_session()

        message = f'''
        <p>You are logged in as <strong>{auth_data.nameid}</strong>.
        The IdP sent back the following attributes:<p>
        '''

        attrs = '<dl>{}</dl>'.format(''.join(
            f'<dt>{attr}</dt><dd>{value}</dd>'
            for attr, value in auth_data.attributes.items()))

        logout_url = url_for('flask_saml2_sp.logout')
        logout = f'<form action="{logout_url}" method="POST"><input type="submit" value="Log out"></form>'

        return message + attrs + logout
    else:
        message = '<p>You are logged out.</p>'

        login_url = url_for('flask_saml2_sp.login')
        link = f'<p><a href="{login_url}">Log in to continue</a></p>'

        return message + link


app.register_blueprint(sp.create_blueprint(), url_prefix='/saml/')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
