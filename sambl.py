#!/usr/bin/python
import sys
import os
import re

from werkzeug.middleware.proxy_fix import ProxyFix

from flask import Flask, url_for, request, render_template, flash, session
from flask_saml2.sp import ServiceProvider
from flask_saml2.sp.idphandler import IdPHandler
from flask_saml2.utils import certificate_from_string, private_key_from_string
import urllib.parse as urlparse
from urllib.parse import parse_qs
from typing import Optional
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
from wtforms.csrf.session import SessionCSRF

import getpass
import ldb
from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.dcerpc.security import dom_sid
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

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

app.register_blueprint(sp.create_blueprint(), url_prefix='/saml/')

email_pattern = re.compile(r"^(?:[a-zA-Z0-9!#$%&'^_`{}~-]+(?:\.[a-zA-Z0-9!#$%&'^_`{|}~-]+)*)@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$")

lp = LoadParm()
creds = Credentials()
creds.guess(lp)
creds.set_username(app.config["SAMBA_USER"])
creds.set_password(app.config["SAMBA_PASSWORD"])

samdb = None
try:
    samdb = SamDB(url=app.config["SAMBA_URL"], session_info=system_session(),credentials=creds, lp=lp)
except ldb.LdbError as e:
    print(e)
    sys.exit()


#except Exception as e:
#    exc_type, exc_obj, exc_tb = sys.exc_info()
#    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
#    print(exc_type, fname, exc_tb.tb_lineno)

#sambl.samdb.newuser(username="test", password="Changeme!", surname="testsn", givenname="testgiven", mailaddress="test@racing.tuwien.ac.at")
#samdb.connect(url=sambl.config.url)

class ReusableForm(Form):
    #password = TextField('Password:', validators=[validators.DataRequired(), validators.Length(min=8, max=4096), validators.Regexp("""^(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[0-9])(?=.*?[#!@$%^&*()\-_+={}[\]|\\:;"'<>,.?\/]).{8,}$""")])
    password = TextField('Password:', validators=[validators.DataRequired(), validators.Length(min=8, max=4096), validators.Regexp(r"(?=^.{8,}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))^.*")])
    class Meta:
        csrf = True
        csrf_secret = app.config["CSRF_SECRET"]
        csrf_class = SessionCSRF
        @property
        def csrf_context(self):
            return session

@app.route('/', methods=['GET', 'POST'])
def index():
    if sp.is_user_logged_in():
        auth_data = sp.get_auth_data_in_session()
        saml_items = auth_data.attributes

        form = ReusableForm(request.form)
        if request.method == 'POST':
            if form.validate():
                if ("name" in saml_items) and ("surname" in saml_items):
                    if re.match(email_pattern, auth_data.nameid):
                        username = auth_data.nameid.split('@')[0]
                        givenname = saml_items["name"]
                        surname = saml_items["surname"]
                        password = request.form['password']
                        email = auth_data.nameid
                        
                        # set data in samba
                        while(True):
                            try:
                                samdb.newuser(username=username, password=password, surname=surname, givenname=givenname, mailaddress=email)
                                flash("Password set successfully")
                            except ldb.LdbError as e:
                                print(e)

                                if ("LDAP_ENTRY_ALREADY_EXISTS" in e[1]):
                                    flash("Error: Password set failed (user already exists and create was tried instead of modify).")
                                    break

                                try:
                                    samdb.connect(url=app.config["SAMBA_URL"])
                                    continue
                                except ldb.LdbError as e:
                                    print(e)
                                    flash("Error: Password set failed due to an internal error!")
                                    break
                                flash("Error: Password set failed due to an internal error!")
                            except Exception as e:
                                print(e)
                                flash("Error: Password set failed due to an internal error!")
                                break

                    else:
                        flash("Error: E-Mail address is not valid as an Windows domain account name (does it contain any of \"/\\[]:;|=,+*?<> or other special characters?).")
                else:
                    flash("Error: Name or surname not set or contains invalid characters")
                    print(saml_items["name"])
                    print(saml_items["surname"])
            else:
                flash('Error: Password does not meet complexity criteria')

        #logout_url = url_for('flask_saml2_sp.logout')
        #logout = f'<form action="{logout_url}" method="POST"><input type="submit" value="Log out"></form>'

        return render_template('set.html', form=form)
    else:
        message = '<p>You are logged out.</p>'

        login_url = url_for('flask_saml2_sp.login')
        link = f'<p><a href="{login_url}">Log in to continue</a></p>'

        return message + link




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
