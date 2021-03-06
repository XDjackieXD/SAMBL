# SAML Samba Server Service

This little tool allows you to create yourself a user in a samba domain by login in with SAML and setting a password.
In the default configuration the passwords set this way will expire after one year so we don't have to deal with deactivating accounts of peoples who left the team.
  
The ACS URL is `https://your.domain/saml/acs` and the entity ID is `https://your.domain/saml/metadata.xml`.
It expects that no other entity creates samba accounts as it uses a file to keep track of UID numbers!
From SAML it expects the additional attributes `name` and `surname`.
The Username has to be a valid email address (if it isn't you'll have to change the line `username = auth_data.nameid.split('@')[0]` in `sambl.py` to match your SAML username to samba username mapping.
  
Dependencies are the samba python API, flask, flask-saml2, flask-wtf, werkzeug and urllib3
  
As this piece of software is feature complete for our usecase it won't see updates often.
I will maintain functionality with new samba and python versions though as we are actively using this piece of software for our internal fileserver.
