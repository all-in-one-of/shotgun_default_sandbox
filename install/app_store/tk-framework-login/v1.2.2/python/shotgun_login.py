# Copyright (c) 2013 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

from urlparse import urlparse

# package shotgun_api3 until toolkit upgrades to a version that
# allows for user based logins
from .shotgun_api3 import Shotgun, MissingTwoFactorAuthenticationFault, AuthenticationFault

from .login import Login
from .login import LoginError

from .login_dialog_sg import LoginDialog

from .qt_abstraction import QtCore


################################################################################
# Shotgun Login Implementation
class ShotgunLogin(Login):
    def __init__(self):
        """ Override the default constructor """
        Login.__init__(self, LoginDialog)
        self._http_proxy = None

    def set_default_login(self, login):
        """
        Set the default value for the login field in the login dialog.

        :param login: A string to set the field to
        """
        self._dialog_kwargs["default_login"] = login

    def set_default_site(self, site):
        """
        Set the default value for the site field in the login dialog.

        :param login: A string to set the field to
        """
        self._dialog_kwargs["default_site"] = site

    def set_http_proxy(self, http_proxy):
        """
        Set the proxy to use when connecting to Shotgun.

        :param http_proxy: A string which will be passed to the Shotgun constructor
            as documented here:
            https://github.com/shotgunsoftware/python-api/wiki/Reference%3A-Methods#shotgun
        """
        self._http_proxy = http_proxy

    def get_http_proxy(self):
        """
        Get the proxy to use when connecting to Shotgun.

        :returns: The proxy string.
        """
        return self._http_proxy 

    def get_login(self, site=None, dialog_message=None, force_dialog=False):
        """ Returns the HumanUser for the current login.  Acts like login otherwise. """
        results = self.login(site, dialog_message, force_dialog)
        if results:
            return results["login"]
        return None

    def get_connection(self, site=None, dialog_message=None, force_dialog=False):
        """ Returns the connection for the current login.  Acts like login otherwise. """
        results = self.login(site, dialog_message, force_dialog)
        if results:
            return results.get("connection")
        return None

    def _get_keyring_values(self, site, login):
        """
        Override the base class implementation to always use a specific keyring
        but encode the site in the login.
        """
        keyring = "com.shotgunsoftware.tk-framework-shotgunlogin"
        parse = urlparse(site)
        login = "%s@%s" % (login, parse.netloc)
        return (keyring, login)

    def _get_settings(self, group=None):
        """
        Override the base class implementation to always use a specific
        organization and application for the QSettings.
        """
        settings = QtCore.QSettings("Shotgun Software", "Shotgun Login Framework")

        if group is not None:
            settings.beginGroup(group)
        return settings

    # Magic string that allows us to detect if we only have a password or both password and session token.
    # Don't you dare use that string at the beginning of your password.
    _MAGIC_STRING = "SG_S3SSI0N_AND_P4SSW0RD"
    # Multi character separator with random chars to reduce the risk of a collision in a session token.
    _SEPARATOR = "%$!@"

    def mangle_password(self, password):
        session_token = self.get_login_info()["connection"].config.session_token
        if session_token:
            return self._MAGIC_STRING + self._SEPARATOR + session_token + self._SEPARATOR + password
        else:
            return password

    def unmangle_password(self, mangled):
        if not mangled:
            return None, None
        if not mangled.startswith(self._MAGIC_STRING):
            return mangled, None
        else:
            session_token_start = mangled.find(self._SEPARATOR) + len(self._SEPARATOR)
            session_token_end = mangled.find(self._SEPARATOR, session_token_start)
            password_start = session_token_end + len(self._SEPARATOR)
            session_token = mangled[session_token_start: session_token_end]
            password = mangled[password_start:]
            return password, session_token

    def _get_human_user(self, connection, login):
        return connection.find_one(
            'HumanUser',
            [['sg_status_list', 'is', 'act'], ['login', 'is', login]], ['id', 'login'], '', 'all'
        )

    def _site_connect(self, site, login, password, auth_token=None):
        """
        Authenticate the given values in Shotgun.

        :param site: The site to login to
        :param login: The login to use
        :param password: The password to use

        :returns: A tuple of (connection, login) if successful, where connection
            is a valid Shotgun connection to site, logged in as login, and login
            is a HumanUser dictionary of the Entity on the Shotgun site representing
            this login.

        :raises: LoginError on failure.
        """
        # try to connect to Shotgun
        try:
            # make sure that the inputs to Shotgun are encoded with a supported encoding
            if site:
                site = site.encode("utf-8")
            if login:
                login = login.encode("utf-8")
            if password:
                password = password.encode("utf-8")
            if self._http_proxy:
                http_proxy = self._http_proxy.encode("utf-8")
            else:
                http_proxy = self._http_proxy

            password, session_token = self.unmangle_password(password)

            # If an 2fa token was passed in, we can assume there's a password to test as well.
            user = None
            if auth_token:
                # connect and force an exchange so the authentication is validated. Also, generate a
                # session token to save since 2fa code are volatile.
                connection = Shotgun(site, login=login, password=password, http_proxy=http_proxy, auth_token=auth_token)
                user = self._get_human_user(connection, login)
                session_token = connection.get_session_token()
            else:
                # If we have a session token, we have to try it first.
                if session_token:
                    try:
                        # connect and force an exchange so the authentication is validated
                        connection = Shotgun(site, session_token=session_token, http_proxy=http_proxy)
                        user = self._get_human_user(connection, login)
                    except AuthenticationFault, e:
                        # If we fail authenticating with a session token, we can ignore the error
                        # and we'll simply move to to next authentication strategy.
                        pass
                if not user:
                    # connect and force an exchange so the authentication is validated
                    connection = Shotgun(site, login=login, password=password, http_proxy=http_proxy)
                    user = self._get_human_user(connection, login)
        except MissingTwoFactorAuthenticationFault:
            raise LoginError("Missing two factor authentication.")
        except Exception, e:
            raise LoginError(str(e))

        if user is None:
            raise LoginError("login not valid.")
        return {"connection": connection, "login": user, "session_token": session_token}
