# Copyright (c) 2013 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

"""
QT Login dialog for authenticating to a Shotgun server.

--------------------------------------------------------------------------------
NOTE! This module is part of the authentication library internals and should
not be called directly. Interfaces and implementation of this module may change
at any point.
--------------------------------------------------------------------------------
"""

from .ui import resources_rc
# START OF CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK
from .ui import login_dialog_sg
from . import LoginError
from .qt_abstraction import QtGui, QtCore
from shotgun_api3 import MissingTwoFactorAuthenticationFault
# END OF CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK


class LoginDialog(QtGui.QDialog):
    """
    Dialog for getting user credentials.
    """

    # Formatting required to display error messages.
    ERROR_MSG_FORMAT = "<font style='color: rgb(252, 98, 70);'>%s</font>"

    # START OF CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK
    def __init__(self, login, parent=None, **kwargs):
        """
        Constructor
        """
        QtGui.QDialog.__init__(self, parent)

        self._is_session_renewal = False

        # setup the gui
        self.ui = login_dialog_sg.Ui_LoginDialog()
        self.ui.setupUi(self)

        # initialize variables
        self._login = login
        self._default_site = kwargs.get("default_site") or ""
        self._default_login = kwargs.get("default_login") or ""

        if not kwargs.get("show_site", True):
            self.ui.site.hide()

        if "title" in kwargs:
            self.setWindowTitle(kwargs["title"])

        # set the logo
        pixmap = kwargs.get("pixmap")
        if not pixmap:
            pixmap = QtGui.QPixmap(":/tk-framework-login/shotgun_logo_light_medium.png")
        self.ui.logo.setPixmap(pixmap)

        hostname, login, password = self._login._get_saved_values()

        password, _ = self._login.unmangle_password(password)

        hostname = hostname or kwargs.get("default_site") or ""
        login = login or kwargs.get("default_login") or ""

        self.ui.site.setText(hostname)
        self.ui.login.setText(login)
        self.ui.password.setText(password)

        # Set the focus appropriately on the topmost line edit that is empty.
        if self.ui.site.text():
            if self.ui.login.text():
                self.ui.password.setFocus(QtCore.Qt.OtherFocusReason)
            else:
                self.ui.login.setFocus(QtCore.Qt.OtherFocusReason)
        else:
            # If we don't even have a host, pre-fill the field with a friendly
            # value and selection.
            self.ui.site.setText("https://mystudio.shotgunstudio.com")
            # This will select mystudio, making it easy to type something else
            self.ui.site.setSelection(8, 8)
            self.ui.site.setFocus(QtCore.Qt.OtherFocusReason)

        # END OF THE CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK

        # Select the right first page.
        self.ui.stackedWidget.setCurrentWidget(self.ui.login_page)

        # hook up signals
        self.ui.sign_in.clicked.connect(self._ok_pressed)
        self.ui.stackedWidget.currentChanged.connect(self._current_page_changed)

        self.ui.verify_2fa.clicked.connect(self._verify_2fa_pressed)
        self.ui.use_backup.clicked.connect(self._use_backup_pressed)

        self.ui.verify_backup.clicked.connect(self._verify_backup_pressed)
        self.ui.use_app.clicked.connect(self._use_app_pressed)

        self.ui.forgot_password_link.linkActivated.connect(self._link_activated)

    def _link_activated(self, site):
        """
        Clicked when the user presses on the "Forgot your password?" link.
        """
        # Don't use the URL that is set in the link, but the URL set in the
        # text box.
        site = self.ui.site.text()

        # Give visual feedback that we are patching the URL before invoking
        # the desktop services. Desktop Services requires HTTP or HTTPS to be
        # present.
        if len(site.split("://")) == 1:
            site = "https://%s" % site
            self.ui.site.setText(site)

        # Launch the browser
        forgot_password = "%s/user/forgot_password" % site
        if not QtGui.QDesktopServices.openUrl(forgot_password):
            self._set_error_message(
                self.ui.message, "Can't open '%s'." % forgot_password
            )

    def _current_page_changed(self, index):
        """
        Resets text error message on the destination page.
        :param index: Index of the page changed.
        """
        if self.ui.stackedWidget.indexOf(self.ui._2fa_page) == index:
            self.ui.invalid_code.setText("")
        elif self.ui.stackedWidget.indexOf(self.ui.backup_page) == index:
            self.ui.invalid_backup_code.setText("")

    def _disable_text_widget(self, widget, tooltip_text):
        """
        Disables a widget and adds tooltip to it.
        :param widget: Text editing widget to disable.
        :param toolkit_text: Tooltip text that explains why the widget is disabled.
        """
        widget.setReadOnly(True)
        widget.setEnabled(False)
        widget.setToolTip(tooltip_text)

    def set_message(self, message):
        """
        Set the message in the dialog. For compatibility with non sg dialog.
        :param message: Message to display in the dialog.
        """
        self._set_login_message(message)

    def _set_login_message(self, message):
        """
        Set the message in the dialog.
        :param message: Message to display in the dialog.
        """
        self.ui.message.setText(message)

    def exec_(self):
        """
        Displays the window modally.
        """
        self.show()
        self.raise_()
        self.activateWindow()

        # the trick of activating + raising does not seem to be enough for
        # modal dialogs. So force put them on top as well.
        self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint | self.windowFlags())
        return QtGui.QDialog.exec_(self)

    def result(self):
        """
        Displays a modal dialog asking for the credentials.
        :returns: A tuple of (hostname, username and session token) string if the user authenticated
                  None if the user cancelled.
        """
        if self.exec_() == QtGui.QDialog.Accepted:
            return (self.ui.site.text().encode("utf-8"),
                    self.ui.login.text().encode("utf-8"),
                    self._new_session_token)
        else:
            return None

    def _set_error_message(self, widget, message):
        """
        Set the error message in the dialog.

        :param widget: Widget to display the message on.
        :param message: Message to display in red in the dialog.
        """
        widget.setText(self.ERROR_MSG_FORMAT % message)

    def _ok_pressed(self):
        """
        validate the values, accepting if login is successful and display an error message if not.
        """
        # pull values from the gui
        site = self.ui.site.text()
        login = self.ui.login.text()
        password = self.ui.password.text()

        if len(site) == 0:
            self._set_error_message(self.ui.message, "Please enter the address of the site to connect to.")
            return
        if len(login) == 0:
            self._set_error_message(self.ui.message, "Please enter your login name.")
            return
        if len(password) == 0:
            self._set_error_message(self.ui.message, "Please enter your password.")
            return

        # if not protocol specified assume https
        if len(site.split("://")) == 1:
            site = "https://%s" % site
            self.ui.site.setText(site)

        try:
            self._authenticate(self.ui.message, site, login, password)
        except MissingTwoFactorAuthenticationFault:
            # We need a two factor authentication code, move to the next page.
            self.ui.stackedWidget.setCurrentWidget(self.ui._2fa_page)
        except Exception, e:
            self._set_error_message(self.ui.message, "%s:  %s" % (e[0], e[1]))
            raise

    def _authenticate(self, error_label, site, login, password, auth_code=None):
        """
        Authenticates the user using the passed in credentials.

        :param error_label: Label to display any error raised from the authentication.
        :param site: Site to connect to.
        :param login: Login to use for that site.
        :param password: Password to use with the login.
        :param auth_code: Optional two factor authentication code.

        :raises MissingTwoFactorAuthenticationFault: Raised if auth_code was None but was required
            by the server.
        """
        try:
            # set the wait cursor
            QtGui.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
            QtGui.QApplication.processEvents()

            # START OF THE CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK
            self._login._check_values(site, login, password, auth_token=auth_code)

        except LoginError, e:
            # login framework swallows all exception types, so capture the text
            # of the error and if it's a 2fa exception rethrow a 2fa error to be compatible
            # with how the dialog was originally implemented in core.
            if "two factor authentication" in str(e):
                raise MissingTwoFactorAuthenticationFault
            # authentication did not succeed
            self._set_error_message(error_label, "%s:  %s" % (e[0], e[1]))
            return
        # END OF THE CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK
        finally:
            # restore the cursor
            QtGui.QApplication.restoreOverrideCursor()
            # dialog is done
            QtGui.QApplication.processEvents()

        # START OF THE CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK
        # all good, save the settings if requested and return accepted
        try:
            site = self.ui.site.text()
            login = self.ui.login.text()
            password = self.ui.password.text()

            # mangle the password before saving.
            mangled_password = self._login.mangle_password(password)
            self._login._save_values(site, login, mangled_password)
        except LoginError:
            # if saving the settings does not work, simply continue without them saved
            pass

        self.accept()
        # END OF THE CHANGES TO BE COMPATIBLE WITH THE LOGIN FRAMEWORK

    def _verify_2fa_pressed(self):
        """
        Called when the Verify button is pressed on the 2fa page.
        """
        self._verify_pressed(self.ui._2fa_code.text(), self.ui.invalid_code)

    def _verify_backup_pressed(self):
        """
        Called when the Verify button is pressed on the backup codes page.
        """
        self._verify_pressed(self.ui.backup_code.text(), self.ui.invalid_backup_code)

    def _verify_pressed(self, code, error_label):
        """
        Validates the code, dismissing the dialog if the login is succesful and displaying an error
        if not.
        :param code: Code entered by the user.
        :param error_label: Label to update if the code is invalid.
        """
        if not code:
            self._set_error_message(error_label, "Please enter your code.")
            return

        site = self.ui.site.text()
        login = self.ui.login.text()
        password = self.ui.password.text()

        try:
            self._authenticate(error_label, site, login, password, code)
        except Exception, e:
            self._set_error_message(self.ui.message, str(e))
            raise

    def _use_backup_pressed(self):
        """
        Switches to the backup codes page.
        """
        self.ui.stackedWidget.setCurrentWidget(self.ui.backup_page)

    def _use_app_pressed(self):
        """
        Switches to the main two factor authentication page.
        """
        self.ui.stackedWidget.setCurrentWidget(self.ui._2fa_page)
