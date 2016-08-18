# Copyright (c) 2013 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.


def get_keyring_store():
    """
    Return the appropriate keyring implementation for the current environment.
    """
    try:
        from .keyring_store import KeyringKeyringStore, keyring_module

        # Grab the priority of the default keyring implementation
        default_priority = keyring_module.get_keyring().priority

        # Grab the priority of the Gnome keyring implementation
        try:
            # Use the underlying algorithm Gnome uses to check priority to avoid
            # the exception if the GnomeKeyring is not available to the general
            # Gnome python module
            gnome_priority = int(keyring_module.backends.Gnome.Keyring.has_requisite_vars())
        except Exception:
            gnome_priority = 0

        # If default priority is less then Gnome priority
        if default_priority < gnome_priority:
            # Try to load our own Gnome implementation
            try:
                from .gnomekeyring_store import GnomeKeyringStore
                return GnomeKeyringStore
            except ImportError:
                pass

        # Priority is either higher than GnomeKeyring or GnomeKeyring could not import
        return KeyringKeyringStore
    except ImportError:
        pass

    raise RuntimeError("No keyring store available")
