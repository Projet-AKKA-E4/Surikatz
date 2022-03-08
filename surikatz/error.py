"""
    Module with custom Exception classes
"""

class IPError(ValueError):
    """
        Exception generated when an IP address is misformed
    """

class FQDNError(Exception):
    """
        Exception generated when an FQDN address is misformed
    """

class APIError(Exception):
    """
        Exception generated when an API is unreachable
    """

class AppNotInstalled(Exception):
    """
        Exception generated when an app isn't installed on the user device
    """