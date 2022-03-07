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