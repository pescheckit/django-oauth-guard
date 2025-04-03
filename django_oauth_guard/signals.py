"""
Custom signals for OAuth session validator.
"""

import django.dispatch

# Signal sent when a token validation fails
token_validation_failed = django.dispatch.Signal()

# Signal sent when a token is refreshed
token_refreshed = django.dispatch.Signal()

# Signal sent when a session fingerprint check fails
session_fingerprint_mismatch = django.dispatch.Signal()

# Signal sent when a session age exceeds the maximum
session_age_exceeded = django.dispatch.Signal()

# Signal sent when user inactivity timeout is reached
user_inactivity_timeout = django.dispatch.Signal()

# Signal sent when a token is expired
token_expired = django.dispatch.Signal()

# Signal sent when a system error occurs during validation
validation_system_error = django.dispatch.Signal()
