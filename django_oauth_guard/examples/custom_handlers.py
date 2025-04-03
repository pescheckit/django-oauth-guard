"""
Example implementations of custom failure handlers and signal receivers.

This file provides examples of how to use Django OAuth Guard's
custom failure handlers and signals in your application.
"""

import logging

from django.contrib import messages
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.dispatch import receiver
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse

from django_oauth_guard.signals import (
    session_fingerprint_mismatch,
    token_refreshed,
    token_validation_failed,
    validation_system_error,
)

logger = logging.getLogger(__name__)


# Custom failure handlers


def handle_token_expired(request, result):
    """
    Custom handler for token expired failures.

    This handler checks if the request is an AJAX request and returns a JSON
    response if it is, otherwise it follows the standard redirect flow.
    """
    provider = result.get("provider", "unknown")
    user = request.user

    # Log the event
    logger.info(f"Token expired for user {user.email} with provider {provider}")

    # For AJAX/API requests, return a JSON response
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(
            {
                "error": "session_expired",
                "provider": provider,
                "message": f"Your {provider} session has expired. Please log in again.",
            },
            status=401,
        )

    # For regular requests, add a message and redirect
    messages.warning(
        request, f"Your {provider} authorization has expired. Please log in again."
    )
    logout(request)
    return HttpResponseRedirect(reverse("account_login"))


def handle_session_mismatch(request, result):
    """
    Custom handler for session fingerprint mismatch (potential session hijacking).

    This handler records details about the potential security incident
    before logging the user out.
    """
    user = request.user
    similarity = result.get("details", {}).get("similarity", 0)
    threshold = result.get("details", {}).get("threshold", 0.9)

    # Log the security incident with more details
    logger.warning(
        "Potential session hijacking detected for user %s. "
        "Fingerprint similarity: %s, Threshold: %s, IP: %s, "
        "User Agent: %s",
        user.email,
        similarity,
        threshold,
        request.META.get("REMOTE_ADDR", "unknown"),
        request.META.get("HTTP_USER_AGENT", "unknown"),
    )

    # Record the incident (example)
    SecurityIncident.objects.create(
        user=user,
        incident_type="session_hijacking",
        similarity=similarity,
        ip_address=request.META.get("REMOTE_ADDR", "unknown"),
        user_agent=request.META.get("HTTP_USER_AGENT", "unknown"),
    )

    # Notify security team for review
    notify_security_team(
        f"Potential session hijacking: {user.email}",
        f"User: {user.email}\n"
        f"Similarity: {similarity}\n"
        f"Threshold: {threshold}\n"
        f"IP: {request.META.get('REMOTE_ADDR', 'unknown')}\n"
        f"User Agent: {request.META.get('HTTP_USER_AGENT', 'unknown')}",
    )

    # Show a security message to the user
    messages.error(
        request,
        "A security issue was detected with your session. "
        "For your protection, you have been logged out. "
        "If you believe this is an error, please contact support.",
    )

    # Log the user out and redirect to login
    logout(request)
    return HttpResponseRedirect(reverse("account_login"))


def handle_inactivity_timeout(request, result):
    """
    Custom handler for user inactivity timeout.

    This handler provides a more user-friendly message and redirects
    the user back to their original page after login.
    """
    next_url = request.get_full_path()

    # Use a friendlier message for inactivity timeout
    messages.info(
        request,
        "Your session has timed out due to inactivity. "
        "Please log in again to continue where you left off.",
    )

    # Log the user out
    logout(request)

    # Redirect to login with next parameter
    return HttpResponseRedirect(f"{reverse('account_login')}?next={next_url}")


# Signal receivers


@receiver(token_validation_failed)
def handle_token_validation_failed(sender, request, user, account, token, **kwargs):
    """
    Handle signal when token validation fails.

    This could be due to revoked access or invalid tokens.
    """
    # Log the event
    logger.warning(
        "OAuth token validation failed for user %s with provider %s",
        user.email,
        account.provider,
    )

    # Record the incident for analysis
    SecurityIncident.objects.create(
        user=user, incident_type="token_validation_failed", provider=account.provider
    )

    # Optionally notify the user via email
    send_mail(
        f"Your {account.provider} connection needs attention",
        f"We've detected an issue with your {account.provider} connection to our app. "
        f"This might happen if you revoked access from {account.provider}. "
        f"Please log in again to reconnect your account.",
        "security@example.com",
        [user.email],
        fail_silently=True,
    )


@receiver(token_refreshed)
def handle_token_refreshed(sender, account, old_token, new_token, **kwargs):
    """
    Handle signal when a token is successfully refreshed.

    This can be used to update any cached data or perform
    actions that depend on the token.
    """
    user = account.user
    provider = account.provider

    # Log the token refresh event
    logger.info("Token refreshed for user %s with provider %s", user.email, provider)

    # Update last token refresh timestamp
    UserProfile.objects.filter(user=user).update(last_token_refresh=timezone.now())

    # If you store provider-specific data, update it with the new token
    if provider == "google":
        # Example: refresh user's Google calendar data with new token
        update_google_calendar(user, new_token.token)
    elif provider == "microsoft":
        # Example: refresh Microsoft Graph data
        update_microsoft_graph_data(user, new_token.token)


@receiver(session_fingerprint_mismatch)
def log_fingerprint_mismatch(sender, request, user, similarity, threshold, **kwargs):
    """Log details about fingerprint mismatches for security auditing."""
    logger.warning(
        "Session fingerprint mismatch for user %s. "
        "Similarity: %s, Threshold: %s, IP: %s, User Agent: %s",
        user.email,
        similarity,
        threshold,
        request.META.get("REMOTE_ADDR", "unknown"),
        request.META.get("HTTP_USER_AGENT", "unknown"),
    )

    # Record metrics for analysis
    record_security_metric(
        "fingerprint_mismatch", user=user, similarity=similarity, threshold=threshold
    )


@receiver(validation_system_error)
def handle_system_error(sender, request, user, error, **kwargs):
    """Handle unexpected system errors during validation."""
    logger.error(
        "System error during security validation for user %s: %s",
        user.email,
        str(error),
    )

    # Alert operations team about the system error
    # Example function call - replace with your actual notification system
    # notify_ops_team(
    #     f"OAuth validation error for user {user.email}",
    #     f"Error: {str(error)}\n" f"User: {user.email}\n" f"Time: {timezone.now()}",
    # )


# Helper functions (would be implemented in your application)


def notify_security_team(subject, message):
    """Notify security team about security incidents."""
    # Implementation could send emails, Slack notifications, etc.
    logger.warning(f"Security notification: {subject}")

    # Example: Send email to security team
    send_mail(
        f"[SECURITY] {subject}",
        message,
        "security-alerts@example.com",
        ["security-team@example.com"],
        fail_silently=True,
    )


def record_security_metric(metric_name, **data):
    """Record security metrics for monitoring and analysis."""
    # Implementation would depend on your metrics system
    logger.info(f"Security metric: {metric_name} - {data}")


def update_google_calendar(user, token):
    """Update user's Google calendar data with new token."""
    # Implementation would use the Google Calendar API with the new token
    logger.info(f"Updating Google Calendar data for user {user.email}")


def update_microsoft_graph_data(user, token):
    """Update Microsoft Graph data with new token."""
    # Implementation would use the Microsoft Graph API with the new token
    logger.info(f"Updating Microsoft Graph data for user {user.email}")


# Sample models referenced in the examples (would be in your models.py)


class SecurityIncident:
    """Example model for security incidents."""

    objects = type("", (), {"create": lambda **kwargs: None})()


class UserProfile:
    """Example model for user profiles."""

    objects = type(
        "",
        (),
        {"filter": lambda user: type("", (), {"update": lambda **kwargs: None})()},
    )()


# Timezone module mock for examples
timezone = type("", (), {"now": lambda: None})()
