"""
Example implementation of a custom OAuth provider for Django OAuth Guard.

This file demonstrates how to implement validator and refresher functions
for a custom OAuth provider and register them with Django OAuth Guard.
"""

import json
import logging
from datetime import timedelta

import requests
from django.utils import timezone

logger = logging.getLogger(__name__)


def validate_discord_token(access_token):
    """
    Validate a Discord OAuth token by calling Discord's API.

    Args:
        access_token: The Discord access token to validate

    Returns:
        bool: True if the token is valid, False otherwise
    """
    try:
        # Discord API endpoint to check token
        url = "https://discord.com/api/v10/users/@me"

        # Call Discord API to validate the token
        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "OAuth-Session-Validator/1.0",
            },
            timeout=5,
        )

        # If we get a 200 response, the token is valid
        is_valid = response.status_code == 200
        return is_valid

    except Exception as e:
        logger.warning(f"Error validating Discord token: {e}")
        # Default to considering token valid on connection errors
        # to avoid logging users out due to temporary API issues
        return True


def refresh_discord_token(account, token):
    """
    Refresh a Discord OAuth token using the refresh token.

    Args:
        account: The SocialAccount instance
        token: The SocialToken instance to refresh

    Returns:
        The refreshed SocialToken instance if successful, None otherwise
    """
    # Check if we have a refresh token
    refresh_token = token.token_secret
    if not refresh_token:
        logger.warning("No refresh token available for Discord account")
        return None

    try:
        # Get the app credentials
        app = account.socialapp
        client_id = app.client_id
        client_secret = app.secret

        # Discord's token endpoint
        url = "https://discord.com/api/v10/oauth2/token"

        # Make the request to refresh the token
        response = requests.post(
            url,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "OAuth-Session-Validator/1.0",
            },
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()

            # Extract the new tokens
            new_token = data.get("access_token")
            new_refresh_token = data.get("refresh_token")
            expires_in = data.get("expires_in", 604800)  # Default to 7 days

            if new_token:
                # Calculate new expiry time
                new_expires_at = timezone.now() + timedelta(seconds=expires_in)

                # Update the token in the database
                token.token = new_token
                if new_refresh_token:
                    token.token_secret = new_refresh_token
                token.expires_at = new_expires_at
                token.save()

                logger.info(
                    f"Successfully refreshed Discord token for user {account.user.id}"
                )
                return token
            else:
                logger.warning(
                    "Discord token refresh response did not contain a new token"
                )
        else:
            logger.warning(f"Failed to refresh Discord token: {response.status_code}")

    except Exception as e:
        logger.exception(f"Error refreshing Discord token: {e}")

    return None


# Custom provider for Apple
def validate_apple_token(access_token):
    """
    Validate an Apple OAuth token.

    Apple doesn't provide a straightforward way to validate tokens server-side.
    This implementation focuses on checking the JWT format and expiry.

    Args:
        access_token: The Apple ID token to validate

    Returns:
        bool: True if the token appears valid, False otherwise
    """
    try:
        # Apple ID tokens are JWTs
        # Basic validation: check JWT format
        parts = access_token.split(".")
        if len(parts) != 3:
            return False

        # Parse the payload
        import base64

        payload_part = parts[1]
        # Add padding if needed
        payload_part += "=" * (4 - len(payload_part) % 4)

        # Decode the payload
        payload = base64.b64decode(payload_part)
        payload_data = json.loads(payload)

        # Check expiry
        exp = payload_data.get("exp", 0)
        current_time = timezone.now().timestamp()

        # Token is valid if not expired
        return exp > current_time

    except Exception as e:
        logger.warning(f"Error validating Apple token: {e}")
        # For Apple, default to invalid token on error
        # since we can't validate properly
        return False


# No refresh function for Apple as Apple doesn't support token refresh
def refresh_apple_token(account, token):
    """
    Apple doesn't support refreshing tokens.

    Args:
        account: The SocialAccount instance
        token: The SocialToken instance to refresh

    Returns:
        None as Apple tokens aren't refreshable
    """
    return None


# Example settings for settings.py:
"""
OAUTH_SESSION_VALIDATOR_PROVIDERS = {
    'discord': {
        'validator': 'myapp.oauth.custom_provider.validate_discord_token',
        'refresher': 'myapp.oauth.custom_provider.refresh_discord_token',
    },
    'apple': {
        'validator': 'myapp.oauth.custom_provider.validate_apple_token',
        'refresher': 'myapp.oauth.custom_provider.refresh_apple_token',
    }
}
"""
