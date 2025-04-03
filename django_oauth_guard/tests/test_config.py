from django.http import HttpResponse
from django.test import TestCase, override_settings

from django_oauth_guard.middleware import OAuthValidationMiddleware


class ConfigurationTestCase(TestCase):
    """Test configuration options of the middleware"""

    def setUp(self):
        # Create a middleware instance
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())

    def test_default_config(self):
        """Test default configuration values"""
        # In our test settings, we override some values for testing purposes
        # Here we check that values from settings are correctly loaded
        # These match the values in tests/settings.py
        self.assertEqual(
            self.middleware.VALIDATION_PROBABILITY, 1.0
        )  # For tests we set to 1.0
        self.assertEqual(
            self.middleware.VALIDATION_INTERVAL, 0
        )  # For tests we set to 0
        self.assertEqual(self.middleware.MAX_INACTIVITY, 86400)
        self.assertEqual(self.middleware.MAX_SESSION_AGE, 604800)
        self.assertEqual(self.middleware.FINGERPRINT_SIMILARITY_THRESHOLD, 0.9)
        self.assertIn("/password/change/", self.middleware.SENSITIVE_PATHS)
        self.assertIn("/settings/", self.middleware.SENSITIVE_PATHS)
        self.assertIn("/payment/", self.middleware.SENSITIVE_PATHS)
        self.assertIn("/admin/", self.middleware.SENSITIVE_PATHS)
        self.assertIn("/delete/", self.middleware.SENSITIVE_PATHS)
        self.assertIn("/email/change/", self.middleware.SENSITIVE_PATHS)

    @override_settings(
        OAUTH_SESSION_VALIDATOR={
            "VALIDATION_PROBABILITY": 0.1,
            "VALIDATION_INTERVAL": 300,
            "MAX_INACTIVITY": 3600,
            "MAX_SESSION_AGE": 86400,
            "SENSITIVE_PATHS": ["/custom/path/"],
            "FINGERPRINT_SIMILARITY_THRESHOLD": 0.8,
        }
    )
    def test_custom_config(self):
        """Test custom configuration via settings"""
        # Create a new middleware instance to apply settings
        middleware = OAuthValidationMiddleware(lambda r: HttpResponse())

        # Check custom settings are applied
        self.assertEqual(middleware.VALIDATION_PROBABILITY, 0.1)
        self.assertEqual(middleware.VALIDATION_INTERVAL, 300)
        self.assertEqual(middleware.MAX_INACTIVITY, 3600)
        self.assertEqual(middleware.MAX_SESSION_AGE, 86400)
        self.assertEqual(middleware.FINGERPRINT_SIMILARITY_THRESHOLD, 0.8)
        self.assertEqual(middleware.SENSITIVE_PATHS, ["/custom/path/"])

    @override_settings(
        OAUTH_SESSION_VALIDATOR={
            "VALIDATION_PROBABILITY": 0.1,
        }
    )
    def test_partial_config(self):
        """Test partial configuration via settings"""
        # Create a new middleware instance to apply settings
        middleware = OAuthValidationMiddleware(lambda r: HttpResponse())

        # Check the specified setting is applied
        self.assertEqual(middleware.VALIDATION_PROBABILITY, 0.1)

        # Check defaults are preserved for unspecified settings
        self.assertEqual(middleware.VALIDATION_INTERVAL, 600)
        self.assertEqual(middleware.MAX_INACTIVITY, 86400)
        self.assertEqual(middleware.MAX_SESSION_AGE, 604800)
        self.assertEqual(middleware.FINGERPRINT_SIMILARITY_THRESHOLD, 0.9)
