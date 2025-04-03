import sys
import unittest
from unittest import mock

from django import VERSION as DJANGO_VERSION
from django.http import HttpResponse
from django.test import RequestFactory, TestCase

from django_oauth_guard.middleware import OAuthValidationMiddleware


@unittest.skipIf(
    sys.version_info < (3, 9) or sys.version_info >= (3, 13),
    "This test is for Python 3.9 - 3.12 compatibility",
)
class PythonVersionCompatibilityTestCase(TestCase):
    """Test compatibility with different Python versions"""

    def setUp(self):
        # Create a middleware instance
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())

    def test_basic_initialization(self):
        """Test that the middleware initializes correctly"""
        self.assertIsInstance(self.middleware, OAuthValidationMiddleware)

    def test_string_handling(self):
        """Test string handling across Python versions"""
        # Generate a fingerprint (tests string handling)
        request = RequestFactory().get("/")
        request.META = {
            "HTTP_USER_AGENT": "test-agent",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_ACCEPT_LANGUAGE": "en-US",
        }

        fingerprint = self.middleware._generate_fingerprint(request)
        self.assertIsInstance(fingerprint, str)
        self.assertTrue(len(fingerprint) > 0)

    def test_string_similarity(self):
        """Test string similarity calculation across Python versions"""
        # Calculate similarity between strings
        similarity = self.middleware._calculate_similarity("abcdef", "abcxyz")
        self.assertIsInstance(similarity, float)
        self.assertTrue(0 <= similarity <= 1)


@unittest.skipIf(
    DJANGO_VERSION[0] < 4 or DJANGO_VERSION[0] >= 6,
    "This test is for Django 4.x - 5.x compatibility",
)
class DjangoVersionCompatibilityTestCase(TestCase):
    """Test compatibility with different Django versions (4.x and 5.x)"""

    def setUp(self):
        # Create a middleware instance
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())

        # Create a request factory
        self.factory = RequestFactory()

    def test_middleware_call(self):
        """Test that the middleware __call__ method works"""
        request = self.factory.get("/")
        request.user = mock.MagicMock(is_authenticated=False)

        response = self.middleware(request)
        self.assertIsInstance(response, HttpResponse)

    def test_django_imports(self):
        """Test that all Django imports work across versions"""
        # This test doesn't do much except verify that the imports worked
        # If Django changes drastically, the imports might fail
        self.assertTrue(hasattr(self.middleware, "get_response"))
