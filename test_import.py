#!/usr/bin/env python
import os

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')
django.setup()

from django_oauth_guard.middleware import OAuthValidationMiddleware

print('Import successful!')
print(f'Middleware version: {OAuthValidationMiddleware.__module__}.{OAuthValidationMiddleware.__name__}')