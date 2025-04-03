"""
Django settings for testing.
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'test-key-not-for-production'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    
    # Required for django-allauth
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    
    # Supported providers
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.facebook',
    'allauth.socialaccount.providers.microsoft',
    'allauth.socialaccount.providers.github',
    'allauth.socialaccount.providers.linkedin_oauth2',
    
    # Our app
    'django_oauth_guard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # Required for allauth
    'allauth.account.middleware.AccountMiddleware',
    
    # This is what we're testing
    'django_oauth_guard.middleware.OAuthValidationMiddleware',
]

# Add URL for login redirection in tests
LOGIN_URL = '/accounts/login/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/accounts/login/'

ROOT_URLCONF = 'tests.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'tests.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'

# django-allauth settings
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
)

SITE_ID = 1

# OAuth Session Validator Settings for testing
OAUTH_SESSION_VALIDATOR = {
    'VALIDATION_PROBABILITY': 1.0,  # Always validate in tests
    'VALIDATION_INTERVAL': 0,       # No throttling in tests
    'MAX_INACTIVITY': 86400,        # 24 hours
    'MAX_SESSION_AGE': 604800,      # 7 days
    'SENSITIVE_PATHS': [
        '/password/change/',
        '/settings/',
        '/payment/',
        '/admin/',
        '/delete/',
        '/email/change/',
    ],
    'FINGERPRINT_SIMILARITY_THRESHOLD': 0.9,
}

# Facebook test settings
FACEBOOK_APP_ID = 'test-app-id'
FACEBOOK_APP_SECRET = 'test-app-secret'

# Caching (use memory caching for tests)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}