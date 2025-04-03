from setuptools import setup, find_packages
import os
import re

# Read version from __init__.py
with open(os.path.join(os.path.dirname(__file__), 'django_oauth_guard', '__init__.py')) as f:
    version = re.search(r'__version__ = [\'"]([^\'"]*)[\'"]', f.read()).group(1)

# Read long description from README.md
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='django-oauth-guard',
    version=version,
    description='Enhanced security middleware for Django applications using OAuth authentication',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='',
    author_email='',
    url='https://github.com/django-oauth-guard',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Django>=2.2',
        'django-allauth>=0.40.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-django>=4.5.0',
            'pytest-cov>=3.0.0',
            'black>=22.0.0',
            'flake8>=5.0.0',
            'isort>=5.0.0',
            'tox>=4.0.0',
        ],
        'test': [
            'pytest>=7.0.0',
            'pytest-django>=4.5.0',
            'pytest-cov>=3.0.0',
            'tox>=4.0.0',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 2.2',
        'Framework :: Django :: 3.0',
        'Framework :: Django :: 3.1',
        'Framework :: Django :: 3.2',
        'Framework :: Django :: 4.0',
        'Framework :: Django :: 4.1',
        'Framework :: Django :: 4.2',
        'Framework :: Django :: 5.0',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],
    python_requires='>=3.9',
)