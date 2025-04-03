"""URL patterns for tests."""

from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path


# Simple view for testing
def home_view(request):
    return HttpResponse('Home page')

urlpatterns = [
    path('', home_view, name='home'),
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),
]