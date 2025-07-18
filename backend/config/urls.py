"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include  # ← include 꼭 필요해요

from myapp.views import (
    health_check
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('myapp.urls')),  # ← 여기서 'api/'는 선택. 원하는 경로로 변경 가능
    path('', include('django_prometheus.urls')), # prometheus metric 수집 경로
]

