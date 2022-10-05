from django.contrib import admin
from django.urls import include,path

urlpattern = [
    path('authapi/',include('authapi.urls')),
]
