# -*- coding: utf-8 -*-

# Django Imports
from django.urls import path, include

# Project Imports
from . import views

urlpatterns = [
    path('auth/', include([
        path('registration/', views.CustomUserRegistrationView.as_view()),
        path('login/', views.CustomLoginView.as_view()),
        path('logout/', views.CustomLogoutView.as_view()),
        path('password/change/', views.CustomChangePasswordView.as_view()),
        path('password/reset/', views.CustomPasswordResetView.as_view(),
             name='rest_password_reset'),
        path('password/reset/confirm/', views.CustomPasswordResetConfirmView.as_view(),
             name='rest_password_reset_confirm'),
    ])),
]
