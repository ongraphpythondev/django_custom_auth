# -*- coding: utf-8 -*-

# Django Imports
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import ugettext_lazy as _

# Project Imports
from accounts.models import User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    """
    Define admin model for custom User model.
    """
    fieldsets = (
        (None, {'fields': ('email', 'password', 'first_name', 'last_name')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'first_name', 'last_name', 'email', 'password1', 'password2'),
        }),
    )
    list_display = ('email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('first_name', 'last_name', 'email')
    ordering = ('-id',)
