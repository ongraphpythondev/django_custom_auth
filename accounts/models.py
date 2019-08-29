# -*- coding: utf-8 -*-

# Django Imports
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import ugettext_lazy as _

# Project Imports
from .managers import UserManager


class User(AbstractUser):
    username = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()

    # Attributes
    email = models.EmailField(_('email_address'), unique=True)

    def __str__(self):
        return "{}".format(self.email)
