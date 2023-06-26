import os

import django.contrib.auth.password_validation as validators
from django.contrib.auth import authenticate
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models

from datetime import datetime

from .utils import make_id


class UserProfileManager(BaseUserManager):
    def create_user(self, email, username, first_name, last_name='', password=None, auth_provider=None):
        if not email:
            raise ValueError('User must have an email address')

        email = self.normalize_email(email).lower()
        user: User = self.model(email=email,
                                username=username,
                                first_name=first_name,
                                last_name=last_name,
                                auth_provider=auth_provider,
                                )

        user.set_password(password)

        # validate the password
        validators.validate_password(password=password, user=User)
        user.is_active = True

        if auth_provider == User.EMAIL:
            user.is_active = False

        user.save()  # Saving in a database

        return user

    @staticmethod
    def register_social_user( email, first_name, provider, last_name=''):
        filtered_user_by_email = User.objects.filter(email=email)

        if filtered_user_by_email.exists():

            if provider == filtered_user_by_email[0].auth_provider:

                registered_user = authenticate(email=email, password=os.environ.get('SOCIAL_SECRET'))

                return registered_user

            else:
                return {}

        else:
            User.objects.create_user(email=email,
                                     first_name=first_name,
                                     last_name=last_name,
                                     password=os.environ.get('SOCIAL_SECRET'),
                                     auth_provider=provider)

            new_user = authenticate(email=email, password=os.environ.get('SOCIAL_SECRET'))
            return new_user

    def create_superuser(self, email, first_name, last_name, password):
        user = self.create_user(email, first_name, last_name, password=password, auth_provider=User.EMAIL)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save()
        return user

    def update_password(self, email, new_password):

        users = self.model.objects.filter(email=email).all()
        if len(users) == 0:
            return

        user = users[0]
        user.set_password(new_password)
        user.save()
        return user


class Group(models.Model):
    key = models.CharField(max_length=100, null=False, blank=False, unique=True, default=make_id)
    name = models.CharField(max_length=50, null=False, blank=False)


class User(AbstractBaseUser, PermissionsMixin):

    GOOGLE = 'GOOGLE'
    EMAIL = 'EMAIL'

    AUTH_PROVIDERS = [
        (GOOGLE, 'google'),
        (EMAIL, 'email'),
    ]

    username = models.CharField(max_length=100, unique=True, default='')
    email = models.EmailField(max_length=100, unique=True)
    auth_provider = models.CharField(max_length=10, choices=AUTH_PROVIDERS, default=GOOGLE)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    group = models.ManyToManyField(Group)

    objects = UserProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return f'email:{self.email} first_name:{self.first_name}, is_active:{self.is_active}'

    def get_object(self):
        return {'email': self.email, 'first_name': self.first_name, 'last_name': self.last_name}


class Chat(models.Model):

    sender_user = models.ForeignKey(User, null=False, on_delete=models.DO_NOTHING, related_name='sender')
    receiver_user = models.ForeignKey(User, null=False, on_delete=models.DO_NOTHING, related_name='receiver')
    message = models.CharField(max_length=1000)
    date = models.DateTimeField(default=datetime.utcnow, null=False)

    def __str__(self):
        return f'message:{self.message}'


class GroupChat(models.Model):

    group = models.ForeignKey(Group, null=False, on_delete=models.DO_NOTHING)
    sender_user = models.ForeignKey(User, null=False, on_delete=models.DO_NOTHING)
    message = models.CharField(max_length=1000)
    date = models.DateTimeField(default=datetime.utcnow, null=False)


class EmailToken(models.Model):
    user = models.OneToOneField(User, null=False, on_delete=models.CASCADE)
    token = models.CharField(max_length=256)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f'user: {self.user.email} token:{self.token} is_verified:{self.is_verified}'
