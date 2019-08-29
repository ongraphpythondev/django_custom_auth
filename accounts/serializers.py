# -*- coding: utf-8 -*-

# Django Imports
from rest_framework import serializers
from rest_auth.serializers import PasswordResetSerializer
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_auth.models import TokenModel
from django.contrib.auth.forms import SetPasswordForm
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode as uid_decoder
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator

# Project Imports
from .models import User
from .forms import PasswordResetForm

# Get the UserModel
UserModel = get_user_model()


class CustomUserRegistrationSerializer(serializers.ModelSerializer):
    """
    Custom Serializer for User Registration
    """
    password1 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True
    )
    password2 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True
    )

    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'password1',
            'password2',
            'first_name',
            'last_name',
        )

    def validate_email_password(self, data):
        json_data = {"success": "false"}
        email_validation = User.objects.filter(email=data['email'])
        if data['password1'] != data['password2']:
            json_data.update(
                {
                    "message": "The password fields didn't match."
                }
            )
            raise AuthenticationFailed(json_data)
        elif email_validation:
            json_data.update(
                {
                    "message": "The email field must be unique."
                }
            )
            raise AuthenticationFailed(json_data)

        return data

    def create(self, validated_data):

        # Check if the both password fields & email are valid.
        self.validate_email_password(validated_data)

        user_obj = User.objects.create_user(
            email=validated_data.get('email', ''),
            password=validated_data.get('password1', ''),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )
        data = {
            "id": user_obj.id,
            "email": validated_data.get('email', ''),
        }
        return data


class CustomLoginResponseSerializer(serializers.ModelSerializer):
    """
    Custom serializer to return all relevant user data on hitting login API
    """
    email = serializers.CharField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')

    class Meta:
        model = TokenModel
        fields = (
            'email', 'key', 'first_name', 'last_name')


class CustomChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for requesting a password Change.
    """
    old_password = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)


class CustomPasswordResetSerializer(PasswordResetSerializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    password_reset_form_class = PasswordResetForm


class CustomPasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        self._errors = {}

        # Decode the uidb64 to uid to get User object
        try:
            params = self.context.get('request').query_params
            uid = force_text(uid_decoder(params.get('uid')))
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise ValidationError({'uid': ['Invalid value']})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, params.get('token')):
            raise ValidationError({'token': ['Invalid value']})

        return attrs

    def save(self):
        return self.set_password_form.save()
