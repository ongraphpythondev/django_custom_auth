# -*- coding: utf-8 -*-

# Django Imports
from rest_auth.views import PasswordResetView, GenericAPIView
from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response
from rest_auth.views import LoginView, APIView
from rest_framework.authtoken.models import Token
from rest_framework.generics import UpdateAPIView
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _

# Project Imports
from .models import User
from .serializers import (CustomUserRegistrationSerializer,
                          CustomChangePasswordSerializer,
                          CustomPasswordResetSerializer,
                          CustomPasswordResetConfirmSerializer
                          )

sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2'
    )
)


class CustomUserRegistrationView(generics.CreateAPIView):
    """
    Custom User Registration View.
    """
    serializer_class = CustomUserRegistrationSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            new_user = serializer.save()
            if new_user:
                return Response(
                    data={
                        "data": new_user
                    }, status=status.HTTP_201_CREATED
                )
        return Response(
            data={
                "message": serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST
        )


class CustomLoginView(LoginView):
    """
    Custom Login View.
    """

    def get_response(self):
        original_response = super().get_response()
        my_data = {
            "success": True,
            "data": original_response.data
        }
        return Response(my_data)

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(
            data=self.request.data, context={'request': request}
        )
        if self.serializer.is_valid():
            self.login()
            return self.get_response()
        else:
            return Response(
                {
                    "message": "Invalid Login Credentials"
                }, status=status.HTTP_400_BAD_REQUEST
            )


class CustomLogoutView(APIView):
    """
    Custom Logout View.
    """
    def post(self, request,  *args, **kwargs):
        return self.logout(request)

    def logout(self, request):
        try:
            request.user.auth_token.delete()
        except Token.DoesNotExist:
            return Response({
                "message": "Invalid Token"
            }, status=status.HTTP_401_UNAUTHORIZED)
        response = Response(
            {
                "message": "Successfully logged out."
            }, status=status.HTTP_200_OK
        )
        return response


class CustomChangePasswordView(UpdateAPIView):
    """
    Custom Change Password View.
    """
    serializer_class = CustomChangePasswordSerializer
    model = User

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response(
                    {
                        "message": "Old Password Does Not Match."
                    }, status=status.HTTP_400_BAD_REQUEST)

            if request.data.get('old_password') == request.data.get('new_password1'):
                return Response(
                    {
                        "message": " New Password can not be as old password."
                    }, status=status.HTTP_400_BAD_REQUEST
                )

            if not (request.data.get('new_password1') == request.data.get('new_password2')):
                return Response(
                    {
                        "message": "Password Does Not Match."
                    }, status=status.HTTP_400_BAD_REQUEST
                )
            else:
                self.object.set_password(serializer.data.get("new_password1"))
                self.object.save()
                return Response(
                    {
                        "message": "Password Change Successfully."
                    }, status=status.HTTP_200_OK
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomPasswordResetView(PasswordResetView):
    """
    Custom View To Overwrite Default Password Reset Email Template
    """
    serializer_class = CustomPasswordResetSerializer


class CustomPasswordResetConfirmView(GenericAPIView):
    """
    Password reset e-mail link is confirmed, therefore
    this resets the user's password.

    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    """
    serializer_class = CustomPasswordResetConfirmSerializer
    permission_classes = (AllowAny,)

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super(CustomPasswordResetConfirmView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": _("Password has been reset with the new password.")}
        )
