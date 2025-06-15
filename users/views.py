from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from djoser.social.views import ProviderAuthView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from rest_framework.permissions import AllowAny


class CustomProviderAuthView(ProviderAuthView):
    """
    Custom ProviderAuthView to set cookies on successful login.

    This view is used to authenticate users using social authentication providers like Google and Facebook.

    The view sets the access and refresh tokens as cookies on successful login.

    The access token is set with the name "access" and the refresh token is set with the name "refresh".

    The cookies are set with the following attributes:

    - max_age: The maximum age of the cookie in seconds.
    - path: The path attribute of the cookie.
    - secure: The secure attribute of the cookie.
    - httponly: The httponly attribute of the cookie.
    - samesite: The samesite attribute of the cookie.

    The values of these attributes are taken from the settings.AUTH_COOKIE_* settings.


    """

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 201:
            access_token = response.data.get("access")
            refresh_token = response.data.get("refresh")

            response.set_cookie(
                "access",
                access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

            response.set_cookie(
                "refresh",
                refresh_token,
                max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

        return response


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom TokenObtainPairView to set cookies on successful login.

    This view is used to obtain access and refresh tokens for a user.

    The view sets the access and refresh tokens as cookies on successful login.

    The access token is set with the name "access" and the refresh token is set with the name "refresh".

    The cookies are set with the following attributes:

    - max_age: The maximum age of the cookie in seconds.
    - path: The path attribute of the cookie.
    - secure: The secure attribute of the cookie.
    - httponly: The httponly attribute of the cookie.
    - samesite: The samesite attribute of the cookie.

    The values of these attributes are taken from the settings.AUTH_COOKIE_* settings.


    """

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.get("access")
            refresh_token = response.data.get("refresh")

            response.set_cookie(
                "access",
                access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

            response.set_cookie(
                "refresh",
                refresh_token,
                max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

        return response


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom TokenRefreshView to set cookies on successful token refresh.

    This view is used to refresh the access token for a user.

    The view sets the access token as a cookie on successful token refresh.

    The access token is set with the name "access".

    The cookie is set with the following attributes:

    - max_age: The maximum age of the cookie in seconds.
    - path: The path attribute of the cookie.
    - secure: The secure attribute of the cookie.
    - httponly: The httponly attribute of the cookie.
    - samesite: The samesite attribute of the cookie.

    The values of these attributes are taken from the settings.AUTH_COOKIE_* settings.
    """

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh")

        if refresh_token:
            request.data["refresh"] = refresh_token

        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.get("access")

            response.set_cookie(
                "access",
                access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

        return response


class CustomTokenVerifyView(TokenVerifyView):
    def post(self, request, *args, **kwargs):
        access_token = request.COOKIES.get("access")

        if access_token:
            request.data["token"] = access_token

        return super().post(request, *args, **kwargs)


class LogoutView(APIView):
    def post(self, request, *args, **kwargs):
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie('access')
        response.delete_cookie('refresh')

        return response


class PrivacyPolicyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        privacy_policy_text = """This is the privacy policy of our application. We value your privacy and are committed to protecting your personal information."""
        return Response({"message": privacy_policy_text}, status=status.HTTP_200_OK)


class TermsOfServiceView(APIView):
    """
    Terms of service view.

    This view returns the terms of service of the application.

    The terms of service text is returned as a response.

    """

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        terms_of_service_text = """
        These are the terms of service of our application. By using our service, you agree to comply with these terms.
        """
        return Response({"message": terms_of_service_text}, status=status.HTTP_200_OK)


class DataDeletionPolicyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        data_deletion_policy_text = """
        This is the data deletion policy of our application. You can request the deletion of your personal data at any time.
        """
        return Response({"message": data_deletion_policy_text}, status=status.HTTP_200_OK)
