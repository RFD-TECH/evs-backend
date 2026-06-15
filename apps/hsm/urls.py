"""EVS HSM URL configuration."""
from django.urls import path

from .views import JwksView, SignView

urlpatterns = [
    path("jwks", JwksView.as_view(), name="hsm-jwks"),
    path("sign", SignView.as_view(), name="hsm-sign"),
]
