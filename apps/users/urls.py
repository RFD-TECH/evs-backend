"""EVS users URL configuration."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import RoleViewSet, UserProfileViewSet

router = SimpleRouter(trailing_slash=False)
router.register("profiles", UserProfileViewSet, basename="user-profile")
router.register("roles", RoleViewSet, basename="role")

urlpatterns = [
    path("", include(router.urls)),
]
