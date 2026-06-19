"""URL configuration for fraud detection (EVS-F05)."""
from django.urls import path

from .views import (
    FlagAddendumView,
    FlagEvidenceView,
    FlagResolveView,
    FraudFlagViewSet,
    FraudRunDetailView,
    FraudRunView,
    RuleActivateView,
    RuleApproveView,
    RuleDefinitionDetailView,
    RuleDefinitionListCreateView,
    RuleDeprecateView,
    RuleDryRunView,
    WatchlistClearView,
    WatchlistView,
)

app_name = "fraud_detection"

flags_list = FraudFlagViewSet.as_view({"get": "list"})
flags_detail = FraudFlagViewSet.as_view({"get": "retrieve"})

urlpatterns = [
    # Detection runs
    path("runs/", FraudRunView.as_view(), name="run-create"),
    path("runs/<uuid:pk>/", FraudRunDetailView.as_view(), name="run-detail"),

    # Fraud flags
    path("flags/", flags_list, name="flag-list"),
    path("flags/<uuid:pk>/", flags_detail, name="flag-detail"),
    path("flags/<uuid:pk>/evidence/", FlagEvidenceView.as_view(), name="flag-evidence"),
    path("flags/<uuid:pk>/resolve/", FlagResolveView.as_view(), name="flag-resolve"),
    path("flags/<uuid:pk>/addendum/", FlagAddendumView.as_view(), name="flag-addendum"),

    # Rule definitions
    path("rules/", RuleDefinitionListCreateView.as_view(), name="rule-list"),
    path("rules/dry-run/", RuleDryRunView.as_view(), name="rule-dry-run"),
    path("rules/<uuid:pk>/", RuleDefinitionDetailView.as_view(), name="rule-detail"),
    path("rules/<uuid:pk>/approve/", RuleApproveView.as_view(), name="rule-approve"),
    path("rules/<uuid:pk>/activate/", RuleActivateView.as_view(), name="rule-activate"),
    path("rules/<uuid:pk>/deprecate/", RuleDeprecateView.as_view(), name="rule-deprecate"),

    # Watchlist
    path("watchlist/", WatchlistView.as_view(), name="watchlist-list"),
    path("watchlist/<uuid:pk>/clear/", WatchlistClearView.as_view(), name="watchlist-clear"),
]
