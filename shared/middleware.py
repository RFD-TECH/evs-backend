"""EVS middleware stack: audit context, edge rate-limit, idempotency."""
from __future__ import annotations

import uuid
import logging

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

from shared.events import set_request_id, set_trace_context

logger = logging.getLogger(__name__)


class JsonExceptionMiddleware:
    """Catch unhandled exceptions and return RFC 7807 JSON (never HTML)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        logger.exception("unhandled_exception path=%s", request.path)
        return JsonResponse(
            {
                "type": "https://evs.clet.gov.gh/errors/server-error",
                "title": "Internal Server Error",
                "status": 500,
                "detail": "An unexpected error occurred.",
                "errorCode": "SERVER_ERROR",
            },
            status=500,
            content_type="application/problem+json",
        )


class AuditMiddleware(MiddlewareMixin):
    """Inject request_id, ip_address, user_agent, and W3C trace context."""

    def process_request(self, request):
        traceparent = request.META.get("HTTP_TRACEPARENT")
        tracestate = request.META.get("HTTP_TRACESTATE")

        if traceparent:
            parts = traceparent.split("-")
            request_id = uuid.UUID(parts[1]) if len(parts) >= 2 else uuid.uuid4()
        else:
            request_id = uuid.uuid4()
            traceparent = f"00-{request_id.hex}-{uuid.uuid4().hex[:16]}-01"

        request.request_id = request_id
        request.ip_address = self._get_ip(request)
        request.user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]

        set_request_id(request_id)
        set_trace_context(traceparent, tracestate)

    @staticmethod
    def _get_ip(request) -> str:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")


class EdgeRateLimitMiddleware:
    """Count rejected (401/403/429) responses per IP; block on threshold."""

    THROTTLE_KEY = "evs:edge:throttle:{ip}"
    BLOCK_KEY = "evs:edge:block:{ip}"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = getattr(request, "ip_address", None) or request.META.get("REMOTE_ADDR", "")
        if ip and cache.get(self.BLOCK_KEY.format(ip=ip)):
            return JsonResponse(
                {"type": "https://evs.clet.gov.gh/errors/rate-limited",
                 "title": "Too Many Requests", "status": 429,
                 "detail": "IP temporarily blocked due to repeated failures.",
                 "errorCode": "RATE_LIMITED"},
                status=429, content_type="application/problem+json",
            )

        response = self.get_response(request)

        if ip and response.status_code in (401, 403, 429):
            throttle_key = self.THROTTLE_KEY.format(ip=ip)
            block_key = self.BLOCK_KEY.format(ip=ip)
            count = cache.get(throttle_key, 0)
            count += 1
            cache.set(throttle_key, count, timeout=900)

            threshold = getattr(settings, "EDGE_THROTTLE_THRESHOLD", 100)
            block_threshold = getattr(settings, "EDGE_BLOCK_THRESHOLD_24H", 1000)

            if count >= block_threshold:
                cache.set(block_key, True, timeout=86400)
                self._record_security_event(request, ip, "ip_blocked", count)
            elif count >= threshold:
                self._record_security_event(request, ip, "throttle_applied", count)

        return response

    @staticmethod
    def _record_security_event(request, ip, category, count):
        try:
            from shared.secops import record_security_event
            record_security_event(
                category=category,
                ip_address=ip,
                request_id=getattr(request, "request_id", None),
                indicators={"path": request.path, "failure_count": count},
            )
        except Exception:
            pass


class IdempotencyKeyMiddleware:
    """Cache-backed deduplication for state-mutating requests."""

    IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
    CACHE_KEY = "evs:idempotency:{key}"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return self.get_response(request)

        idempotency_key = request.headers.get(self.IDEMPOTENCY_KEY_HEADER, "")
        if not idempotency_key:
            return self.get_response(request)

        cache_key = self.CACHE_KEY.format(key=idempotency_key)
        cached = cache.get(cache_key)
        if cached:
            return JsonResponse(cached["data"], status=cached["status"])

        response = self.get_response(request)

        ttl = getattr(settings, "IDEMPOTENCY_CACHE_TTL_SECONDS", 86400)
        if response.status_code < 500 and hasattr(response, "data"):
            try:
                cache.set(cache_key, {"data": response.data, "status": response.status_code}, timeout=ttl)
            except Exception:
                pass

        return response
