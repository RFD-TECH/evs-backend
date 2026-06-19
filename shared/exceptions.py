"""Standard EVS response envelope and exception handler."""
from datetime import datetime, timezone
from http import HTTPStatus

from django_fsm import TransitionNotAllowed
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler


def format_rfc7807_error(
    status_code: int, error_code: str, message: str, request_id: str, fields=None
) -> dict:
    try:
        title = HTTPStatus(status_code).phrase
    except ValueError:
        title = "Error"
    payload = {
        "type": f"https://evs.clet.gov.gh/errors/{error_code.lower().replace('_', '-')}",
        "title": title,
        "status": status_code,
        "detail": message,
        "errorCode": error_code,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "instance": f"urn:evs:request:{request_id}" if request_id else "urn:evs:request:unknown",
    }
    if fields:
        payload["invalid_params"] = fields
    return payload


class StepUpRequired(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Additional security verification is required for this action."
    default_code = "step_up_required"
    evs_error_code = "STEP_UP_REQUIRED"


class HsmUnavailable(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Signing service is temporarily unavailable."
    default_code = "hsm_unavailable"
    evs_error_code = "HSM_UNAVAILABLE"


def evs_exception_handler(exc, context):
    request = context.get("request")
    request_id = str(getattr(request, "request_id", "")) if request else ""

    if isinstance(exc, TransitionNotAllowed):
        data = format_rfc7807_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="TRANSITION_NOT_ALLOWED",
            message=str(exc),
            request_id=request_id,
        )
        return Response(data, status=status.HTTP_400_BAD_REQUEST, content_type="application/problem+json")

    response = exception_handler(exc, context)

    if response is None:
        data = format_rfc7807_error(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="SERVER_ERROR",
            message="Internal server error.",
            request_id=request_id,
        )
        return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR, content_type="application/problem+json")

    error_code = getattr(exc, "evs_error_code", None) or _get_error_code(response.status_code)
    error_detail = response.data.copy() if isinstance(response.data, dict) else response.data

    fields = None
    message = str(exc)
    if isinstance(exc, APIException):
        message = str(exc.detail)
    if isinstance(error_detail, dict):
        non_field = error_detail.pop("non_field_errors", None)
        detail = error_detail.pop("detail", None)
        if detail:
            message = str(detail)
        if error_detail:
            fields = {k: [str(e) for e in v] if isinstance(v, list) else str(v) for k, v in error_detail.items()}
        if non_field:
            message = " ".join(str(e) for e in non_field)

    data = format_rfc7807_error(
        status_code=response.status_code,
        error_code=error_code,
        message=message,
        request_id=request_id,
        fields=fields,
    )
    response.data = data
    response.content_type = "application/problem+json"
    return response


def _get_error_code(status_code: int) -> str:
    return {
        400: "VALIDATION_ERROR",
        401: "NOT_AUTHENTICATED",
        403: "AUTHZ_DENIED",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        429: "RATE_LIMITED",
        500: "SERVER_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }.get(status_code, "ERROR")


def success_response(data=None, message="Success", status_code=None, meta=None, **kwargs):
    """Return a standard success envelope.

    Accepts ``status_code`` or the shorthand ``status`` kwarg.
    """
    _code = status_code or kwargs.get("status") or status.HTTP_200_OK
    return Response(
        {"success": True, "message": message, "data": data or {}, "meta": meta or {}},
        status=_code,
    )


def error_response(message, code="ERROR", errors=None, detail=None, status_code=None, meta=None, **kwargs):
    """Return an RFC 7807 problem+json error response.

    Accepts ``status_code`` or the shorthand ``status`` kwarg.
    Accepts ``errors`` or ``detail`` for the field-error map.
    """
    _code = status_code or kwargs.get("status") or status.HTTP_400_BAD_REQUEST
    _errors = errors or detail
    request_id = (meta or {}).get("request_id", "")
    data = format_rfc7807_error(
        status_code=_code,
        error_code=code,
        message=message,
        request_id=request_id,
        fields=_errors,
    )
    return Response(data, status=_code, content_type="application/problem+json")
