import uuid

import structlog
import requests

from django.conf import settings

from django_structlog.middlewares.request import RequestMiddleware, get_request_header
from django_structlog import signals

logger = structlog.getLogger(__name__)


def send_to_newrelic(logger, log_method, event_dict):
    if not settings.LOGGING_NEW_RELIC_API_KEY:
        # NOOP if there is no New Relic api key
        return event_dict

    # Uses the New Relic Log API
    # https://docs.newrelic.com/docs/logs/log-management/log-api/introduction-log-api/
    headers = {'Api-Key': settings.LOGGING_NEW_RELIC_API_KEY}

    # Our log message and all the event context is sent as a JSON string
    # in the POST body
    # https://docs.newrelic.com/docs/logs/log-management/log-api/introduction-log-api/#json-content
    payload = {
        'message': f"{event_dict['event']}",
    }
    payload.update(event_dict)

    requests.post(
        'https://log-api.newrelic.com/log/v1',
        json=payload,
        headers=headers,
    )
    return event_dict


class ReadTheDocsRequestMiddleware(RequestMiddleware):
    """
    ``ReadTheDocsRequestMiddleware`` adds request metadata to ``structlog``'s logger context.

    This middleware overrides the original to avoid logging ``request`` object
    because it's not JSON serializable.
    See https://github.com/jrobichaud/django-structlog/issues/72

    >>> MIDDLEWARE = [
    ...     # ...
    ...     'readthedocs.core.logs.ReadTheDocsRequestMiddleware',
    ... ]

    """

    def __call__(self, request):
        from ipware import get_client_ip

        request_id = get_request_header(
            request, "x-request-id", "HTTP_X_REQUEST_ID"
        ) or str(uuid.uuid4())

        correlation_id = get_request_header(
            request, "x-correlation-id", "HTTP_X_CORRELATION_ID"
        )

        with structlog.threadlocal.tmp_bind(logger):
            logger.bind(request_id=request_id)
            self.bind_user_id(request),
            if correlation_id:
                logger.bind(correlation_id=correlation_id)

            ip, _ = get_client_ip(request)
            logger.bind(ip=ip)
            signals.bind_extra_request_metadata.send(
                sender=self.__class__, request=request, logger=logger
            )

            logger.info(
                "request_started",
                # NOTE here we remove the request and log the URL
                # request=request,
                absolute_url=request.build_absolute_uri(),
                user_agent=request.META.get("HTTP_USER_AGENT"),
            )
            self._raised_exception = False
            response = self.get_response(request)
            if not self._raised_exception:
                self.bind_user_id(request),
                signals.bind_extra_request_finished_metadata.send(
                    sender=self.__class__,
                    request=request,
                    logger=logger,
                    response=response,
                )
                logger.info(
                    "request_finished",
                    code=response.status_code,
                    # NOTE here we remove the request and log the URL
                    # request=request,
                    absolute_url=request.build_absolute_uri(),
                )

        return response


structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.processors.TimeStamper(fmt='iso'),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        send_to_newrelic,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    context_class=structlog.threadlocal.wrap_dict(dict),
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
