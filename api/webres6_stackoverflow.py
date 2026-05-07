#
# SPDX-FileCopyrightText: 2026 Stack Overflow Community and others
#
# SPDX-License-Identifier: CC-BY-SA-4.0
#
##############################################################################
# Source - https://stackoverflow.com/a/71334860
# Posted by r s, modified by community. See post 'Timeline' for change history
# Retrieved 2026-05-07, License - CC BY-SA 4.0
from opentelemetry import context as otel_context
from concurrent.futures import ThreadPoolExecutor, as_completed

class TracedThreadPoolExecutor(ThreadPoolExecutor):
    """Implementation of :class:`ThreadPoolExecutor` that will pass context into sub tasks."""

    def __init__(self, tracer: Tracer, *args, **kwargs):
        self.tracer = tracer
        super().__init__(*args, **kwargs)

    def with_otel_context(self, context: otel_context.Context, fn: Callable):
        otel_context.attach(context)
        return fn()

    def submit(self, fn, *args, **kwargs):
        """Submit a new task to the thread pool."""

        # get the current otel context
        context = otel_context.get_current()
        if context:
            return super().submit(
                lambda: self.with_otel_context(
                    context, lambda: fn(*args, **kwargs)
                ),
            )
        else:
            return super().submit(lambda: fn(*args, **kwargs))
