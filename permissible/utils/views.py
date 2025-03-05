"""
Utility functions for views in the permissible package.
"""

from __future__ import annotations

from typing import Optional, Dict, Any

from rest_framework.request import Request


def make_context_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Extract context data from a request, either from request.data (for POST/PUT/PATCH)
    or from request.query_params (for GET).

    This function helps create a context dictionary that can be used in permission checks,
    making relevant request parameters available to permission checkers.

    Args:
        request: The DRF Request object

    Returns:
        A dictionary containing context data or None if no valid data is found

    Examples:
        # In a viewset method:
        context = make_context_from_request(request)
        obj.has_object_permission(request.user, 'custom_action', context=context)
    """
    if not request:
        return None

    context = {}

    # Try to get data from request.data (for POST, PUT, PATCH requests)
    if hasattr(request, "data") and request.data:
        # Handle both dict and non-dict data (like QueryDict)
        if hasattr(request.data, "dict"):
            # Convert QueryDict to regular dict
            context.update(request.data.dict())
        elif isinstance(request.data, dict):
            context.update(request.data)
        # If it's a list or other non-dict type, add it as 'data'
        elif request.data:
            context["data"] = request.data

    # Try to get data from query_params (for GET requests)
    if hasattr(request, "query_params") and request.query_params:
        # Handle QueryDict conversion to regular dict
        if hasattr(request.query_params, "dict"):
            query_dict = request.query_params.dict()

            # Don't override existing keys from data
            for key, value in query_dict.items():
                if key not in context:
                    context[key] = value
        else:
            # Unlikely but handling just in case
            for key, value in request.query_params.items():
                if key not in context:
                    context[key] = value

    # Add the request itself to the context
    context["request"] = request

    # Add the user for convenience, but only if it exists
    if hasattr(request, "user"):
        context["user"] = request.user

    return context if context else None
