"""Shared utilities for HTTP decoy route modules."""

import ipaddress

from fastapi import Request


def get_source_ip(request: Request) -> str:
    """Extract the most-likely real client IP, with format validation."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if ip:
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                pass  # Invalid IP format — fall through to client.host
    return request.client.host if request.client else "unknown"
