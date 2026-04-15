"""
File: runtime_defaults.py
Author: Matt-Ung
Last Updated: 2026-04-14
Purpose:
  Hold shared runtime default values used across the app runtime and testing
  harness.

Summary:
  This module exists so maintained defaults stay aligned between the live
  workflow runtime and the testing harness without duplicating magic numbers in
  multiple entrypoints.
"""

DEFAULT_DEEP_AGENT_REQUEST_LIMIT = 200
REQUEST_LIMIT_ERROR_MARKER = "request_limit of "
