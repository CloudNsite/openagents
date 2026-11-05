# -*- coding: utf-8 -*-
"""Return-path validation for direct Google sign-in (/v1/auth/google/start)."""

import pytest

from app.routers.google_login import _safe_return


@pytest.mark.parametrize("path", [
    "/",
    "/094c2141/threads/abc?x=1",
    "/auth/desktop?port=54321&state=abc&retried=1",
])
def test_keeps_paths_on_this_site(path):
    assert _safe_return(path) == path


@pytest.mark.parametrize("path", [
    "",
    "https://evil.example/",
    "//evil.example/",
    "/\\evil.example/",
    "/\t/evil.example/",
    "/\n/evil.example/",
    "/\r/evil.example/",
])
def test_refuses_anything_that_can_leave_the_site(path):
    assert _safe_return(path) == "/"
