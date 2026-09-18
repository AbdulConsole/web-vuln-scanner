"""
Shared detection signatures and reference data.

Centralized here so a single review/update touches one file instead of
several detector modules, and so two detectors never accidentally drift
to slightly different definitions of "looks like a SQL error".
"""
from __future__ import annotations

# Substrings (checked case-insensitively) that indicate a database error
# was reflected in a response -- strong evidence of SQL injection.
SQL_ERROR_SIGNATURES: list[str] = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ora-01756",
    "ora-00933",
    "ora-00921",
    "sqlite3::",
    "sqlite error",
    "sqlstate[",
    "pg_query():",
    "postgresql query failed",
    "syntax error at or near",
    "microsoft ole db provider for odbc drivers",
    "microsoft jet database engine",
    "odbc sql server driver",
    "supplied argument is not a valid mysql",
    "mysqlclient.",
    "npgsql.",
    "system.data.sqlclient.sqlexception",
]

# Substrings indicating a framework debug/error page leaked into a
# response, rather than a generic error page.
DEBUG_PAGE_SIGNATURES: list[str] = [
    "traceback (most recent call last)",
    "django version",
    "werkzeug debugger",
    "whoops, looks like something went wrong",
    "server error in '/' application",
    "microsoft .net framework versions",
    "fatal error:",
    "warning: include(",
    "notice: undefined",
    "stack trace:",
    "exception in thread",
    "debug = true",
]

# path -> (content signatures, human title). A path is only reported if
# BOTH the status is 200 AND at least one content signature matches --
# status 200 alone is common on sites with custom "not found" pages that
# return 200 for anything, so it is not sufficient evidence on its own.
SENSITIVE_PATH_SIGNATURES: dict[str, tuple[list[str], str]] = {
    "/.git/config": (["[core]", "repositoryformatversion"], "Exposed .git configuration file"),
    "/.git/HEAD": (["ref:"], "Exposed .git HEAD file"),
    "/.env": (["APP_", "DB_", "SECRET"], "Exposed .env environment file"),
    "/.env.local": (["APP_", "DB_", "SECRET"], "Exposed .env.local environment file"),
    "/wp-config.php.bak": (["DB_PASSWORD", "define("], "Exposed WordPress config backup"),
    "/config.php.bak": (["<?php", "password"], "Exposed PHP config backup"),
    "/.DS_Store": (["Bud1"], "Exposed macOS .DS_Store metadata file"),
    "/server-status": (["Apache Server Status"], "Exposed Apache server-status page"),
    "/phpinfo.php": (["PHP Version", "phpinfo()"], "Exposed phpinfo() page"),
    "/.svn/entries": (["dir"], "Exposed Subversion entries file"),
    "/web.config": (["<configuration>"], "Exposed IIS web.config file"),
}

# Field-name substrings (checked case-insensitively) recognized as
# anti-CSRF tokens.
CSRF_TOKEN_FIELD_HINTS: list[str] = [
    "csrf",
    "_token",
    "authenticity_token",
    "csrfmiddlewaretoken",
    "requestverificationtoken",
    "anti-forgery",
    "xsrf",
]

# Path substrings (checked case-insensitively) suggesting a URL is
# intended to require authentication/authorization. A heuristic
# pre-filter ONLY, used by the access-control detector -- never treated
# as proof a page is actually sensitive.
SENSITIVE_PATH_HINTS: list[str] = [
    "admin", "administrator", "manage", "management", "dashboard",
    "settings", "account", "config", "internal", "private", "staff",
    "backend", "cpanel", "controlpanel",
]

# header -> display metadata for the security-headers detector.
SECURITY_HEADERS: dict[str, dict[str, str]] = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "description": (
            "No Content-Security-Policy header was returned. CSP is the "
            "primary browser-side defense against XSS and data-injection "
            "attacks -- without it, a successful injection can execute "
            "arbitrary script with no restriction on script sources."
        ),
        "remediation": (
            "Add a Content-Security-Policy header. Start restrictive, e.g. "
            "\"default-src 'self'\", and add specific sources as needed "
            "rather than using 'unsafe-inline' or wildcard sources."
        ),
        "severity": "medium",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "description": (
            "No 'X-Content-Type-Options: nosniff' header was returned. "
            "Without it, some browsers may MIME-sniff a response body and "
            "render it as a different content type than declared, which "
            "can enable stored-XSS-like attacks via file upload endpoints."
        ),
        "remediation": "Add 'X-Content-Type-Options: nosniff' to all responses.",
        "severity": "low",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options header",
        "description": (
            "No X-Frame-Options header was returned, so the page can be "
            "embedded in an <iframe> on another site -- a prerequisite for "
            "clickjacking attacks."
        ),
        "remediation": (
            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or a "
            "Content-Security-Policy 'frame-ancestors' directive."
        ),
        "severity": "medium",
    },
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security header",
        "description": (
            "No HSTS header was returned over HTTPS. Without it, a user "
            "who types the bare domain or follows an http:// link can be "
            "downgraded to plaintext HTTP and subjected to interception."
        ),
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains' once the entire site is served over HTTPS."
        ),
        "severity": "medium",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "description": (
            "No Referrer-Policy header was returned. The full referring "
            "URL (which can contain tokens or sensitive path segments) may "
            "be leaked to third parties via the Referer header."
        ),
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
        "severity": "low",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy header",
        "description": (
            "No Permissions-Policy header was returned, so the page does "
            "not explicitly restrict access to sensitive browser features "
            "(camera, microphone, geolocation) for itself or embedded content."
        ),
        "remediation": (
            "Add a Permissions-Policy header disabling features the site "
            "does not use, e.g. \"camera=(), microphone=(), geolocation=()\"."
        ),
        "severity": "informational",
    },
}
