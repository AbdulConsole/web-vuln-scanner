from __future__ import annotations

from app.crawler.models import CrawledUrl, CrawlSummary, DiscoveredForm, DiscoveredParameter
from app.detectors.probing import collect_param_targets, strip_query
from app.models.enums import HttpMethod, ParameterSource


def test_strip_query_removes_query_string():
    assert strip_query("http://example.com/search?q=1&x=2") == "http://example.com/search"


def test_strip_query_is_idempotent_on_url_without_query():
    assert strip_query("http://example.com/page") == "http://example.com/page"


def _make_summary(urls: list[CrawledUrl]) -> CrawlSummary:
    return CrawlSummary(target_base_url="http://example.com/", urls=urls)


def test_collects_query_parameter_targets():
    crawled = CrawledUrl(
        url="http://example.com/search?q=test",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=1.0,
        depth=0,
        source_url=None,
        parameters=[DiscoveredParameter(name="q", source=ParameterSource.QUERY, sample_value="test")],
    )
    targets = collect_param_targets(_make_summary([crawled]))
    assert len(targets) == 1
    assert targets[0].parameter_name == "q"
    assert targets[0].url == "http://example.com/search"  # query stripped
    assert targets[0].method == HttpMethod.GET


def test_collects_form_field_targets():
    form = DiscoveredForm(
        action="http://example.com/login",
        method=HttpMethod.POST,
        inputs=[{"name": "username", "type": "text", "value": ""}],
    )
    crawled = CrawledUrl(
        url="http://example.com/login-page",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=1.0,
        depth=0,
        source_url=None,
        forms=[form],
    )
    targets = collect_param_targets(_make_summary([crawled]))
    assert len(targets) == 1
    assert targets[0].parameter_name == "username"
    assert targets[0].method == HttpMethod.POST


def test_excludes_password_fields():
    form = DiscoveredForm(
        action="http://example.com/login",
        method=HttpMethod.POST,
        inputs=[
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
        ],
    )
    crawled = CrawledUrl(
        url="http://example.com/login-page",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=1.0,
        depth=0,
        source_url=None,
        forms=[form],
    )
    targets = collect_param_targets(_make_summary([crawled]))
    names = [t.parameter_name for t in targets]
    assert "password" not in names
    assert "username" in names


def test_deduplicates_same_parameter_seen_on_multiple_urls():
    def make_url(url: str) -> CrawledUrl:
        return CrawledUrl(
            url=url,
            method=HttpMethod.GET,
            status_code=200,
            content_type="text/html",
            response_time_ms=1.0,
            depth=0,
            source_url=None,
            parameters=[DiscoveredParameter(name="id", source=ParameterSource.QUERY, sample_value="1")],
        )

    urls = [make_url("http://example.com/item?id=1"), make_url("http://example.com/item?id=2")]
    targets = collect_param_targets(_make_summary(urls))
    # Same base URL + method + parameter name -- deduplicated to one target.
    assert len(targets) == 1


def test_respects_max_targets_cap():
    params = [
        DiscoveredParameter(name=f"p{i}", source=ParameterSource.QUERY, sample_value="1")
        for i in range(10)
    ]
    crawled = CrawledUrl(
        url="http://example.com/search",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=1.0,
        depth=0,
        source_url=None,
        parameters=params,
    )
    targets = collect_param_targets(_make_summary([crawled]), max_targets=3)
    assert len(targets) == 3


def test_skips_forms_with_no_testable_fields():
    form = DiscoveredForm(
        action="http://example.com/login",
        method=HttpMethod.POST,
        inputs=[{"name": "password", "type": "password", "value": ""}],
    )
    crawled = CrawledUrl(
        url="http://example.com/login-page",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=1.0,
        depth=0,
        source_url=None,
        forms=[form],
    )
    targets = collect_param_targets(_make_summary([crawled]))
    assert targets == []
