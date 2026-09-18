from __future__ import annotations

from app.crawler.parser import (
    extract_form_parameters,
    extract_forms,
    extract_links,
    extract_query_parameters,
)
from app.models.enums import HttpMethod, ParameterSource


def test_extract_links_resolves_relative_links():
    html = """
    <html><body>
        <a href="/about">About</a>
        <a href="contact.html">Contact</a>
        <a href="https://external.com/page">External</a>
    </body></html>
    """
    links = extract_links(html, "http://example.com/dir/")
    assert "http://example.com/about" in links
    assert "http://example.com/dir/contact.html" in links
    assert "https://external.com/page" in links


def test_extract_links_skips_non_navigational_hrefs():
    html = """
    <html><body>
        <a href="mailto:test@example.com">Mail</a>
        <a href="tel:+123456">Call</a>
        <a href="javascript:void(0)">JS</a>
        <a href="#section">Anchor</a>
        <a href="data:text/plain,hi">Data</a>
        <a href="/real-page">Real</a>
    </body></html>
    """
    links = extract_links(html, "http://example.com/")
    assert links == ["http://example.com/real-page"]


def test_extract_links_deduplicates():
    html = """
    <a href="/page">One</a>
    <a href="/page">Two</a>
    """
    links = extract_links(html, "http://example.com/")
    assert links == ["http://example.com/page"]


def test_extract_forms_defaults_to_get_method():
    html = '<form action="/search"><input name="q" type="text"></form>'
    forms = extract_forms(html, "http://example.com/")
    assert len(forms) == 1
    assert forms[0].method == HttpMethod.GET
    assert forms[0].action == "http://example.com/search"


def test_extract_forms_respects_explicit_post_method():
    html = '<form action="/login" method="POST"><input name="username"></form>'
    forms = extract_forms(html, "http://example.com/")
    assert forms[0].method == HttpMethod.POST


def test_extract_forms_captures_input_fields():
    html = """
    <form action="/login" method="post">
        <input name="username" type="text" value="">
        <input name="password" type="password">
        <textarea name="comments"></textarea>
        <select name="role"><option value="admin">Admin</option></select>
        <input type="submit" value="Go">
    </form>
    """
    forms = extract_forms(html, "http://example.com/")
    names = {f["name"] for f in forms[0].inputs}
    assert names == {"username", "password", "comments", "role"}


def test_extract_forms_without_action_defaults_to_base_url():
    html = '<form><input name="q"></form>'
    forms = extract_forms(html, "http://example.com/search-page")
    assert forms[0].action == "http://example.com/search-page"


def test_extract_query_parameters_deduplicates_by_name():
    params = extract_query_parameters("http://example.com/search?q=test&q=ignored&page=2")
    names = [p.name for p in params]
    assert names == ["q", "page"]
    assert params[0].sample_value == "test"
    assert all(p.source == ParameterSource.QUERY for p in params)


def test_extract_query_parameters_empty_for_no_query_string():
    assert extract_query_parameters("http://example.com/page") == []


def test_extract_form_parameters_uses_form_source_for_post():
    html = '<form action="/login" method="post"><input name="username"></form>'
    form = extract_forms(html, "http://example.com/")[0]
    params = extract_form_parameters(form)
    assert params[0].source == ParameterSource.FORM


def test_extract_form_parameters_uses_query_source_for_get():
    html = '<form action="/search" method="get"><input name="q"></form>'
    form = extract_forms(html, "http://example.com/")[0]
    params = extract_form_parameters(form)
    assert params[0].source == ParameterSource.QUERY
