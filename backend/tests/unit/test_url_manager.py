from __future__ import annotations

from app.crawler.url_manager import UrlManager


def _always_in_scope(url: str) -> bool:
    return True


def test_seed_adds_url_at_depth_zero():
    manager = UrlManager(max_depth=3, max_urls=100, is_in_scope=_always_in_scope)
    assert manager.seed("http://example.com/") is True
    assert manager.has_next() is True
    item = manager.pop_next()
    assert item.url == "http://example.com/"
    assert item.depth == 0
    assert item.source_url is None


def test_seeding_the_same_url_twice_is_ignored():
    manager = UrlManager(max_depth=3, max_urls=100, is_in_scope=_always_in_scope)
    manager.seed("http://example.com/")
    assert manager.seed("http://example.com/") is False
    assert manager.queue_length == 1


def test_enqueue_discovered_deduplicates_normalized_urls():
    manager = UrlManager(max_depth=3, max_urls=100, is_in_scope=_always_in_scope)
    manager.seed("http://example.com/")
    manager.pop_next()

    assert manager.enqueue_discovered("http://example.com/page", 1, "http://example.com/") is True
    # Same URL, different casing/port -- should normalize to a duplicate.
    assert (
        manager.enqueue_discovered("HTTP://Example.com:80/page", 1, "http://example.com/")
        is False
    )
    assert manager.queue_length == 1


def test_enqueue_discovered_respects_max_depth():
    manager = UrlManager(max_depth=1, max_urls=100, is_in_scope=_always_in_scope)
    manager.seed("http://example.com/")
    manager.pop_next()

    assert manager.enqueue_discovered("http://example.com/ok", 1, "http://example.com/") is True
    assert (
        manager.enqueue_discovered("http://example.com/too-deep", 2, "http://example.com/ok")
        is False
    )


def test_enqueue_discovered_respects_max_urls_cap():
    manager = UrlManager(max_depth=10, max_urls=2, is_in_scope=_always_in_scope)
    manager.seed("http://example.com/")  # counts toward the cap
    manager.pop_next()

    assert manager.enqueue_discovered("http://example.com/a", 1, "http://example.com/") is True
    # Cap (2) reached: seed + /a already consumed it.
    assert manager.enqueue_discovered("http://example.com/b", 1, "http://example.com/") is False


def test_enqueue_discovered_filters_out_of_scope_urls():
    def only_example_com(url: str) -> bool:
        return "example.com" in url

    manager = UrlManager(max_depth=3, max_urls=100, is_in_scope=only_example_com)
    manager.seed("http://example.com/")
    manager.pop_next()

    assert manager.enqueue_discovered("http://evil.com/", 1, "http://example.com/") is False
    assert manager.enqueue_discovered("http://example.com/ok", 1, "http://example.com/") is True


def test_enqueue_discovered_rejects_invalid_urls():
    manager = UrlManager(max_depth=3, max_urls=100, is_in_scope=_always_in_scope)
    manager.seed("http://example.com/")
    manager.pop_next()

    assert manager.enqueue_discovered("javascript:void(0)", 1, "http://example.com/") is False
    assert manager.enqueue_discovered("not a url", 1, "http://example.com/") is False


def test_pop_batch_returns_fifo_order_and_respects_size():
    manager = UrlManager(max_depth=3, max_urls=100, is_in_scope=_always_in_scope)
    manager.seed("http://example.com/")
    manager.pop_next()
    for i in range(5):
        manager.enqueue_discovered(f"http://example.com/{i}", 1, "http://example.com/")

    batch = manager.pop_batch(3)
    assert [item.url for item in batch] == [
        "http://example.com/0",
        "http://example.com/1",
        "http://example.com/2",
    ]
    assert manager.queue_length == 2


def test_discovered_count_tracks_all_seen_urls():
    manager = UrlManager(max_depth=3, max_urls=100, is_in_scope=_always_in_scope)
    manager.seed("http://example.com/")
    manager.pop_next()
    manager.enqueue_discovered("http://example.com/a", 1, "http://example.com/")
    manager.enqueue_discovered("http://example.com/b", 1, "http://example.com/")
    assert manager.discovered_count == 3
