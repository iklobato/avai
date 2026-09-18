"""Page: the clamped page request every paginated dashboard panel takes."""

from __future__ import annotations

from avai.dashboard.queries import Page
from avai.dashboard.queries.common import MAX_PER_PAGE


class TestPageClamps:
    def test_page_below_one_becomes_one(self):
        assert Page(0, 10).number == 1
        assert Page(-5, 10).number == 1

    def test_size_is_kept_between_one_and_the_max(self):
        assert Page(1, 0).size == 1
        assert Page(1, 999).size == MAX_PER_PAGE
        assert Page(1, 25).size == 25


class TestPageSlice:
    def test_slices_the_requested_page(self):
        rows, fields = Page(2, 3).slice(list(range(8)))
        assert rows == [3, 4, 5]
        assert fields == {"total": 8, "page": 2, "per_page": 3, "total_pages": 3}

    def test_page_past_the_end_falls_back_to_the_last(self):
        rows, fields = Page(99, 3).slice(list(range(8)))
        assert rows == [6, 7]
        assert fields["page"] == 3

    def test_no_rows_is_one_empty_page(self):
        rows, fields = Page(4, 10).slice([])
        assert rows == []
        assert fields == {"total": 0, "page": 1, "per_page": 10, "total_pages": 1}


class TestPageWithin:
    def test_huge_page_gets_an_offset_sqlite_can_hold(self):
        page = Page(10**20, 200).within(1000)
        assert page.number == 5
        assert page.offset == 800
