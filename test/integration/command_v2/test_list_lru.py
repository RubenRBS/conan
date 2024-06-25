import time

from unittest import mock
from unittest.mock import patch

import pytest
from mock.mock import MagicMock

from conan.test.assets.genconanfile import GenConanfile
from conan.test.utils.tools import TestClient


class TestLRU:
    def test_error_lru_remote(self):
        c = TestClient(default_server_user=True)
        c.run("list * --lru=1s -r=default", assert_error=True)
        assert "'--lru' cannot be used in remotes, only in cache" in c.out

    @patch("conans.util.dates.timestamp_now")
    @patch("conans.util.dates.revision_timestamp_now")
    @pytest.mark.parametrize("method", ["list", "remove"])
    def test_cache_clean_lru(self, timestamp_now_mock, revision_timestamp_now_mock, method):
        time_offset = 0

        def current_time():
            return time.time() + time_offset

        def timestamp_now():
            # seconds since epoch 0, easy to store, in UTC
            import calendar
            return calendar.timegm(time.gmtime(current_time()))

        def revision_timestamp_now():
            return current_time()

        timestamp_now_mock.side_effect = timestamp_now
        revision_timestamp_now_mock.side_effect = revision_timestamp_now

        c = TestClient()
        c.save({"conanfile.py": GenConanfile()})
        c.run("create . --name=pkg --version=0.1")
        c.run("create . --name=dep --version=0.2")

        time_offset += 2
        # This should update the LRU
        c.run("install --requires=pkg/0.1")
        # Removing recipes (+ its binaries) that recipes haven't been used
        if method == "list":
            c.run("list *#* --lru=1s --format=json", redirect_stdout="old.json")
            c.run("remove --list=old.json -c")
        else:
            c.run("remove * --lru=1s -c")
        # Do the checks
        c.run("list *:*#*")
        assert "pkg" in c.out
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in c.out
        assert "dep" not in c.out

        time_offset += 2
        # This should update the LRU of the recipe only
        c.run("graph info --requires=pkg/0.1")
        # IMPORTANT: Note the pattern is NOT the same as the equivalent for 'conan remove'
        if method == "list":
            c.run("list *#*:*#* --lru=1s --format=json", redirect_stdout="old.json")
            c.run("remove --list=old.json -c")
        else:
            c.run("remove *:* --lru=1s -c")

        # Check the binary has been removed, but the recipe is still there
        c.run("list *:*")

        assert "pkg" in c.out
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" not in c.out
        assert "dep" not in c.out
