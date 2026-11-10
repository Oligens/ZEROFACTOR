import datetime as dt
import email.utils
import unittest
from unittest.mock import patch

from fetch_osv_metadata import fetch_metadata


class MetadataTests(unittest.TestCase):
    @patch("fetch_osv_metadata.urllib.request.urlopen")
    def test_reads_upstream_last_modified(self, mocked):
        class Response:
            status = 200
            headers = {"Last-Modified": "Mon, 09 Nov 2026 12:00:00 GMT"}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
        mocked.return_value = Response()
        value = fetch_metadata()
        self.assertEqual(value["name"], "OSV")
        self.assertEqual(value["last_updated"], "2026-11-09T12:00:00Z")

    def test_rejects_non_approved_url(self):
        with self.assertRaises(ValueError):
            fetch_metadata("https://example.com/all.zip")


if __name__ == "__main__":
    unittest.main()
