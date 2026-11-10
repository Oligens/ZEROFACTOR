import unittest
from unittest.mock import patch

from fetch_rustsec_metadata import fetch_metadata


class RustSecMetadataTests(unittest.TestCase):
    @patch("fetch_rustsec_metadata.urllib.request.urlopen")
    def test_reads_official_latest_commit_timestamp(self, mocked):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def geturl(self):return "https://api.github.com/repos/RustSec/advisory-db/commits?per_page=1"
            def read(self):
                return b'[{"sha":"abc123","commit":{"committer":{"date":"2026-11-09T12:00:00Z"}}}]'
        mocked.return_value=Response()
        result=fetch_metadata()
        self.assertEqual(result["name"],"RustSec")
        self.assertEqual(result["revision"],"abc123")
        self.assertEqual(result["last_updated"],"2026-11-09T12:00:00Z")

    def test_rejects_untrusted_host(self):
        with self.assertRaises(ValueError):
            fetch_metadata("https://example.com/repos/RustSec/advisory-db/commits")


if __name__=="__main__":unittest.main()
