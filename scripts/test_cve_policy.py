import datetime as dt, unittest
from cve_policy import evaluate

class PolicyTests(unittest.TestCase):
 def test_blocks_high_severity_exact_match(self):
  now=dt.datetime(2026,11,9,tzinfo=dt.timezone.utc)
  data={"sources":[{"name":"OSV","last_updated":"2026-11-08T00:00:00Z"}],"matches":[{"package":"demo","resolved_version":"1.2.3","version_match":True,"severity_label":"HIGH","source":"OSV"}]}
  result=evaluate(data,{"max_database_age_days":7,"allowed_sources":["OSV"],"fail_on_or_above":"high"},now)
  self.assertFalse(result["passed"]);self.assertEqual(len(result["decisions"]["block"]),1)
 def test_stale_source_fails_closed(self):
  now=dt.datetime(2026,11,9,tzinfo=dt.timezone.utc)
  result=evaluate({"sources":[{"name":"OSV","last_updated":"2026-10-01T00:00:00Z"}],"matches":[]},{"max_database_age_days":7,"allowed_sources":["OSV"]},now)
  self.assertFalse(result["passed"]);self.assertTrue(result["source_errors"])
 def test_unversioned_match_is_review_not_block(self):
  result=evaluate({"sources":[],"matches":[{"package":"demo","severity_label":"critical"}]},{"allowed_sources":[]})
  self.assertFalse(result["passed"]);self.assertEqual(len(result["decisions"]["review"]),1)
if __name__=="__main__":unittest.main()
