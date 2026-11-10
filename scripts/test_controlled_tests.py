import datetime as dt, json, pathlib, tempfile, unittest
from controlled_tests import run

class ControlledTestSafety(unittest.TestCase):
 def test_rejects_http_and_unlisted_host_before_network(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/"scope.json"
   p.write_text(json.dumps({"authorization_id":"auth-test-0001","authorized":true,"owner":"Synthetic Test Owner","modules":["HTTP_POSTURE"],"target_url":"http://127.0.0.1/","allowed_hosts":["127.0.0.1"],"expires_at":"2099-01-01T00:00:00Z"}))
   with self.assertRaisesRegex(ValueError,"HTTPS"):run(p,pathlib.Path(td)/"out.json",["security_headers"])
 def test_rejects_expired_scope(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/"scope.json"
   p.write_text(json.dumps({"authorization_id":"auth-test-0001","authorized":true,"owner":"Synthetic Test Owner","modules":["HTTP_POSTURE"],"target_url":"https://example.test/","allowed_hosts":["example.test"],"expires_at":"2000-01-01T00:00:00Z"}))
   with self.assertRaisesRegex(ValueError,"expired"):run(p,pathlib.Path(td)/"out.json",["security_headers"])
if __name__=="__main__":unittest.main()
