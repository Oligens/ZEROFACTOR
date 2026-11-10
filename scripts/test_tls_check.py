import json
import pathlib
import tempfile
import unittest
from unittest.mock import MagicMock
from tls_check import run

class FakeSecureSocket:
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def getpeercert(self,binary_form=False):
        if binary_form: return b"synthetic-certificate"
        return {"notBefore":"Jan  1 00:00:00 2026 GMT","notAfter":"Jan  1 00:00:00 2028 GMT"}
    def cipher(self): return ("TLS_AES_128_GCM_SHA256","TLSv1.3",128)
    def version(self): return "TLSv1.3"

class FakeContext:
    minimum_version=None
    def wrap_socket(self,raw,server_hostname):
        self.server_hostname=server_hostname
        return FakeSecureSocket()

class TLSModuleTests(unittest.TestCase):
    def scope(self,modules):
        return {"authorization_id":"written-auth-0001","authorized":True,"owner":"Synthetic Lab Owner",
                "target_url":"https://fixture.example.test/","allowed_hosts":["fixture.example.test"],
                "expires_at":"2099-01-01T00:00:00Z","modules":modules,"timeout_seconds":3}
    def test_performs_one_verified_handshake_and_records_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            scope=pathlib.Path(td)/"scope.json"; output=pathlib.Path(td)/"tls.json"
            scope.write_text(json.dumps(self.scope(["TLS"])))
            fake_context=FakeContext()
            connect=MagicMock()
            connect.return_value.__enter__.return_value="raw"
            self.assertEqual(run(scope,output,connect=connect,context_factory=lambda:fake_context),0)
            payload=json.loads(output.read_text())
            self.assertEqual(payload["result"],"pass")
            self.assertEqual(payload["details"]["tls_version"],"TLSv1.3")
            self.assertEqual(payload["safety"]["handshakes"],1)
            connect.assert_called_once_with(("fixture.example.test",443),timeout=3)
    def test_requires_explicit_tls_module_permission_before_network(self):
        with tempfile.TemporaryDirectory() as td:
            scope=pathlib.Path(td)/"scope.json"; output=pathlib.Path(td)/"tls.json"
            scope.write_text(json.dumps(self.scope(["HTTP_POSTURE"])))
            connect=MagicMock()
            with self.assertRaisesRegex(ValueError,"authorize the TLS"):
                run(scope,output,connect=connect)
            connect.assert_not_called()

if __name__=="__main__":
    unittest.main()
