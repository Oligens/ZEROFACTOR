import json, os, tempfile, unittest
from io import BytesIO
from unittest.mock import patch
import app

class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.NamedTemporaryFile(delete=False);self.tmp.close()
        self.patch=patch.dict(os.environ,{"ZEROFACTOR_DB":self.tmp.name});self.patch.start()
        app.DB=self.tmp.name
    def tearDown(self):
        self.patch.stop();os.unlink(self.tmp.name)
    def call(self,path,method="GET",payload=None,cookies="",csrf=""):
        raw=json.dumps(payload or {}).encode();env={"REQUEST_METHOD":method,"PATH_INFO":path,"CONTENT_LENGTH":str(len(raw)),"wsgi.input":BytesIO(raw),"HTTP_COOKIE":cookies,"HTTP_X_CSRF_TOKEN":csrf}
        got={}
        def start(status,headers):got.update(status=status,headers=headers)
        data=b"".join(app.app(env,start))
        return got,json.loads(data)
    def test_register_login_and_project_isolation(self):
        r,_=self.call("/api/register","POST",{"email":"a@example.test","password":"long-secure-password"})
        self.assertTrue(r["status"].startswith("201"))
        r,p=self.call("/api/login","POST",{"email":"a@example.test","password":"long-secure-password"})
        self.assertTrue(r["status"].startswith("200"))
        headers=dict(r["headers"]); session=[v for k,v in r["headers"] if k=="Set-Cookie" and v.startswith("zf_session")][0].split(";",1)[0]
        csrf=[v for k,v in r["headers"] if k=="Set-Cookie" and v.startswith("zf_csrf")][0].split(";",1)[0].split("=",1)[1]
        r,project=self.call("/api/projects","POST",{"name":"private project"},session+"; zf_csrf="+csrf,csrf)
        self.assertTrue(r["status"].startswith("201"))
        self.assertEqual(self.call("/api/projects","GET",cookies=session+"; zf_csrf="+csrf)[1]["projects"][0]["name"],"private project")
        other,_=self.call("/api/projects/"+project["id"],cookies="")
        self.assertTrue(other["status"].startswith("401"))
    def test_csrf_blocks_mutation(self):
        self.call("/api/register","POST",{"email":"b@example.test","password":"long-secure-password"})
        r,_=self.call("/api/projects","POST",{"name":"x"})
        self.assertTrue(r["status"].startswith("401"))

if __name__=="__main__":unittest.main()
