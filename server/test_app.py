import json,os,tempfile,unittest
from io import BytesIO
from unittest.mock import patch
import app
class ApiTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.NamedTemporaryFile(delete=False);self.tmp.close()
  self.patch=patch.dict(os.environ,{"ZEROFACTOR_DB":self.tmp.name});self.patch.start();app.DB=self.tmp.name
 def tearDown(self):
  self.patch.stop();os.unlink(self.tmp.name)
 def call(self,path,method="GET",payload=None,cookies="",csrf=""):
  raw=json.dumps(payload or {}).encode();env={"REQUEST_METHOD":method,"PATH_INFO":path,"CONTENT_LENGTH":str(len(raw)),"wsgi.input":BytesIO(raw),"HTTP_COOKIE":cookies,"HTTP_X_CSRF_TOKEN":csrf}
  got={}
  def start(status,headers):got.update(status=status,headers=headers)
  data=b"".join(app.app(env,start));return got,json.loads(data)
 def register_login(self,email):
  self.call("/api/register","POST",{"email":email,"password":"long-secure-password"})
  r,_=self.call("/api/login","POST",{"email":email,"password":"long-secure-password"})
  self.assertTrue(r["status"].startswith("200"))
  session=[v for k,v in r["headers"] if k=="Set-Cookie" and v.startswith("zf_session")][0].split(";",1)[0]
  csrf=[v for k,v in r["headers"] if k=="Set-Cookie" and v.startswith("zf_csrf")][0].split(";",1)[0].split("=",1)[1]
  return session+"; zf_csrf="+csrf,csrf
 def test_registration_login_and_project_isolation(self):
  cookies,csrf=self.register_login("a@example.test")
  r,project=self.call("/api/projects","POST",{"name":"private project"},cookies,csrf)
  self.assertTrue(r["status"].startswith("201"))
  r,data=self.call("/api/projects","GET",cookies=cookies)
  self.assertEqual(data["projects"][0]["name"],"private project")
  other_cookies,other_csrf=self.register_login("b@example.test")
  r,_=self.call("/api/projects/"+project["id"],cookies=other_cookies)
  self.assertTrue(r["status"].startswith("404"))
  r,_=self.call("/api/projects/"+project["id"]+"/members","POST",{"email":"b@example.test","role":"viewer"},cookies,csrf)
  self.assertTrue(r["status"].startswith("201"))
  r,data=self.call("/api/projects","GET",cookies=other_cookies)
  self.assertEqual(data["projects"][0]["role"],"viewer")
  r,_=self.call("/api/projects/"+project["id"]+"/assessments","POST",{"label":"not allowed","report":{}},other_cookies,other_csrf)
  self.assertTrue(r["status"].startswith("403"))
 def test_csrf_blocks_authenticated_mutation(self):
  cookies,_=self.register_login("csrf@example.test")
  r,_=self.call("/api/projects","POST",{"name":"blocked"},cookies)
  self.assertTrue(r["status"].startswith("403"))
 def test_dashboard_home_served_by_same_origin_api(self):
  env={"REQUEST_METHOD":"GET","PATH_INFO":"/","CONTENT_LENGTH":"0","wsgi.input":BytesIO(b"")}
  got={}
  def start(status,headers):got.update(status=status,headers=headers)
  body=b"".join(app.app(env,start))
  self.assertTrue(got["status"].startswith("200"))
  self.assertIn(b"ZEROFACTOR",body)
 def test_short_password_is_rejected(self):
  r,_=self.call("/api/register","POST",{"email":"weak@example.test","password":"short"})
  self.assertTrue(r["status"].startswith("400"))
if __name__=="__main__":unittest.main()
