import json
import os
import subprocess
import sys

import server


def test_brevo_delivery_uses_https_api(monkeypatch):
    monkeypatch.setenv('BREVO_API_KEY','test-private-key')
    monkeypatch.setenv('EMAIL_FROM','verified@example.com')
    class Response:
        status=201
        def __enter__(self): return self
        def __exit__(self,*args): pass
    def send(request,timeout):
        assert request.full_url=='https://api.brevo.com/v3/smtp/email'
        assert request.get_header('Api-key')=='test-private-key'
        body=json.loads(request.data)
        assert body['to']==[{'email':'a@example.com'}]
        assert body['sender']['email']=='verified@example.com'
        assert '12345678' in body['textContent']
        assert timeout==20
        return Response()
    monkeypatch.setattr(server.urllib.request,'urlopen',send)
    assert server.smtp_ready()
    server.send_reset_email('a@example.com','12345678')


def test_cloud_ssl_validation(monkeypatch):
    from database import Postgres
    seen={}
    def connect(url,**kwargs):
        seen.update(kwargs)
        return object()
    monkeypatch.setattr('database.psycopg.connect',connect)
    Postgres('postgresql://user:private@db.example.com/nexo')
    assert seen['sslmode']=='verify-full' and seen['sslrootcert']=='system'


def test_render_refuses_ephemeral_database():
    env={**os.environ,'RENDER':'true','DATABASE_URL':''}
    response=subprocess.run([sys.executable,'-c','import server'],env=env,capture_output=True,text=True,timeout=30)
    assert response.returncode!=0
    assert 'Set DATABASE_URL' in response.stderr
