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


def test_bracketed_dns_hostname_does_not_change_password(monkeypatch):
    from database import Postgres
    captured=[]
    monkeypatch.setattr('database.psycopg.connect',lambda url,**kwargs:captured.append((url,kwargs)))
    Postgres('postgresql://postgres.project:fake%40password@[aws-0-ap-south-1.pooler.supabase.com]:5432/postgres?sslmode=verify-full')
    assert captured[0][0]=='postgresql://postgres.project:fake%40password@aws-0-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=verify-full'
    assert captured[0][1]['sslmode']=='verify-full'


def test_standard_uri_and_ipv6_are_preserved(monkeypatch):
    from database import Postgres
    captured=[]
    monkeypatch.setattr('database.psycopg.connect',lambda url,**kwargs:captured.append(url))
    for url in ('postgresql://user:fake%5Bpassword%5D@db.example.com/db','postgresql://user:fake@[::1]:5432/db'):
        Postgres(url)
        assert captured[-1]==url


def test_separate_database_password_preserves_symbols(monkeypatch):
    from database import Postgres
    captured=[]
    password='fake[]@#%/? password'
    monkeypatch.setenv('DATABASE_PASSWORD',password)
    monkeypatch.setattr('database.psycopg.connect',lambda url,**kwargs:captured.append((url,kwargs)))
    url='postgresql://postgres.project@aws-0-ap-south-1.pooler.supabase.com:5432/postgres'
    Postgres(url)
    assert captured[0][0]==url
    assert captured[0][1]['password']==password
    assert captured[0][1]['sslmode']=='verify-full'
    assert captured[0][1]['sslrootcert'].endswith('supabase-ca.crt')


def test_supabase_ca_is_a_public_ca_certificate():
    import ssl
    from pathlib import Path
    certificate=Path(server.__file__).parent/'certs'/'supabase-ca.crt'
    assert certificate.exists()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(certificate))
    assert context.cert_store_stats()['x509_ca']==1
