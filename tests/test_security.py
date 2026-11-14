import hashlib
import importlib
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

os.environ['NEXO_ALLOWED_HOSTS']='testserver,localhost,127.0.0.1'
import server



def account(email='a@example.com'):
    client=TestClient(server.app)
    response=client.post('/api/signup',json={'name':'Alice','email':email,'password':'private-password-123'})
    assert response.status_code==200,response.text
    return client,response


@pytest.fixture
def mail(monkeypatch):
    outbox=[]
    monkeypatch.setenv('SMTP_HOST','smtp.example.com')
    monkeypatch.setenv('SMTP_FROM','nexo@example.com')
    monkeypatch.setattr(server,'send_reset_email',lambda email,code: outbox.append((email,code)))
    return outbox


def request_code(client,mail):
    response=client.post('/api/reset/request',json={'email':'a@example.com'})
    assert response.status_code==200,response.text
    assert len(mail[-1][1])==8
    assert mail[-1][1] not in response.text
    return mail[-1][1]


def reset(client,code):
    return client.post('/api/recover',json={'email':'a@example.com','recovery_code':code,'new_password':'replacement-password-456'})


def test_sessions_storage_and_logout():
    client,response=account()
    cookie=response.headers['set-cookie']
    assert 'HttpOnly' in cookie and 'SameSite=strict' in cookie and 'Max-Age=2592000' in cookie
    token=client.cookies['nexo_session']
    with server.connection() as db:
        user=db.execute('SELECT * FROM users').fetchone()
        session=db.execute('SELECT * FROM sessions').fetchone()
        assert user['password_hash']!='private-password-123'
        assert user['salt'].startswith('v2:')
        assert session['token_hash']==hashlib.sha256(token.encode()).hexdigest()
    # A new application module instance reads the same on-disk database.
    reopened=importlib.util.module_from_spec(importlib.util.spec_from_file_location('nexo_restarted',server.__file__))
    spec=importlib.util.spec_from_file_location('nexo_restarted',server.__file__)
    previous=os.environ.get('NEXO_DATA_DIR')
    os.environ['NEXO_DATA_DIR']=str(server.DB.parent)
    try:
        spec.loader.exec_module(reopened)
        reopened.DB=server.DB
        browser=TestClient(reopened.app)
        browser.cookies.set('nexo_session',token)
        assert browser.get('/api/me').status_code==200
    finally:
        if previous is None: os.environ.pop('NEXO_DATA_DIR',None)
        else: os.environ['NEXO_DATA_DIR']=previous
    assert client.post('/api/logout').status_code==200
    browser.cookies.set('nexo_session',token)
    assert browser.get('/api/me').status_code==401


def test_reset_single_use_and_session_revocation(mail):
    client,_=account()
    old_token=client.cookies['nexo_session']
    code=request_code(client,mail)
    with server.connection() as db:
        row=db.execute('SELECT * FROM password_resets').fetchone()
        assert row['code_hash']!=code and server.check_hash(code,row['code_hash'],row['salt'])
    assert reset(client,code).status_code==200
    assert reset(client,code).status_code==400
    assert client.get('/api/me').status_code==401
    assert client.post('/api/login',json={'email':'a@example.com','password':'private-password-123'}).status_code==401
    assert client.post('/api/login',json={'email':'a@example.com','password':'replacement-password-456'}).status_code==200
    assert client.cookies['nexo_session']!=old_token


def test_reset_expiry_attempt_limit_and_reissue(mail):
    client,_=account()
    code=request_code(client,mail)
    wrong='00000000' if code!='00000000' else '11111111'
    for _ in range(5): assert reset(client,wrong).status_code==400
    assert reset(client,code).status_code==400
    code=request_code(client,mail)
    with server.connection() as db: db.execute('UPDATE password_resets SET expires_at=?',(time.time()-1,))
    assert reset(client,code).status_code==400
    replacement=request_code(client,mail)
    assert reset(client,replacement).status_code==200
    assert client.post('/api/reset/request',json={'email':'a@example.com'}).status_code==429


def test_reset_unknown_email_and_unconfigured_smtp(mail,monkeypatch):
    client,_=account()
    known=client.post('/api/reset/request',json={'email':'a@example.com'})
    unknown=client.post('/api/reset/request',json={'email':'unknown@example.com'})
    assert known.json()==unknown.json() and known.status_code==unknown.status_code==200
    assert len(mail)==1
    monkeypatch.delenv('SMTP_HOST')
    assert client.post('/api/reset/request',json={'email':'a@example.com'}).status_code==503


def test_smtp_failure_invalidates_code(mail,monkeypatch,caplog):
    client,_=account()
    def failure(email,code): raise RuntimeError('secret-must-not-be-logged')
    monkeypatch.setattr(server,'send_reset_email',failure)
    assert client.post('/api/reset/request',json={'email':'a@example.com'}).status_code==200
    with server.connection() as db: assert db.execute('SELECT COUNT(*) FROM password_resets').fetchone()[0]==0
    assert 'secret-must-not-be-logged' not in caplog.text


def test_concurrent_redemption_only_once(mail):
    client,_=account()
    code=request_code(client,mail)
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses=list(pool.map(lambda _:reset(TestClient(server.app),code).status_code,range(2)))
    assert sorted(statuses)==[200,400]


def test_privacy_themes_and_mutations():
    alice,_=account()
    bob,_=account('b@example.com')
    hid=alice.get('/api/habits').json()[0]['id']
    assert alice.put(f'/api/habits/{hid}',json={'name':'Alice private habit'}).status_code==200
    for method,path,payload in [
        ('put',f'/api/habits/{hid}',{'name':'Intrusion'}),
        ('put',f'/api/habits/{hid}/check',{'log_date':bob.get('/api/overview').json()['today'],'completed':True}),
        ('post',f'/api/habits/{hid}/archive',None),
        ('post',f'/api/habits/{hid}/reset',None),
        ('delete',f'/api/habits/{hid}',None)]:
        assert bob.request(method,path,json=payload).status_code==404
    for path in ['/api/habits','/api/overview','/api/insights','/api/export/backup']:
        assert 'Alice private habit' not in bob.get(path).text
        assert TestClient(server.app).get(path).status_code==401
    backup=bob.get('/api/export/backup').content
    assert bob.post('/api/restore',content=backup).status_code==200
    assert alice.get('/api/habits').json()[0]['name']=='Alice private habit'
    assert alice.put('/api/me',json={'name':'Alice','theme':'dark'}).status_code==200
    assert alice.get('/api/me').json()['theme']=='dark'
    assert bob.get('/api/me').json()['theme']=='light'
    assert alice.put('/api/me',json={'name':'Alice','theme':'invalid'}).status_code==400
    for field in ('password_hash','salt','recovery_hash'):
        assert field not in alice.get('/api/me').text


def test_headers_origin_host_expiry_and_throttle(monkeypatch):
    client,_=account()
    assert client.get('/api/me').headers['cache-control']=='no-store'
    assert client.get('/').headers['x-frame-options']=='DENY'
    assert client.post('/api/logout',headers={'Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/logout',headers={'Sec-Fetch-Site':'cross-site'}).status_code==403
    assert client.get('/',headers={'Host':'evil.example'}).status_code==400
    with server.connection() as db: db.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'")
    assert client.get('/api/me').status_code==401
    for _ in range(10): assert client.post('/api/login',json={'email':'a@example.com','password':'wrong'}).status_code==401
    assert client.post('/api/login',json={'email':'a@example.com','password':'wrong'}).status_code==429
    monkeypatch.setenv('NEXO_HTTPS','1')
    secure=TestClient(server.app,base_url='https://testserver')
    response=secure.post('/api/signup',json={'name':'Secure','email':'secure@example.com','password':'private-password-123'})
    assert any(cookie.name=='nexo_session' and cookie.secure for cookie in response.cookies.jar)
    assert secure.get('/api/me').status_code==200


def test_legacy_password_migration():
    client,_=account()
    salt='ab'*16
    digest=hashlib.pbkdf2_hmac('sha256',b'private-password-123',bytes.fromhex(salt),300000).hex()
    with server.connection() as db: db.execute('UPDATE users SET password_hash=?,salt=?',(digest,salt))
    assert client.post('/api/login',json={'email':'a@example.com','password':'private-password-123'}).status_code==200
    with server.connection() as db: assert db.execute('SELECT salt FROM users').fetchone()[0].startswith('v2:')


@pytest.mark.parametrize('mode',['starttls','ssl'])
def test_smtp_transport(monkeypatch,mode):
    events=[]
    class SMTP:
        def __init__(self,host,port,**kwargs):
            assert host=='smtp.example.com'
            assert ('context' in kwargs)==(mode=='ssl')
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def starttls(self,context): events.append('tls')
        def login(self,user,password):
            assert user=='sender' and password=='private-key'
            events.append('login')
        def send_message(self,msg):
            assert msg['To']=='a@example.com' and '12345678' in msg.get_content()
            events.append('sent')
    for key,value in {'SMTP_HOST':'smtp.example.com','SMTP_FROM':'nexo@example.com','SMTP_USERNAME':'sender','SMTP_PASSWORD':'private-key','SMTP_SECURITY':mode}.items(): monkeypatch.setenv(key,value)
    monkeypatch.setattr(server.smtplib,'SMTP',SMTP)
    monkeypatch.setattr(server.smtplib,'SMTP_SSL',SMTP)
    server.send_reset_email('a@example.com','12345678')
    assert events==(['tls','login','sent'] if mode=='starttls' else ['login','sent'])


def test_password_change_blocks_stale_login_session():
    client,_=account()
    with server.connection() as db:
        row=db.execute('SELECT * FROM users').fetchone()
        db.execute('UPDATE users SET password_hash=? WHERE id=?',('changed',row['id']))
    with pytest.raises(server.HTTPException) as exc:
        server.issue_session(server.Response(),row['id'],row['password_hash'])
    assert exc.value.status_code==401


def test_deployment_origin_and_health(monkeypatch):
    monkeypatch.setenv('NEXO_PUBLIC_ORIGIN','https://nexo.example.com')
    client=TestClient(server.app)
    assert client.get('/healthz').json()=={'ok':True}
    assert client.post('/api/logout',headers={'Origin':'https://nexo.example.com'}).status_code==200
    assert client.post('/api/logout',headers={'Origin':'http://testserver'}).status_code==403
