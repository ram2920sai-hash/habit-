import hashlib
import logging
import time
from urllib.parse import parse_qs,urlsplit

import pytest
from fastapi.testclient import TestClient

import google_login
import server


def test_callback_access_log_redacts_authorization_parameters():
    record=logging.LogRecord('uvicorn.access',logging.INFO,'',0,'%s - "%s %s HTTP/%s" %s',
        ('127.0.0.1','GET','/api/auth/google/callback?code=private-code&state=private-state','1.1',303),None)
    assert google_login.OAuthAccessFilter().filter(record)
    assert 'private-code' not in record.getMessage() and 'private-state' not in record.getMessage()


@pytest.fixture
def oauth(monkeypatch):
    monkeypatch.setenv('GOOGLE_CLIENT_ID','test.apps.googleusercontent.com')
    monkeypatch.setenv('GOOGLE_CLIENT_SECRET','test-secret-never-returned')
    monkeypatch.setenv('NEXO_PUBLIC_ORIGIN','http://testserver')
    # Test callback origin is explicitly substituted, production validates HTTPS.
    monkeypatch.setattr(google_login,'callback_uri',lambda:'http://testserver/api/auth/google/callback')


def begin(client):
    response=client.get('/api/auth/google/start',follow_redirects=False)
    assert response.status_code==302
    query=parse_qs(urlsplit(response.headers['location']).query)
    return response,query


def identity(monkeypatch,query,**overrides):
    claims={'sub':'google-user-123','email':'alice@gmail.com','email_verified':True,'name':'Alice', 'nonce':query['nonce'][0],**overrides}
    monkeypatch.setattr(google_login,'exchange_and_verify',lambda code,verifier:claims)


def finish(client,query,code='fake-code'):
    return client.get('/api/auth/google/callback',params={'state':query['state'][0],'code':code},follow_redirects=False)


def test_unconfigured_button_is_hidden():
    client=TestClient(server.app)
    assert client.get('/api/auth/providers').json()=={'google':False}
    assert client.get('/api/auth/google/start').status_code==503
    assert 'Continue with Google' in client.get('/').text


def test_google_signup_session_and_repeat_login(oauth,monkeypatch):
    client=TestClient(server.app)
    response,query=begin(client)
    assert query['scope']==['openid email profile'] and query['code_challenge_method']==['S256']
    assert 'test-secret' not in response.headers['location']
    assert 'HttpOnly' in response.headers['set-cookie'] and 'SameSite=lax' in response.headers['set-cookie']
    with server.connection() as db:
        row=db.execute('SELECT * FROM oauth_flows').fetchone()
        assert row['state_hash']==hashlib.sha256(query['state'][0].encode()).hexdigest()
        assert row['verifier'] not in response.headers['location']
    identity(monkeypatch,query)
    assert finish(client,query).headers['location']=='/'
    user=client.get('/api/me').json()
    assert user['email']=='alice@gmail.com'
    assert len(client.get('/api/habits').json())==10
    assert finish(client,query).headers['location']=='/?auth_error=google_expired'
    _,again=begin(client)
    identity(monkeypatch,again)
    assert finish(client,again).headers['location']=='/'
    assert client.get('/api/me').json()['id']==user['id']
    with server.connection() as db:
        assert db.execute('SELECT COUNT(*) FROM users').fetchone()[0]==1
        assert db.execute('SELECT COUNT(*) FROM oauth_flows').fetchone()[0]==0


@pytest.mark.parametrize('kind',['wrong_browser','expired','wrong_nonce','unverified','provider_failure','cancelled'])
def test_rejected_google_attempts(oauth,monkeypatch,kind):
    client=TestClient(server.app)
    _,query=begin(client)
    identity(monkeypatch,query)
    if kind=='wrong_browser': client=TestClient(server.app)
    if kind=='expired':
        with server.connection() as db: db.execute('UPDATE oauth_flows SET expires_at=?',(time.time()-1,))
    if kind=='wrong_nonce': identity(monkeypatch,query,nonce='wrong')
    if kind=='unverified': identity(monkeypatch,query,email_verified=False)
    if kind=='provider_failure':
        def fail(*args): raise ValueError('private-provider-data')
        monkeypatch.setattr(google_login,'exchange_and_verify',fail)
    if kind=='cancelled':
        result=client.get('/api/auth/google/callback',params={'state':query['state'][0],'error':'access_denied'},follow_redirects=False)
    else: result=finish(client,query)
    assert result.status_code==303 and result.headers['location'].startswith('/?auth_error=')
    assert 'private-provider-data' not in result.text
    assert client.get('/api/me').status_code==401
    with server.connection() as db: assert db.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0


def test_existing_gmail_account_is_not_silently_merged(oauth,monkeypatch):
    client=TestClient(server.app)
    response=client.post('/api/signup',json={'name':'Local Alice','email':'alice@gmail.com','password':'local-password-123'},headers={'Origin':'http://testserver'})
    assert response.status_code==200
    uid=response.json()['user']['id']
    client.post('/api/habits',json={'name':'Existing private habit'},headers={'Origin':'http://testserver'})
    client.post('/api/logout',headers={'Origin':'http://testserver'})
    _,query=begin(client)
    identity(monkeypatch,query)
    assert finish(client,query).headers['location']=='/?auth_error=google_existing_account'
    assert client.get('/api/me').status_code==401
    assert client.post('/api/login',json={'email':'alice@gmail.com','password':'local-password-123'},headers={'Origin':'http://testserver'}).status_code==200
    assert client.get('/api/me').json()['id']==uid
    assert len(client.get('/api/habits').json())==11
    with server.connection() as db:
        assert db.execute('SELECT COUNT(*) FROM google_identities').fetchone()[0]==0


def test_third_party_email_cannot_take_over_existing_account(oauth,monkeypatch):
    client=TestClient(server.app)
    assert client.post('/api/signup',json={'name':'Alice','email':'alice@example.com','password':'local-password-123'},headers={'Origin':'http://testserver'}).status_code==200
    client.post('/api/logout',headers={'Origin':'http://testserver'})
    _,query=begin(client)
    identity(monkeypatch,query,email='alice@example.com')
    assert finish(client,query).headers['location']=='/?auth_error=google_existing_account'
    assert client.get('/api/me').status_code==401
