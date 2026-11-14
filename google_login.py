"""Google OpenID Connect authorization-code login with PKCE and browser binding."""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token


class OAuthAccessFilter(logging.Filter):
    """Keep authorization codes and state out of Uvicorn request logs."""
    def filter(self, record):
        if isinstance(record.args, tuple) and len(record.args) == 5:
            address, method, path, protocol, status = record.args
            if isinstance(path, str) and path.split('?', 1)[0] == '/api/auth/google/callback':
                record.args = (address, method, path.split('?', 1)[0], protocol, status)
        return True


logging.getLogger('uvicorn.access').addFilter(OAuthAccessFilter())


def configured():
    return bool(os.getenv('GOOGLE_CLIENT_ID') and os.getenv('GOOGLE_CLIENT_SECRET') and os.getenv('NEXO_PUBLIC_ORIGIN'))


def callback_uri():
    origin=os.environ['NEXO_PUBLIC_ORIGIN'].rstrip('/')
    parsed=urllib.parse.urlsplit(origin)
    if parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in ('localhost','127.0.0.1')):
        raise ValueError('Google login requires an HTTPS public origin')
    if parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise ValueError('Configure a plain public origin')
    return origin+'/api/auth/google/callback'


def exchange_and_verify(code,verifier):
    body=urllib.parse.urlencode({'code':code,'client_id':os.environ['GOOGLE_CLIENT_ID'],
        'client_secret':os.environ['GOOGLE_CLIENT_SECRET'],'redirect_uri':callback_uri(),
        'grant_type':'authorization_code','code_verifier':verifier}).encode()
    request=urllib.request.Request('https://oauth2.googleapis.com/token',data=body,
        headers={'Content-Type':'application/x-www-form-urlencoded'},method='POST')
    with urllib.request.urlopen(request,timeout=20) as response:
        tokens=json.loads(response.read(65536))
    transport=GoogleRequest()
    def bounded_request(*args,**kwargs):
        kwargs.setdefault('timeout',10)
        return transport(*args,**kwargs)
    # Google's library verifies signature, issuer, audience, and expiry.
    return id_token.verify_oauth2_token(tokens['id_token'],bounded_request,os.environ['GOOGLE_CLIENT_ID'])


def failure(reason):
    response=RedirectResponse('/?auth_error='+reason,status_code=303)
    response.delete_cookie('nexo_google_flow',path='/api/auth/google',httponly=True,samesite='lax',secure=os.getenv('NEXO_HTTPS')=='1')
    return response


def register(app,connection,make_hash,issue_session,defaults,rate_limit):
    @app.get('/api/auth/providers')
    def providers():
        return {'google':configured()}

    @app.get('/api/auth/google/start')
    def start(request:Request):
        if not configured(): raise HTTPException(503,'Google sign-in is not configured yet')
        rate_limit('google:'+request.client.host,30,900)
        state=secrets.token_urlsafe(32)
        browser=secrets.token_urlsafe(32)
        verifier=secrets.token_urlsafe(48)
        nonce=secrets.token_urlsafe(32)
        redirect=callback_uri()
        with connection() as db:
            db.execute('DELETE FROM oauth_flows WHERE expires_at<?',(time.time(),))
            db.execute('INSERT INTO oauth_flows VALUES(?,?,?,?,?)',
                (hashlib.sha256(state.encode()).hexdigest(),hashlib.sha256(browser.encode()).hexdigest(),verifier,nonce,time.time()+600))
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        query=urllib.parse.urlencode({'client_id':os.environ['GOOGLE_CLIENT_ID'],'redirect_uri':redirect,
            'response_type':'code','scope':'openid email profile','state':state,'nonce':nonce,
            'code_challenge':challenge,'code_challenge_method':'S256','prompt':'select_account'})
        response=RedirectResponse('https://accounts.google.com/o/oauth2/v2/auth?'+query,status_code=302)
        response.set_cookie('nexo_google_flow',browser,max_age=600,httponly=True,secure=os.getenv('NEXO_HTTPS')=='1',
            samesite='lax',path='/api/auth/google')
        return response

    @app.get('/api/auth/google/callback')
    def callback(request:Request,state:str='',code:str='',error:str=''):
        if not configured(): return failure('google_unavailable')
        if not state or len(state)>256: return failure('google_expired')
        browser=request.cookies.get('nexo_google_flow','')
        if not browser or len(browser)>256: return failure('google_expired')
        # Atomically consume only a flow belonging to this browser, once.
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            flow=db.execute('SELECT * FROM oauth_flows WHERE state_hash=? AND browser_hash=? AND expires_at>?',
                (hashlib.sha256(state.encode()).hexdigest(),hashlib.sha256(browser.encode()).hexdigest(),time.time())).fetchone()
            if flow:
                db.execute('DELETE FROM oauth_flows WHERE state_hash=?',(flow['state_hash'],))
        if not flow: return failure('google_expired')
        if error: return failure('google_cancelled')
        if not code or len(code)>4096: return failure('google_failed')
        try:
            claims=exchange_and_verify(code,flow['verifier'])
            if not isinstance(claims.get('nonce'),str) or not hmac.compare_digest(claims['nonce'],flow['nonce']):
                return failure('google_failed')
            email=claims.get('email','').strip().lower()
            subject=claims.get('sub','')
            if claims.get('email_verified') is not True or not isinstance(subject,str) or not subject or len(subject)>255:
                return failure('google_failed')
            if len(email)>254 or '@' not in email: return failure('google_failed')
        except Exception:
            # Never return/log provider tokens, codes, credentials, or raw exceptions.
            return failure('google_failed')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            identity=db.execute('SELECT user_id FROM google_identities WHERE subject=?',(subject,)).fetchone()
            if identity:
                uid=identity['user_id']
            else:
                user=db.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
                if user:
                    # Local emails were not verified at signup. Never silently merge
                    # accounts: an old local password could otherwise retain access.
                    return failure('google_existing_account')
                else:
                    ph,ps=make_hash(secrets.token_urlsafe(48))
                    rh,rs=make_hash(secrets.token_urlsafe(48))
                    name=str(claims.get('name') or email.split('@')[0]).strip()[:80] or 'NEXO user'
                    cur=db.execute('INSERT INTO users(name,email,password_hash,salt,recovery_hash,recovery_salt,timezone,created_at) VALUES(?,?,?,?,?,?,?,?)',
                        (name,email,ph,ps,rh,rs,'Asia/Kolkata',datetime.now(timezone.utc).isoformat()))
                    uid=cur.lastrowid
                    # Same initial habits as an email/password account, scoped to this user.
                    from zoneinfo import ZoneInfo
                    day=datetime.now(ZoneInfo('Asia/Kolkata')).date().isoformat()
                    for emoji,title,category,value,unit,frequency,target in defaults:
                        db.execute('INSERT INTO habits(user_id,name,emoji,category,goal_value,goal_unit,frequency,target_count,goal_label,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                            (uid,title,emoji,category,value,unit,frequency,target,str(value)+' '+unit,day))
                db.execute('INSERT INTO google_identities(subject,user_id) VALUES(?,?)',(subject,uid))
        response=RedirectResponse('/',status_code=303)
        issue_session(response,uid)
        response.delete_cookie('nexo_google_flow',path='/api/auth/google',httponly=True,samesite='lax',secure=os.getenv('NEXO_HTTPS')=='1')
        return response
