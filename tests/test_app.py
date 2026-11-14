import os, sys, tempfile
from pathlib import Path
from datetime import date, timedelta

os.environ['NEXO_ALLOWED_HOSTS']='testserver,localhost,127.0.0.1'
os.environ['NEXO_DATA_DIR']=tempfile.mkdtemp(prefix='nexo-test-')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from server import app

def test_workflow(monkeypatch):
    codes=[]
    monkeypatch.setenv("SMTP_HOST","smtp.example.com")
    monkeypatch.setenv("SMTP_FROM","nexo@example.com")
    monkeypatch.setattr("server.send_reset_email",lambda email,code: codes.append(code))
    a,b=TestClient(app),TestClient(app)
    assert a.get('/api/me').status_code==401
    x=a.post('/api/signup',json={'name':'Alice','email':'alice@example.com','password':'good-password-123'})
    assert x.status_code==200,x.text
    assert 'recovery_code' not in x.json()
    y=b.post('/api/signup',json={'name':'Bob','email':'bob@example.com','password':'good-password-456'})
    assert y.status_code==200
    ah=a.get('/api/habits').json();bh=b.get('/api/habits').json()
    assert len(ah)==len(bh)==10
    assert a.put(f"/api/habits/{bh[0]['id']}/check",json={'log_date':date.today().isoformat(),'completed':True}).status_code==404
    tid=a.get('/api/overview').json()['today']
    hid=ah[0]['id']
    assert a.put(f'/api/habits/{hid}/check',json={'log_date':tid,'completed':True}).status_code==200
    d=a.get('/api/overview').json();assert d['today_stats']['done']==1
    assert b.get('/api/overview').json()['today_stats']['done']==0
    assert a.put(f'/api/habits/{hid}/check',json={'log_date':(date.fromisoformat(tid)+timedelta(days=1)).isoformat(),'completed':True}).status_code==400
    assert a.get('/api/insights').status_code==200
    assert len(a.get('/api/insights').json()['monthly'])==6
    new=a.post('/api/habits',json={'name':'Morning sunlight','frequency':'weekly','target_count':4,'goal_value':15,'goal_unit':'min'});assert new.status_code==200
    newid=new.json()['id']
    assert a.put(f'/api/habits/{newid}',json={'name':'Sunlight','category':'Health','frequency':'monthly','target_count':15}).status_code==200
    for fmt in ('pdf','xlsx','backup'):
        r=a.get('/api/export/'+fmt);assert r.status_code==200 and len(r.content)>50
    backup=a.get('/api/export/backup').content
    assert a.post(f'/api/habits/{newid}/archive').status_code==200
    assert a.get('/api/habits?archive=true').json()[0]['id']==newid
    assert a.post('/api/restore',content=backup,headers={'Content-Type':'application/json'}).status_code==200
    assert len(a.get('/api/habits').json())==11
    assert a.post('/api/reset/request',json={'email':'alice@example.com'}).status_code==200
    code=codes[-1]
    assert a.post('/api/recover',json={'email':'alice@example.com','recovery_code':code,'new_password':'another-password-345'}).status_code==200
    assert a.get('/api/me').status_code==401
    assert a.post('/api/login',json={'email':'alice@example.com','password':'another-password-345'}).status_code==200
    assert a.post('/api/logout').status_code==200
    assert a.get('/api/me').status_code==401
