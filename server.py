"""NEXO - local-first multi-user habit tracker."""
import calendar
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import logging
import smtplib
import ssl
import time
import urllib.request
from email.message import EmailMessage
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from dotenv import load_dotenv
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from database import Postgres
from psycopg import IntegrityError as PostgresIntegrityError

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')
DATABASE_URL=os.getenv('DATABASE_URL','')
if os.getenv('RENDER') and not DATABASE_URL:
    raise RuntimeError('Set DATABASE_URL to your private Neon or Supabase PostgreSQL URL before deploying on Render.')
DATA = Path(os.environ.get('NEXO_DATA_DIR', str(BASE / 'data')))
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / 'nexo.db'
SESSION_DAYS = 30
app = FastAPI(title='NEXO Smart Habit Tracker', docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv('NEXO_ALLOWED_HOSTS','localhost,127.0.0.1,[::1]').split(','))
app.mount('/static', StaticFiles(directory=BASE / 'static'), name='static')

@app.get('/manifest.webmanifest', include_in_schema=False)
def webmanifest():
    return FileResponse(BASE / 'static' / 'manifest.webmanifest', media_type='application/manifest+json')

@app.get('/service-worker.js', include_in_schema=False)
def service_worker():
    return FileResponse(BASE / 'static' / 'service-worker.js', media_type='application/javascript', headers={'Cache-Control': 'no-cache'})

DEFAULTS = [
 ('🌅','Wake up early','Wellness',1,'time','daily',1),
 ('💧','Drink 3L water','Health',3,'L','daily',1),
 ('🏃','Exercise','Fitness',30,'min','daily',1),
 ('🏋️','Gym workout','Fitness',45,'min','weekly',4),
 ('📚','Reading','Learning',10,'pages','daily',1),
 ('🧘','Meditation','Mindfulness',10,'min','daily',1),
 ('🧑‍💻','Study for 2 hours','Learning',2,'hours','daily',1),
 ('✨','Skincare routine','Wellness',2,'times','daily',1),
 ('📵','Limit social media','Lifestyle',60,'min max','daily',1),
 ('💰','Track expenses','Finance',1,'entry','daily',1),
]

@contextmanager
def connection():
    if DATABASE_URL:
        db=Postgres(DATABASE_URL)
    else:
        db=sqlite3.connect(DB, timeout=15)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=5000')
    try:
        yield db
        db.commit()
    except:
        db.rollback()
        raise
    finally:
        db.close()

def init():
    with connection() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, salt TEXT NOT NULL, recovery_hash TEXT NOT NULL, recovery_salt TEXT NOT NULL,
          timezone TEXT NOT NULL DEFAULT 'Asia/Kolkata', theme TEXT NOT NULL DEFAULT 'light', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS habits(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL, emoji TEXT NOT NULL DEFAULT '✨', category TEXT NOT NULL DEFAULT 'Personal',
          goal_value REAL NOT NULL DEFAULT 1, goal_unit TEXT NOT NULL DEFAULT 'times',
          frequency TEXT NOT NULL DEFAULT 'daily', target_count INTEGER NOT NULL DEFAULT 1,
          goal_label TEXT NOT NULL DEFAULT '', reminder_time TEXT NOT NULL DEFAULT '', reminder_enabled INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL, archived_at TEXT DEFAULT NULL);
        CREATE TABLE IF NOT EXISTS logs(habit_id INTEGER NOT NULL REFERENCES habits(id) ON DELETE CASCADE,
          log_date TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(habit_id,log_date));
        CREATE INDEX IF NOT EXISTS idx_habits_user ON habits(user_id);
        CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(log_date);
        CREATE TABLE IF NOT EXISTS password_resets(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          code_hash TEXT NOT NULL, salt TEXT NOT NULL, expires_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY, started REAL NOT NULL, count INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS oauth_flows(state_hash TEXT PRIMARY KEY,browser_hash TEXT NOT NULL,
          verifier TEXT NOT NULL,nonce TEXT NOT NULL,expires_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS google_identities(subject TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE);
        ''')
init()

def hash_secret(value, salt):
    modern=salt.startswith('v2:')
    return hashlib.pbkdf2_hmac('sha256', value.encode(), bytes.fromhex(salt[3:] if modern else salt), 600_000 if modern else 300_000).hex()

def make_hash(value):
    salt='v2:'+secrets.token_hex(16)
    return hash_secret(value,salt),salt

def check_hash(value,digest,salt):
    return hmac.compare_digest(hash_secret(value,salt),digest)

def rate_limit(key, limit, seconds):
    """SQLite-backed counters shared across restarts and workers."""
    now=time.time()
    key=hashlib.sha256(key.encode()).hexdigest()
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM rate_limits WHERE started<?',(now-86400,))
        row=db.execute('SELECT * FROM rate_limits WHERE key=?',(key,)).fetchone()
        if row and row['started']>now-seconds:
            if row['count']>=limit: raise HTTPException(429,'Too many attempts. Please try again later.')
            db.execute('UPDATE rate_limits SET count=count+1 WHERE key=?',(key,))
        else:
            db.execute('INSERT OR REPLACE INTO rate_limits VALUES(?,?,1)',(key,now))

@app.middleware('http')
async def security_headers(request, call_next):
    if request.method not in ('GET','HEAD','OPTIONS'):
        origin=request.headers.get('origin')
        allowed=os.getenv('NEXO_PUBLIC_ORIGIN',str(request.base_url).rstrip('/'))
        if request.headers.get('sec-fetch-site')=='cross-site' or (origin and origin!=allowed):
            return JSONResponse({'detail':'Cross-site request blocked'},status_code=403)
        if request.url.path.startswith('/api/'):
            try:
                size=int(request.headers.get('content-length','0'))
            except ValueError:
                return JSONResponse({'detail':'Invalid content length'},status_code=400)
            if size>2_000_000:
                return JSONResponse({'detail':'Request too large'},status_code=413)
    if request.url.path in ('/api/login','/api/signup','/api/reset/request','/api/recover'):
        try: rate_limit('ip:'+request.client.host,60,900)
        except HTTPException as e: return JSONResponse({'detail':e.detail},status_code=e.status_code)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    if request.url.path.startswith('/api/') or request.url.path=='/':
        response.headers['Cache-Control']='no-store'
    if os.getenv('NEXO_HTTPS')=='1': response.headers['Strict-Transport-Security']='max-age=31536000'
    return response

def smtp_ready():
    return bool((os.getenv('BREVO_API_KEY') and os.getenv('EMAIL_FROM')) or (os.getenv('SMTP_HOST') and os.getenv('SMTP_FROM')))

def send_reset_email(email, code):
    content=f'Your NEXO password reset code is: {code}\n\nIt expires in 10 minutes and can be used once. If you did not request it, ignore this email. Never share this code.'
    if os.getenv('BREVO_API_KEY'):
        payload={'sender':{'name':'NEXO','email':os.environ['EMAIL_FROM']},'to':[{'email':email}],
                 'subject':'Your NEXO password reset code','textContent':content}
        req=urllib.request.Request('https://api.brevo.com/v3/smtp/email',data=json.dumps(payload).encode(),
            headers={'api-key':os.environ['BREVO_API_KEY'],'Content-Type':'application/json','Accept':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=20) as response:
            if response.status not in (200,201,202): raise RuntimeError('Email provider rejected request')
        return
    msg=EmailMessage()
    msg['Subject']='Your NEXO password reset code'
    msg['From']=os.environ['SMTP_FROM']
    msg['To']=email
    msg.set_content(content)
    context=ssl.create_default_context()
    mode=os.getenv('SMTP_SECURITY','starttls')
    if mode not in ('starttls','ssl'): raise ValueError('SMTP_SECURITY must be starttls or ssl')
    cls=smtplib.SMTP_SSL if mode=='ssl' else smtplib.SMTP
    kwargs={'context':context} if mode=='ssl' else {}
    with cls(os.environ['SMTP_HOST'],int(os.getenv('SMTP_PORT','465' if mode=='ssl' else '587')),timeout=20,**kwargs) as smtp:
        if mode=='starttls': smtp.starttls(context=context)
        if os.getenv('SMTP_USERNAME'): smtp.login(os.environ['SMTP_USERNAME'],os.environ.get('SMTP_PASSWORD',''))
        smtp.send_message(msg)

def prepare_reset(email):
    # Always scheduled, including unknown accounts, so response timing does not reveal registration.
    code=f'{secrets.randbelow(100_000_000):08d}'
    digest,salt=make_hash(code)
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        user=db.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
        if not user: return
        uid=user['id']
        db.execute('INSERT OR REPLACE INTO password_resets VALUES(?,?,?,?,0)',(uid,digest,salt,time.time()+600))
    try:
        send_reset_email(email,code)
    except Exception:
        with connection() as db:
            db.execute('DELETE FROM password_resets WHERE user_id=? AND code_hash=?',(uid,digest))
        logging.getLogger('nexo').error('Password reset email delivery failed; check SMTP configuration.')

def issue_session(response,user_id,verified_hash=None):
    token=secrets.token_urlsafe(32)
    expires=datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        if verified_hash is not None:
            current=db.execute('SELECT password_hash FROM users WHERE id=?',(user_id,)).fetchone()
            if not current or current['password_hash']!=verified_hash:
                raise HTTPException(401,'Password changed. Please log in again.')
        db.execute('DELETE FROM sessions WHERE user_id=? OR expires_at<?',(user_id,datetime.now(timezone.utc).isoformat()))
        db.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user_id,expires.isoformat()))
    response.set_cookie('nexo_session', token, max_age=SESSION_DAYS*86400, httponly=True,
                        secure=os.environ.get('NEXO_HTTPS','0')=='1', samesite='strict', path='/')

def user_from(req):
    token=req.cookies.get('nexo_session','')
    if not token: raise HTTPException(401,'Please log in')
    digest=hashlib.sha256(token.encode()).hexdigest()
    with connection() as db:
        row=db.execute('''SELECT u.id,u.name,u.email,u.timezone,u.theme FROM users u JOIN sessions s ON s.user_id=u.id
          WHERE s.token_hash=? AND s.expires_at>?''',(digest,datetime.now(timezone.utc).isoformat())).fetchone()
    if not row: raise HTTPException(401,'Session expired. Please log in again')
    return dict(row)

def valid_day(s):
    try:
        d=date.fromisoformat(s)
        if d.isoformat()!=s: raise ValueError()
        return d
    except (ValueError,TypeError): raise HTTPException(400,'Invalid date')

def today(user):
    try: return datetime.now(ZoneInfo(user['timezone'])).date()
    except Exception: return date.today()

def owned_habit(db,user_id,habit_id):
    h=db.execute('SELECT * FROM habits WHERE user_id=? AND id=?',(user_id,habit_id)).fetchone()
    if not h: raise HTTPException(404,'Habit not found')
    return h

class Signup(BaseModel):
    name:str=Field(min_length=1,max_length=80)
    email:str=Field(min_length=5,max_length=254)
    password:str=Field(min_length=10,max_length=256)
    timezone:str='Asia/Kolkata'
class Login(BaseModel):
    email:str=Field(max_length=254)
    password:str=Field(max_length=256)
class ResetRequest(BaseModel):
    email:str=Field(min_length=5,max_length=254)
class Recover(BaseModel):
    email:str=Field(max_length=254)
    recovery_code:str=Field(min_length=8,max_length=8,pattern=r'^\d{8}$')
    new_password:str=Field(min_length=10,max_length=256)
class HabitIn(BaseModel):
    name:str=Field(min_length=1,max_length=90)
    emoji:str=Field(default='✨',max_length=16)
    category:str=Field(default='Personal',min_length=1,max_length=50)
    goal_value:float=Field(default=1,gt=0,le=100000)
    goal_unit:str=Field(default='times',max_length=30)
    frequency:str='daily'
    target_count:int=Field(default=1,ge=1,le=31)
    goal_label:str=Field(default='',max_length=100)
    reminder_time:str=Field(default='',max_length=5)
    reminder_enabled:bool=False
class CheckIn(BaseModel):
    log_date:str
    completed:bool
class Profile(BaseModel):
    name:str=Field(min_length=1,max_length=80)
    timezone:str='Asia/Kolkata'
    theme:str='light'

@app.get('/')
def index(): return FileResponse(BASE/'static'/'index.html')

@app.get('/healthz')
def health():
    with connection() as db: db.execute('SELECT 1')
    return {'ok':True}

@app.post('/api/signup')
def signup(data:Signup,response:Response):
    email=data.email.strip().lower()
    if '@' not in email or '.' not in email.split('@')[-1]: raise HTTPException(400,'Enter a valid email')
    try: ZoneInfo(data.timezone)
    except Exception: raise HTTPException(400,'Unsupported timezone')
    ph,ps=make_hash(data.password)
    # Keep legacy columns for database compatibility, but disable permanent recovery codes.
    rh,rs=make_hash(secrets.token_urlsafe(32))
    if not data.name.strip(): raise HTTPException(400,'Name cannot be empty')
    with connection() as db:
        try:
            cur=db.execute('INSERT INTO users(name,email,password_hash,salt,recovery_hash,recovery_salt,timezone,created_at) VALUES(?,?,?,?,?,?,?,?)',
                           (data.name.strip(),email,ph,ps,rh,rs,data.timezone,datetime.now(timezone.utc).isoformat()))
        except (sqlite3.IntegrityError,PostgresIntegrityError): raise HTTPException(409,'An account with this email already exists')
        uid=cur.lastrowid
        for emoji,name,category,value,unit,frequency,target in DEFAULTS:
            db.execute('''INSERT INTO habits(user_id,name,emoji,category,goal_value,goal_unit,frequency,target_count,goal_label,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?)''',(uid,name,emoji,category,value,unit,frequency,target,str(value)+' '+unit, datetime.now(ZoneInfo(data.timezone)).date().isoformat()))
    issue_session(response,uid)
    return {'user':{'id':uid,'name':data.name.strip(),'email':email,'timezone':data.timezone,'theme':'light'}}

@app.post('/api/login')
def login(data:Login,response:Response):
    rate_limit('login:'+data.email.strip().lower(),10,900)
    with connection() as db:
        row=db.execute('SELECT * FROM users WHERE email=?',(data.email.strip().lower(),)).fetchone()
    valid=check_hash(data.password,row['password_hash'] if row else '0'*64,row['salt'] if row else 'v2:'+'0'*32)
    if not row or not valid:
        raise HTTPException(401,'Invalid email or password')
    verified_hash=row['password_hash']
    if not row['salt'].startswith('v2:'):
        ph,ps=make_hash(data.password)
        with connection() as db:
            db.execute('UPDATE users SET password_hash=?,salt=? WHERE id=? AND password_hash=?',(ph,ps,row['id'],row['password_hash']))
        verified_hash=ph
    issue_session(response,row['id'],verified_hash)
    return {'user':{k:row[k] for k in ['id','name','email','timezone','theme']}}

@app.post('/api/reset/request')
def request_reset(data:ResetRequest,tasks:BackgroundTasks):
    rate_limit('reset:'+data.email.strip().lower(),3,900)
    if not smtp_ready(): raise HTTPException(503,'Email reset is not configured. Ask the app administrator to configure SMTP.')
    tasks.add_task(prepare_reset,data.email.strip().lower())
    return {'message':'If an account exists for that email, a reset code will be sent. Check your inbox and spam folder.'}

@app.post('/api/recover')
def recover(data:Recover):
    error=False
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT r.* FROM password_resets r JOIN users u ON u.id=r.user_id WHERE u.email=?',(data.email.strip().lower(),)).fetchone()
        if not row or row['expires_at']<=time.time() or row['attempts']>=5:
            error=True
        elif not check_hash(data.recovery_code,row['code_hash'],row['salt']):
            db.execute('UPDATE password_resets SET attempts=attempts+1 WHERE user_id=?',(row['user_id'],))
            error=True
        else:
            ph,ps=make_hash(data.new_password)
            db.execute('UPDATE users SET password_hash=?,salt=? WHERE id=?',(ph,ps,row['user_id']))
            db.execute('DELETE FROM sessions WHERE user_id=?',(row['user_id'],))
            db.execute('DELETE FROM password_resets WHERE user_id=?',(row['user_id'],))
    if error: raise HTTPException(400,'Invalid or expired code. Request a new code.')
    return {'ok':True}

@app.post('/api/logout')
def logout(request:Request,response:Response):
    token=request.cookies.get('nexo_session','')
    with connection() as db:
        db.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie('nexo_session',path='/')
    return {'ok':True}

@app.get('/api/me')
def me(request:Request): return user_from(request)

@app.put('/api/me')
def update_profile(request:Request,data:Profile):
    u=user_from(request)
    if not data.name.strip(): raise HTTPException(400,'Name cannot be empty')
    try: ZoneInfo(data.timezone)
    except Exception: raise HTTPException(400,'Invalid timezone')
    if data.theme not in ('light','dark'): raise HTTPException(400,'Invalid theme')
    with connection() as db:
        db.execute('UPDATE users SET name=?,timezone=?,theme=? WHERE id=?',
                   (data.name.strip(),data.timezone,data.theme,u['id']))
    return {'ok':True}

@app.get('/api/habits')
def habits(request:Request,archive:bool=False):
    u=user_from(request)
    with connection() as db:
        rows=db.execute('SELECT * FROM habits WHERE user_id=? AND archived_at IS '+('NOT NULL' if archive else 'NULL')+' ORDER BY id', (u['id'],)).fetchall()
    return [dict(x) for x in rows]

@app.post('/api/habits')
def add_habit(request:Request,data:HabitIn):
    u=user_from(request)
    validate_habit(data)
    with connection() as db:
        cur=db.execute('''INSERT INTO habits(user_id,name,emoji,category,goal_value,goal_unit,frequency,target_count,
           goal_label,reminder_time,reminder_enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
           (u['id'],data.name.strip(),data.emoji,data.category.strip(),data.goal_value,data.goal_unit,
           data.frequency,data.target_count,data.goal_label,data.reminder_time,int(data.reminder_enabled),today(u).isoformat()))
    return {'id':cur.lastrowid}

def validate_habit(data):
    if data.frequency not in ('daily','weekly','monthly'): raise HTTPException(400,'Choose a valid goal frequency')
    if data.reminder_time:
        try: datetime.strptime(data.reminder_time,'%H:%M')
        except Exception: raise HTTPException(400,'Reminder must be HH:MM')
    if not data.name.strip() or not data.category.strip(): raise HTTPException(400,'Name and category cannot be empty')

@app.put('/api/habits/{habit_id}')
def edit_habit(habit_id:int,request:Request,data:HabitIn):
    u=user_from(request)
    validate_habit(data)
    with connection() as db:
        owned_habit(db,u['id'],habit_id)
        db.execute('''UPDATE habits SET name=?,emoji=?,category=?,goal_value=?,goal_unit=?,frequency=?,target_count=?,
          goal_label=?,reminder_time=?,reminder_enabled=? WHERE id=?''',
          (data.name.strip(),data.emoji,data.category.strip(),data.goal_value,data.goal_unit,
           data.frequency,data.target_count,data.goal_label,data.reminder_time,int(data.reminder_enabled),habit_id))
    return {'ok':True}

@app.post('/api/habits/{habit_id}/archive')
def archive_habit(habit_id:int,request:Request):
    u=user_from(request)
    with connection() as db:
        h=owned_habit(db,u['id'],habit_id)
        db.execute('UPDATE habits SET archived_at=? WHERE id=?',
                   (None if h['archived_at'] else today(u).isoformat(),habit_id))
    return {'ok':True}

@app.post('/api/habits/{habit_id}/reset')
def reset_habit(habit_id:int,request:Request):
    u=user_from(request)
    with connection() as db:
        owned_habit(db,u['id'],habit_id)
        db.execute('DELETE FROM logs WHERE habit_id=?',(habit_id,))
    return {'ok':True}

@app.delete('/api/habits/{habit_id}')
def delete_habit(habit_id:int,request:Request):
    u=user_from(request)
    with connection() as db:
        owned_habit(db,u['id'],habit_id)
        db.execute('DELETE FROM habits WHERE id=?',(habit_id,))
    return {'ok':True}

@app.put('/api/habits/{habit_id}/check')
def checkin(habit_id:int,request:Request,data:CheckIn):
    u=user_from(request)
    d=valid_day(data.log_date)
    if d > today(u): raise HTTPException(400,'Future days cannot be marked completed')
    with connection() as db:
        h=owned_habit(db,u['id'],habit_id)
        if d < date.fromisoformat(h['created_at']): raise HTTPException(400,'Habit did not exist on this date')
        if h['archived_at'] and d > date.fromisoformat(h['archived_at']): raise HTTPException(400,'Habit was archived')
        db.execute('''INSERT INTO logs(habit_id,log_date,completed) VALUES(?,?,?)
          ON CONFLICT(habit_id,log_date) DO UPDATE SET completed=excluded.completed''',(habit_id,d.isoformat(),int(data.completed)))
    return {'ok':True}

def read_snapshot(uid, user_today, start, end):
    with connection() as db:
        hs=[dict(r) for r in db.execute('SELECT * FROM habits WHERE user_id=? ORDER BY id',(uid,)).fetchall()]
        logs=[dict(r) for r in db.execute('''SELECT l.habit_id,l.log_date,l.completed FROM logs l
          JOIN habits h ON h.id=l.habit_id WHERE h.user_id=? AND l.log_date BETWEEN ? AND ?''',
          (uid,start.isoformat(),end.isoformat())).fetchall()]
    by_log={(r['habit_id'],r['log_date']):bool(r['completed']) for r in logs}
    days=[]
    d=start
    while d<=end:
        active=[h for h in hs if date.fromisoformat(h['created_at'])<=d and
                (h['archived_at'] is None or d<=date.fromisoformat(h['archived_at']))]
        completed=sum(bool(by_log.get((h['id'],d.isoformat()),False)) for h in active)
        days.append({'date':d.isoformat(),'total':len(active),'done':completed,
                     'percentage':round(100*completed/len(active)) if active else 0})
        d+=timedelta(days=1)
    return hs,by_log,days

def streaks(days,t):
    eligible=[x for x in days if x['date']<=t.isoformat() and x['total']>0]
    current=best=run=0
    for x in eligible:
        if x['percentage']==100: run+=1
        else: run=0
        best=max(best,run)
    # A streak remains active until the end of the current day; don't penalize a day in progress.
    current=run
    if eligible and eligible[-1]['date']==t.isoformat() and eligible[-1]['percentage']<100:
        current=0
        for x in reversed(eligible[:-1]):
            if x['percentage']==100: current+=1
            else: break
    return current,best

@app.get('/api/overview')
def overview(request:Request,month:Optional[str]=None):
    u=user_from(request)
    t=today(u)
    if month:
        try:
            y,m=map(int,month.split('-'))
            start=date(y,m,1)
        except Exception: raise HTTPException(400,'Invalid month')
    else: start=t.replace(day=1)
    end=date(start.year,start.month,calendar.monthrange(start.year,start.month)[1])
    history_start=min(date(2020,1,1),t-timedelta(days=400))
    # Avoid huge historical data scans but retain accurate streaks for all user days.
    with connection() as db:
        first=db.execute('SELECT MIN(created_at) AS first FROM habits WHERE user_id=?',(u['id'],)).fetchone()['first']
    history_start=min(date.fromisoformat(first),start) if first else start
    hist_hs,_,hist=read_snapshot(u['id'],t,history_start,max(t,end))
    current,best=streaks(hist,t)
    first_week=t-timedelta(days=t.weekday())
    days=[r for r in hist if start<=date.fromisoformat(r['date'])<=end]
    week=[r for r in hist if first_week<=date.fromisoformat(r['date'])<=t]
    month_past=[r for r in days if r['date']<=t.isoformat() and r['total']>0]
    td=next((r for r in hist if r['date']==t.isoformat()),{'total':0,'done':0,'percentage':0})
    with connection() as db:
        logs=db.execute('''SELECT l.habit_id,l.log_date,l.completed FROM logs l JOIN habits h ON l.habit_id=h.id
          WHERE h.user_id=? AND l.log_date BETWEEN ? AND ?''',(u['id'],start.isoformat(),end.isoformat())).fetchall()
    log_map={f"{x['habit_id']}:{x['log_date']}":bool(x['completed']) for x in logs}
    per_habit=[]
    for h in hist_hs:
        eligible=[x for x in hist if start<=date.fromisoformat(x['date'])<=min(end,t) and
                  date.fromisoformat(h['created_at'])<=date.fromisoformat(x['date']) and
                  (not h['archived_at'] or x['date']<=h['archived_at'])]
        count=sum(bool(log_map.get(f"{h['id']}:{x['date']}")) for x in eligible)
        per_habit.append({'id':h['id'],'name':h['name'],'emoji':h['emoji'],'count':count,'possible':len(eligible),
                         'percentage':round(100*count/len(eligible)) if eligible else 0,'archived':bool(h['archived_at'])})
    return {'user':u,'today':t.isoformat(),'selected_month':start.strftime('%Y-%m'),
            'today_stats':{**td,'pending':td['total']-td['done']},
            'current_streak':current,'best_streak':best,
            'week_score':round(sum(x['percentage'] for x in week if x['total'])/max(1,sum(x['total']>0 for x in week))),
            'month_score':round(sum(x['percentage'] for x in month_past)/len(month_past)) if month_past else 0,
            'all_completed':sum(x['done'] for x in hist if x['date']<=t.isoformat()),
            'days':days,'recent_days':[x for x in hist if t-timedelta(days=29)<=date.fromisoformat(x['date'])<=t],
            'habits':hist_hs,'log_map':log_map,'per_habit':per_habit}

@app.get('/api/tracking')
def tracking(request:Request,start:str,archive:bool=False):
    u=user_from(request)
    s=valid_day(start)
    if (s.weekday()!=0): raise HTTPException(400,'Week must start on Monday')
    with connection() as db:
        hs=[dict(r) for r in db.execute('SELECT * FROM habits WHERE user_id=? AND archived_at IS '+('NOT NULL' if archive else 'NULL')+' ORDER BY id',(u['id'],))]
        logs=[dict(r) for r in db.execute('''SELECT l.habit_id,l.log_date,l.completed FROM logs l JOIN habits h ON h.id=l.habit_id
          WHERE h.user_id=? AND l.log_date BETWEEN ? AND ?''',(u['id'],s.isoformat(),(s+timedelta(days=6)).isoformat())).fetchall()]
    return {'habits':hs,'logs':{f"{x['habit_id']}:{x['log_date']}":bool(x['completed']) for x in logs},'today':today(u).isoformat()}

@app.get('/api/export/{fmt}')
def export(request:Request,fmt:str,month:Optional[str]=None):
    u=user_from(request)
    if fmt not in ('xlsx','pdf','backup'): raise HTTPException(404,'Unknown format')
    if month:
        try: yr,mo=map(int,month.split('-')); start=date(yr,mo,1)
        except Exception: raise HTTPException(400,'Invalid month')
    else: start=today(u).replace(day=1)
    end=date(start.year,start.month,calendar.monthrange(start.year,start.month)[1])
    with connection() as db:
        hs=[dict(r) for r in db.execute('SELECT * FROM habits WHERE user_id=?',(u['id'],))]
        logs=[dict(r) for r in db.execute('SELECT l.* FROM logs l JOIN habits h ON h.id=l.habit_id WHERE h.user_id=?',(u['id'],))]
    if fmt=='backup':
        content=json.dumps({'version':1,'habits':hs,'logs':logs},ensure_ascii=False,indent=2).encode()
        return StreamingResponse(io.BytesIO(content),media_type='application/json',headers={
            'Content-Disposition':'attachment; filename="nexo-backup.json"'})
    relevant=[r for r in logs if start.isoformat()<=r['log_date']<=end.isoformat() and r['completed']]
    lookup={(r['habit_id'],r['log_date']) for r in relevant}
    records=[]
    for h in hs:
        if h['created_at']>end.isoformat() or (h['archived_at'] and h['archived_at']<start.isoformat()): continue
        for day in range(1,end.day+1):
            dt=start.replace(day=day)
            if dt.isoformat()<h['created_at'] or (h['archived_at'] and dt.isoformat()>h['archived_at']): continue
            records.append((h['name'],h['category'],dt.isoformat(),'Yes' if (h['id'],dt.isoformat()) in lookup else 'No',
                            f"{h['goal_value']:g} {h['goal_unit']}",h['frequency'],h['target_count']))
    out=io.BytesIO()
    if fmt=='xlsx':
        from openpyxl import Workbook
        from openpyxl.styles import Font,PatternFill,Alignment
        wb=Workbook(); ws=wb.active; ws.title='Monthly Progress'
        ws.append(['Habit','Category','Date','Completed','Goal','Frequency','Target count'])
        for r in records: ws.append(r)
        for cell in ws[1]: cell.fill=PatternFill('solid',fgColor='DDE7FF');cell.font=Font(bold=True,color='19294C')
        ws.freeze_panes='A2';ws.auto_filter.ref=ws.dimensions
        for letter,width in {'A':28,'B':19,'C':16,'D':16,'E':18,'F':14,'G':15}.items():ws.column_dimensions[letter].width=width
        wb.save(out)
        media='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    else:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
        doc=SimpleDocTemplate(out,pagesize=A4)
        styles=getSampleStyleSheet()
        summary=[Paragraph('NEXO | Monthly Habit Report',styles['Title']),
                 Paragraph(f"{start.strftime('%B %Y')}  |  {u['name']}",styles['Heading2']),Spacer(1,16)]
        active=[r for r in records if r[2]<=today(u).isoformat()]
        done=sum(r[3]=='Yes' for r in active)
        summary.append(Paragraph(f'Completed check-ins: {done} / {len(active)}  |  Consistency: {round(done/len(active)*100) if active else 0}%',styles['Normal']))
        summary.append(Spacer(1,16))
        rows=[['Habit','Done','Eligible','Rate']]
        for h in hs:
            rr=[r for r in active if r[0]==h['name']]
            if not rr: continue
            count=sum(r[3]=='Yes' for r in rr)
            rows.append([h['name'][:30],str(count),str(len(rr)),str(round(count/len(rr)*100))+'%'])
        table=Table(rows,colWidths=[255,65,65,65],repeatRows=1)
        table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e7edff')),
           ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f7f9ff')]),
           ('BOTTOMPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),9)]))
        summary.append(table);doc.build(summary)
        media='application/pdf'
    out.seek(0)
    return StreamingResponse(out,media_type=media,headers={'Content-Disposition':f'attachment; filename="nexo-{start.strftime("%Y-%m")}.{fmt}"'})

@app.post('/api/restore')
async def restore(request:Request):
    u=user_from(request)
    raw=await request.body()
    if len(raw)>2_000_000: raise HTTPException(413,'Backup is too large')
    try:
        payload=json.loads(raw)
        hs=payload['habits']; logs=payload['logs']
        if payload.get('version')!=1 or not isinstance(hs,list) or not isinstance(logs,list): raise ValueError()
        if len(hs)>300 or len(logs)>100000: raise ValueError()
        validated=[]; old_ids=set()
        for h in hs:
            old_id=int(h['id'])
            if old_id in old_ids: raise ValueError()
            old_ids.add(old_id)
            data=HabitIn(**{k:h[k] for k in HabitIn.model_fields if k in h})
            validate_habit(data)
            created=valid_day(h['created_at']).isoformat()
            archived=valid_day(h['archived_at']).isoformat() if h.get('archived_at') else None
            validated.append((old_id,data,created,archived))
        validated_logs=[]
        for l in logs:
            hid=int(l['habit_id']);dt=valid_day(l['log_date']).isoformat()
            if hid not in old_ids: raise ValueError()
            validated_logs.append((hid,dt,int(bool(l['completed']))))
    except Exception: raise HTTPException(400,'Invalid or unsupported NEXO backup')
    with connection() as db:
        db.execute('DELETE FROM habits WHERE user_id=?',(u['id'],))
        id_map={}
        for old_id,h,created,archived in validated:
            cur=db.execute('''INSERT INTO habits(user_id,name,emoji,category,goal_value,goal_unit,frequency,target_count,
              goal_label,reminder_time,reminder_enabled,created_at,archived_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
              (u['id'],h.name,h.emoji,h.category,h.goal_value,h.goal_unit,h.frequency,h.target_count,
               h.goal_label,h.reminder_time,int(h.reminder_enabled),created,archived))
            id_map[old_id]=cur.lastrowid
        for hid,dt,done in validated_logs:
            db.execute('INSERT OR REPLACE INTO logs VALUES(?,?,?)',(id_map[hid],dt,done))
    return {'ok':True,'habits':len(validated),'logs':len(validated_logs)}

@app.get('/api/insights')
def insights(request:Request):
    """Rolling six-month completion trend and per-habit period target progress."""
    u=user_from(request)
    t=today(u)
    first=t.replace(day=1)
    for _ in range(5): first=(first-timedelta(days=1)).replace(day=1)
    habits,log_map,days=read_snapshot(u['id'],t,first,t)
    monthly=[]
    for i in range(6):
        d=first
        for _ in range(i):
            d=(d.replace(day=28)+timedelta(days=4)).replace(day=1)
        selected=[x for x in days if x['date'].startswith(d.strftime('%Y-%m')) and x['total']>0]
        den=sum(x['total'] for x in selected)
        monthly.append({'month':d.strftime('%Y-%m'),'percentage':round(100*sum(x['done'] for x in selected)/den) if den else 0,
                        'done':sum(x['done'] for x in selected),'possible':den})
    goals=[]
    for h in habits:
        if h['archived_at']: continue
        if h['frequency']=='daily': start=t;period='today'
        elif h['frequency']=='weekly': start=t-timedelta(days=t.weekday());period='this week'
        else: start=t.replace(day=1);period='this month'
        completed=0
        for i in range((t-start).days+1):
            d=start+timedelta(days=i)
            if d>=date.fromisoformat(h['created_at']) and log_map.get((h['id'],d.isoformat()),False): completed+=1
        target=h['target_count']
        goals.append({'id':h['id'],'name':h['name'],'emoji':h['emoji'],'frequency':h['frequency'],
                      'goal_value':h['goal_value'],'goal_unit':h['goal_unit'],'target':target,
                      'completed':completed,'period':period,'percentage':min(100,round(completed/target*100))})
    return {'monthly':monthly,'goals':goals}

from google_login import register as register_google_login
register_google_login(app,connection,make_hash,issue_session,DEFAULTS,rate_limit)
