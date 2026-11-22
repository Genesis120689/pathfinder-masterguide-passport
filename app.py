import os, json, hashlib, hmac, secrets, datetime, io, pathlib, base64, binascii
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeSerializer, BadSignature
import qrcode
BASE=pathlib.Path(__file__).parent
DATA_DIR=pathlib.Path(os.getenv('PASSPORT_DATA_DIR', str(BASE))).expanduser().resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB=None  # Supabase PostgreSQL
CAT=json.loads((BASE/'requirements.json').read_text(encoding='utf8'))
SOURCES=json.loads((BASE/'requirements_sources.json').read_text())
LEVELS=['Friend','Companion','Explorer','Ranger','Voyager','Guide','Master Guide']
ROLES=['admin','ssd','ssd_youth_director','ssd_pathfinder_director','mission','mission_youth_director','pastor','director','masterguide','trainee','pathfinder']
# Stable unique instance secret; generated outside the distributed archive on first launch.
secret_file=DATA_DIR/'.instance_secret'
if os.getenv('PASSPORT_SECRET'):
 SECRET=os.environ['PASSPORT_SECRET']
else:
 if not secret_file.exists():
  secret_file.write_text(secrets.token_urlsafe(48), encoding='utf8')
  try: os.chmod(secret_file,0o600)
  except OSError: pass
 SECRET=secret_file.read_text(encoding='utf8').strip()
app=FastAPI(title='Pathfinder & Master Guide Digital Passport')
app.mount(
    "/static",
    StaticFiles(directory=str(BASE)),
    name="static"
)
app.add_middleware(SessionMiddleware, secret_key=SECRET, same_site='lax', https_only=os.getenv('HTTPS_ONLY')=='1')
signer=URLSafeSerializer(SECRET,salt='passport-qr')
from postgres_db import connect as conn, IntegrityError
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def password_hash(p):
 salt=os.urandom(16);return (salt+hashlib.pbkdf2_hmac('sha256',p.encode(),salt,240000)).hex()
def password_check(p, saved):
 try:
  raw=bytes.fromhex(saved);return hmac.compare_digest(raw[16:],hashlib.pbkdf2_hmac('sha256',p.encode(),raw[:16],240000))
 except: return False
def init():
 with conn() as c:
  from postgres_db import SCHEMA
  c.executescript(SCHEMA)
  # First-run administrator is chosen by the owner via local setup with a one-time token.
  # Existing databases and administrator records remain unchanged.
  if not c.execute('SELECT 1 FROM users WHERE role="admin"').fetchone():
   token_path=DATA_DIR/'.setup_token'
   if not token_path.exists():
    token_path.write_text(secrets.token_urlsafe(24), encoding='utf8')
    try: os.chmod(token_path,0o600)
    except OSError: pass
   print('\n*** SETUP REQUIRED: open http://127.0.0.1:8765 on this computer. ***',flush=True)
   if not os.getenv('PASSPORT_SETUP_TOKEN'):
    print('*** ONE-TIME SETUP TOKEN:',token_path.read_text(encoding='utf8').strip(),'***\n',flush=True)
init()
# Existing administrator accounts from earlier versions used Master Guide as a placeholder.
# Do not alter any member's genuine records; administrative identity is not a class enrolment.
with conn() as c:
 c.execute("UPDATE users SET level='Administration' WHERE role='admin' AND level='Master Guide'")
def me(req):
 uid=req.session.get('uid')
 with conn() as c: return c.execute('SELECT id,name,username,role,club_id,level,certified FROM users WHERE id=?',(uid,)).fetchone()
def need(req,roles=None):
 u=me(req)
 if not u: raise HTTPException(401,'Please sign in')
 if roles and u['role'] not in roles: raise HTTPException(403,'Not authorized')
 return u
def audit(c,u,subject,action,detail=''):
 c.execute('INSERT INTO audits(actor,subject,action,detail,created) VALUES(?,?,?,?,?)',(u['id'],subject,action,detail,now()))
def can_manage(u,target):
 if u['role'] in ['admin','ssd','ssd_youth_director','ssd_pathfinder_director']:return True
 if u['role'] in ['director','pastor','mission','mission_youth_director','masterguide'] and u['club_id'] and u['club_id']==target['club_id']:return True
 return False
import re
class SetupAdmin(BaseModel):
 name:str
 username:str
 password:str
 token:str
@app.get('/api/setup/status')
def setup_status():
 with conn() as c: missing=not bool(c.execute('SELECT 1 FROM users WHERE role="admin"').fetchone())
 return {'setup_required':missing}
@app.post('/api/setup/admin')
def setup_admin(body:SetupAdmin,req:Request):
 # Cloud bootstrap is allowed only when the operator configured a private, long random token.
 cloud_token=os.getenv('PASSPORT_SETUP_TOKEN','').strip()
 if not cloud_token and (req.client is None or req.client.host not in ('127.0.0.1','::1','localhost')):
  raise HTTPException(403,'Initial setup requires a preconfigured cloud setup token')
 tok=DATA_DIR/'.setup_token'
 expected_token=cloud_token if cloud_token else (tok.read_text(encoding='utf8').strip() if tok.exists() else '')
 if not expected_token or not hmac.compare_digest(body.token.strip(),expected_token):
  raise HTTPException(403,'Invalid one-time setup token')
 name=body.name.strip();username=body.username.strip().lower()
 if len(name)<2 or not (3<=len(username)<=40) or not re.fullmatch(r'[a-z0-9._-]+',username):
  raise HTTPException(400,'Enter a valid name and username (3–40 letters, digits, dot, dash, underscore)')
 if len(body.password)<12:
  raise HTTPException(400,'Choose a password with at least 12 characters')
 with conn() as c:
  c.execute('BEGIN IMMEDIATE')
  if c.execute('SELECT 1 FROM users WHERE role="admin"').fetchone():
   raise HTTPException(409,'Administrator already exists. Sign in to add another administrator.')
  cur=c.execute('INSERT INTO users(name,username,password,role,level,created) VALUES(?,?,?,?,?,?)',(name,username,password_hash(body.password),'admin','Administration',now()))
  audit(c,{'id':cur.lastrowid},cur.lastrowid,'first_admin_created','local setup')
 try:tok.unlink()
 except OSError: pass
 req.session.clear();req.session['uid']=cur.lastrowid
 return {'ok':True}
class Login(BaseModel): username:str;password:str
class Club(BaseModel):name:str;church:str;mission:str
class NewUser(BaseModel):name:str;username:str;password:str;role:str='pathfinder';club_id:int|None=None;level:str='Friend'
class Status(BaseModel):user_id:int;level:str;req_key:str;status:str;notes:str=''
class Approve(BaseModel):user_id:int;stage:str
class ChangeRole(BaseModel):user_id:int;role:str
@app.get('/assets/{asset_name}')
def app_asset(asset_name:str):
 allowed={'passport_brand_banner.webp':'image/webp','passport_app_icon.png':'image/png','icon-192.png':'image/png','icon-512.png':'image/png','pathfinder_official.jpg':'image/jpeg','master_guide_official.jpg':'image/jpeg','login_portrait.jpg':'image/jpeg','login_scenery.png':'image/png','approved_login_artwork.webp':'image/webp','approved_main_logo.webp':'image/webp','approved_login_artwork.png':'image/png','approved_main_logo.png':'image/png','wife_master_guide_portrait.png':'image/png','master_guide_dashboard_portrait.webp':'image/webp'}
 if asset_name not in allowed: raise HTTPException(404,'Asset not found')
 return FileResponse(BASE/'assets'/asset_name, media_type=allowed[asset_name], headers={'Cache-Control':'no-cache'})
@app.get('/manifest.webmanifest')
def app_manifest():
 return JSONResponse({'name':'Pathfinder & Master Guide Digital Passport','short_name':'Digital Passport','start_url':'/','display':'standalone','background_color':'#09362e','theme_color':'#123d31','icons':[{'src':'/assets/icon-192.png','sizes':'192x192','type':'image/png'},{'src':'/assets/icon-512.png','sizes':'512x512','type':'image/png'}]},media_type='application/manifest+json')
@app.get('/assets/master_guide_studio.jpg')
def studio_photo(): return FileResponse(BASE/'assets'/'master_guide_studio.jpg',media_type='image/jpeg')
@app.get('/',response_class=HTMLResponse)
def home():return (BASE/'index.html').read_text(encoding='utf8')
@app.post('/api/login')
def login(body:Login,req:Request):
 with conn() as c:u=c.execute('SELECT * FROM users WHERE username=?',(body.username.strip().lower(),)).fetchone()
 if not u or not password_check(body.password,u['password']):raise HTTPException(401,'Invalid username or password')
 req.session.clear();req.session['uid']=u['id'];return {'ok':True}
@app.post('/api/logout')
def logout(req:Request):req.session.clear();return {'ok':True}
@app.get('/api/me')
def who(req:Request):
 u=need(req);return dict(u)
@app.get('/api/catalog')
def catalog(req:Request):
 need(req);return {'requirements':CAT,'sources':SOURCES,'warning':'Curriculum reference set is a condensed overview, not a complete certified transcription. Verify every class requirement against the approved General Conference and Mission manuals before certifying anyone.'}
@app.get('/api/clubs')
def clubs(req:Request):
 need(req)
 with conn() as c:return [dict(r) for r in c.execute('SELECT * FROM clubs ORDER BY name')]
@app.post('/api/clubs')
def club_create(body:Club,req:Request):
 u=need(req,['admin','ssd']);
 with conn() as c:
  cur=c.execute('INSERT INTO clubs(name,church,mission) VALUES(?,?,?)',(body.name,body.church,body.mission));audit(c,u,0,'create_club',body.name)
  return {'id':cur.lastrowid}
@app.get('/api/users')
def users(req:Request):
 u=need(req)
 with conn() as c:
  if u['role'] in ['admin','ssd','ssd_youth_director','ssd_pathfinder_director']: rows=c.execute('SELECT id,name,username,role,club_id,level,certified FROM users ORDER BY name').fetchall()
  elif u['role'] in ['director','mission','mission_youth_director','pastor','masterguide']: rows=c.execute('SELECT id,name,username,role,club_id,level,certified FROM users WHERE club_id=? ORDER BY name',(u['club_id'],)).fetchall()
  else: rows=[c.execute('SELECT id,name,username,role,club_id,level,certified FROM users WHERE id=?',(u['id'],)).fetchone()]
  return [dict(r) for r in rows if r]
@app.post('/api/users')
def create_user(body:NewUser,req:Request):
 u=need(req,['admin','ssd','director']);
 if body.role not in ROLES or (body.role!='admin' and body.level not in LEVELS):raise HTTPException(400,'Invalid role or level')
 if body.role=='admin' and u['role']!='admin':raise HTTPException(403,'Only a system administrator may create another administrator')
 if len(body.password)<10:raise HTTPException(400,'Minimum password length is 10')
 if u['role']=='director':
  if body.role not in ['pathfinder','trainee'] or body.club_id!=u['club_id']:raise HTTPException(403,'Directors create only trainees and Pathfinders in their club')
 with conn() as c:
  try:
   cur=c.execute('INSERT INTO users(name,username,password,role,club_id,level,created) VALUES(?,?,?,?,?,?,?)',(body.name,body.username.strip().lower(),password_hash(body.password),body.role,(None if body.role=='admin' else body.club_id),('Administration' if body.role=='admin' else body.level),now()));audit(c,u,cur.lastrowid,'create_user',body.role);return {'id':cur.lastrowid}
  except IntegrityError:raise HTTPException(400,'Username exists or club is invalid')
@app.get('/api/progress/{user_id}')
def progress(user_id:int,req:Request):
 u=need(req)
 with conn() as c:
  target=c.execute('SELECT id,name,club_id,level,role,certified FROM users WHERE id=?',(user_id,)).fetchone()
  if not target or (u['id']!=user_id and not can_manage(u,target)):raise HTTPException(403,'Not permitted')
  rows=c.execute('SELECT level,req_key,status,notes,approved_by,updated FROM progress WHERE user_id=?',(user_id,)).fetchall()
  aps=c.execute('SELECT kind,stage,created FROM approvals WHERE user_id=?',(user_id,)).fetchall()
  appt=c.execute('SELECT stage,created FROM appointments WHERE user_id=?',(user_id,)).fetchall()
  return {'user':dict(target),'progress':[dict(r) for r in rows],'approvals':[dict(r) for r in aps],'appointments':[dict(r) for r in appt]}
@app.post('/api/progress')
def set_status(body:Status,req:Request):
 u=need(req)
 if body.level not in LEVELS or body.req_key not in [f'{section}|{i}' for section,items in CAT[body.level].items() for i in range(len(items))]:raise HTTPException(400,'Unknown requirement')
 if body.status not in ['not_started','pending','completed']:raise HTTPException(400,'Invalid status')
 with conn() as c:
  target=c.execute('SELECT * FROM users WHERE id=?',(body.user_id,)).fetchone()
  if not target:raise HTTPException(404,'User not found')
  if body.level!=target['level']:raise HTTPException(400,'Different enrolled level')
  if body.status=='completed':
   if u['id']==target['id'] or u['role'] not in ['masterguide','director','mission','mission_youth_director','ssd_youth_director','ssd_pathfinder_director'] or not can_manage(u,target):raise HTTPException(403,'Only authorized mentor/director can approve')
  elif u['id']!=target['id'] and not can_manage(u,target):raise HTTPException(403,'Not authorized')
  c.execute('INSERT INTO progress(user_id,level,req_key,status,submitted_by,approved_by,updated,notes) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,level,req_key) DO UPDATE SET status=excluded.status,submitted_by=excluded.submitted_by,approved_by=excluded.approved_by,updated=excluded.updated,notes=excluded.notes',(body.user_id,body.level,body.req_key,body.status,u['id'],u['id'] if body.status=='completed' else None,now(),body.notes[:1000]));audit(c,u,body.user_id,'requirement_'+body.status,body.level+':'+body.req_key)
 return {'ok':True}
@app.post('/api/approval')
def approve(body:Approve,req:Request):
 u=need(req)
 stage_roles={'pastor':'pastor','director':'director','mission':'mission','investiture':'mission'}
 if body.stage not in stage_roles or (u['role']!=stage_roles[body.stage] and not (body.stage in ['mission','investiture'] and u['role']=='mission_youth_director') ):raise HTTPException(403,'Wrong approval role')
 with conn() as c:
  target=c.execute('SELECT * FROM users WHERE id=?',(body.user_id,)).fetchone()
  if not target or target['role'] not in ['trainee','masterguide']:raise HTTPException(400,'Must be an MG trainee')
  if not can_manage(u,target):raise HTTPException(403,'Different club')
  total=sum(len(x) for x in CAT['Master Guide'].values())
  done=c.execute('SELECT COUNT(*) FROM progress WHERE user_id=? AND level=? AND status="completed"',(body.user_id,'Master Guide')).fetchone()[0]
  if done<total:raise HTTPException(400,f'MG requirements not yet all approved ({done}/{total})')
  prior={r['stage'] for r in c.execute('SELECT stage FROM approvals WHERE user_id=? AND kind="mg"',(body.user_id,))}
  if body.stage=='investiture' and not {'pastor','director','mission'}.issubset(prior):raise HTTPException(400,'All three approvals required before investiture')
  if body.stage=='mission' and not {'pastor','director'}.issubset(prior):raise HTTPException(400,'Pastor and Club Director approvals required first')
  c.execute('INSERT OR IGNORE INTO approvals(user_id,kind,stage,approved_by,created) VALUES(?,?,?,?,?)',(body.user_id,'mg',body.stage,u['id'],now()))
  if body.stage=='investiture':
   if os.getenv('CERTIFICATION_ENABLED')!='1':
    raise HTTPException(409,'Investiture recording is disabled until the SSD-approved complete curriculum and certification authorization are configured')
   c.execute("UPDATE users SET certified=1,role='masterguide' WHERE id=?",(body.user_id,))
  audit(c,u,body.user_id,'mg_approval',body.stage)
 return {'ok':True}
@app.post('/api/appointment')
def appointment(body:Approve,req:Request):
 u=need(req)
 stages={'pastor':'pastor','mission':'mission','ssd':'ssd'}
 if body.stage not in stages or (u['role']!=stages[body.stage] and not (body.stage=='mission' and u['role']=='mission_youth_director') and not (body.stage=='ssd' and u['role'] in ['ssd_youth_director','ssd_pathfinder_director']) ):raise HTTPException(403,'Wrong role for appointment')
 with conn() as c:
  t=c.execute('SELECT * FROM users WHERE id=?',(body.user_id,)).fetchone()
  if not t or not t['certified']:raise HTTPException(400,'Only certified Master Guides may be appointed director')
  if not can_manage(u,t):raise HTTPException(403,'Different club')
  prior={r['stage'] for r in c.execute('SELECT stage FROM appointments WHERE user_id=?',(body.user_id,))}
  if body.stage=='mission' and 'pastor' not in prior:raise HTTPException(400,'Pastor recommendation required')
  if body.stage=='ssd' and 'mission' not in prior:raise HTTPException(400,'Mission approval required')
  c.execute('INSERT OR IGNORE INTO appointments(user_id,stage,approved_by,created) VALUES(?,?,?,?)',(body.user_id,body.stage,u['id'],now()))
  if body.stage=='mission':c.execute('UPDATE users SET role="director" WHERE id=?',(body.user_id,))
  audit(c,u,body.user_id,'appointment',body.stage)
 return {'ok':True}

@app.get('/api/admin/overview')
def admin_overview(req:Request):
 u=need(req,['admin'])
 with conn() as c:
  result={'clubs':c.execute('SELECT COUNT(*) FROM clubs').fetchone()[0],
          'members':c.execute("SELECT COUNT(*) FROM users WHERE role!='admin'").fetchone()[0],
          'missions':c.execute('SELECT COUNT(DISTINCT mission) FROM clubs').fetchone()[0],
          'pending_requirements':c.execute("SELECT COUNT(*) FROM progress WHERE status='pending'").fetchone()[0],
          'certified_master_guides':c.execute('SELECT COUNT(*) FROM users WHERE certified=1').fetchone()[0],
          'announcements':c.execute('SELECT COUNT(*) FROM announcements').fetchone()[0],
          'events':c.execute('SELECT COUNT(*) FROM events').fetchone()[0]}
  return result

@app.get('/api/qr/{user_id}')
def qr(user_id:int,req:Request):
 u=need(req)
 with conn() as c:t=c.execute('SELECT id,club_id FROM users WHERE id=?',(user_id,)).fetchone()
 if not t or (u['id']!=user_id and not can_manage(u,t)):raise HTTPException(403,'Not allowed')
 token=signer.dumps({'uid':user_id})
 url=str(req.base_url).rstrip('/')+'/verify/'+token
 img=qrcode.make(url);buf=io.BytesIO();img.save(buf,format='PNG');buf.seek(0)
 return StreamingResponse(buf,media_type='image/png')
@app.get('/verify/{token}',response_class=HTMLResponse)
def verify(token:str,req:Request):
 try: data=signer.loads(token);uid=int(data['uid'])
 except (BadSignature,KeyError,ValueError):raise HTTPException(400,'Invalid QR')
 u=need(req)
 with conn() as c:t=c.execute('SELECT id,name,club_id,level,certified FROM users WHERE id=?',(uid,)).fetchone()
 if not t or (u['id']!=uid and not can_manage(u,t)):raise HTTPException(403,'This passport is not in your club')
 return HTMLResponse(f'<meta name="viewport" content="width=device-width, initial-scale=1"><script>location.href="/?user={uid}"</script><p>Opening passport...</p>')
@app.get('/api/audit')
def audits(req:Request):
 u=need(req,['admin','ssd'])
 with conn() as c:return [dict(r) for r in c.execute('SELECT * FROM audits ORDER BY id DESC LIMIT 200')]
class Enroll(BaseModel): user_id:int
@app.post('/api/enroll-mg')
def enroll_mg(body:Enroll,req:Request):
 u=need(req,['director','admin','ssd'])
 with conn() as c:
  target=c.execute('SELECT * FROM users WHERE id=?',(body.user_id,)).fetchone()
  if not target or not can_manage(u,target):raise HTTPException(403,'Not your club')
  if target['level']!='Guide' or target['role']!='pathfinder':raise HTTPException(400,'This transition requires an enrolled Guide Pathfinder; other eligible candidates can be created as MG trainees directly')
  c.execute("UPDATE users SET level='Master Guide',role='trainee' WHERE id=?",(body.user_id,));audit(c,u,body.user_id,'enroll_master_guide');return {'ok':True}
@app.get('/manifest.webmanifest')
def manifest():return JSONResponse({'name':'Pathfinder & Master Guide Passport','short_name':'PF Passport','start_url':'/','display':'standalone','background_color':'#f3f6f2','theme_color':'#123d31'})


# Community bulletin and scoped calendar — v0.3
SSD_PUBLISHERS={'admin','ssd','ssd_youth_director','ssd_pathfinder_director'}
MISSION_PUBLISHERS={'mission','mission_youth_director'}
class AnnouncementPost(BaseModel):
 title:str
 body:str
 image_base64:str|None=None
class EventPost(BaseModel):
 title:str
 description:str=''
 starts_at:str
 ends_at:str|None=None
 location:str=''
 scope:str='club'
 club_id:int|None=None

def checked_str(x,limit,name):
 x=x.strip()
 if not x or len(x)>limit:raise HTTPException(400,f'{name} must have 1-{limit} characters')
 return x

@app.get('/api/announcements')
def get_announcements(req:Request):
 need(req)
 with conn() as c:
  return [dict(x) for x in c.execute('SELECT a.id,a.title,a.body,a.image_path,a.created,u.name AS author FROM announcements a JOIN users u ON a.created_by=u.id ORDER BY a.id DESC LIMIT 30')]

@app.post('/api/announcements')
def add_announcement(body:AnnouncementPost,req:Request):
 u=need(req)
 if u['role'] not in SSD_PUBLISHERS:raise HTTPException(403,'Only SSD Youth/Pathfinder Directors and admin may publish central announcements')
 title=checked_str(body.title,140,'Title'); content=checked_str(body.body,3000,'Message')
 image_url=None
 if body.image_base64:
  try:
   payload=body.image_base64.split(',',1)[-1]
   raw=base64.b64decode(payload,validate=True)
  except (ValueError,binascii.Error):raise HTTPException(400,'Invalid picture')
  if len(raw)>3_000_000:raise HTTPException(400,'Picture too large (3 MB maximum)')
  if raw.startswith(b'\xff\xd8\xff'): extension='jpg'
  elif raw.startswith(b'\x89PNG\r\n\x1a\n'): extension='png'
  elif raw.startswith(b'RIFF') and raw[8:12]==b'WEBP': extension='webp'
  else:raise HTTPException(400,'Use JPEG, PNG or WebP images only')
  folder=DATA_DIR/'announcements';folder.mkdir(parents=True,exist_ok=True)
  filename=secrets.token_hex(14)+'.'+extension
  (folder/filename).write_bytes(raw)
  image_url='/assets/announcements/'+filename
 with conn() as c:
  cur=c.execute('INSERT INTO announcements(title,body,image_path,created_by,created) VALUES(?,?,?,?,?)',(title,content,image_url,u['id'],now()))
  audit(c,u,0,'create_announcement',title)
 return {'id':cur.lastrowid}

@app.delete('/api/announcements/{post_id}')
def delete_announcement(post_id:int,req:Request):
 u=need(req)
 if u['role'] not in SSD_PUBLISHERS:raise HTTPException(403,'Not authorized')
 with conn() as c:
  existing=c.execute('SELECT id FROM announcements WHERE id=?',(post_id,)).fetchone()
  if not existing:raise HTTPException(404,'Announcement not found')
  c.execute('DELETE FROM announcements WHERE id=?',(post_id,));audit(c,u,0,'delete_announcement',str(post_id))
 return {'ok':True}

@app.get('/assets/announcements/{filename}')
def announcement_image(filename:str,req:Request):
 need(req)
 if '/' in filename or '\\' in filename or not filename.rsplit('.',1)[-1].lower() in ['jpg','png','webp'] or len(filename)>90:raise HTTPException(404)
 candidate=DATA_DIR/'announcements'/filename
 if not candidate.is_file():raise HTTPException(404)
 return FileResponse(candidate)

@app.get('/api/events')
def get_events(req:Request):
 u=need(req)
 with conn() as c:
  if u['role'] in ['admin','ssd','ssd_youth_director','ssd_pathfinder_director']:
   rows=c.execute('SELECT * FROM events ORDER BY starts_at ASC,id DESC').fetchall()
  else:
   rows=c.execute('SELECT * FROM events WHERE scope IN ("ssd","mission") OR (scope="club" AND club_id=?) ORDER BY starts_at ASC,id DESC',(u['club_id'],)).fetchall()
  return [dict(x) for x in rows]

@app.post('/api/events')
def add_event(body:EventPost,req:Request):
 u=need(req)
 title=checked_str(body.title,140,'Title');description=body.description.strip()[:2000];location=body.location.strip()[:180]
 try:
  start=datetime.datetime.fromisoformat(body.starts_at)
  if body.ends_at and datetime.datetime.fromisoformat(body.ends_at)<start:raise ValueError()
 except ValueError:raise HTTPException(400,'Invalid dates or end date before start date')
 if body.scope not in ['ssd','mission','club']:raise HTTPException(400,'Invalid calendar scope')
 if body.scope=='ssd' and u['role'] not in SSD_PUBLISHERS:raise HTTPException(403,'SSD calendar requires an SSD director')
 if body.scope=='mission' and u['role'] not in MISSION_PUBLISHERS|SSD_PUBLISHERS:raise HTTPException(403,'Mission calendar requires a Mission director')
 if body.scope=='club' and u['role'] not in SSD_PUBLISHERS|MISSION_PUBLISHERS|{'director'}:raise HTTPException(403,'Club Director required')
 club_id=None
 if body.scope=='club':
  club_id=body.club_id if u['role'] in SSD_PUBLISHERS else u['club_id']
  if not club_id:raise HTTPException(400,'Assign a club first')
  with conn() as c:
   if not c.execute('SELECT 1 FROM clubs WHERE id=?',(club_id,)).fetchone():raise HTTPException(400,'Club not found')
 with conn() as c:
  cur=c.execute('INSERT INTO events(title,description,starts_at,ends_at,location,scope,club_id,created_by,created) VALUES(?,?,?,?,?,?,?,?,?)',(title,description,body.starts_at,body.ends_at,location,body.scope,club_id,u['id'],now()))
  audit(c,u,0,'create_event',body.scope+':'+title)
 return {'id':cur.lastrowid}

@app.delete('/api/events/{event_id}')
def delete_event(event_id:int,req:Request):
 u=need(req)
 with conn() as c:
  event=c.execute('SELECT * FROM events WHERE id=?',(event_id,)).fetchone()
  if not event:raise HTTPException(404,'Event not found')
  if not (u['role'] in SSD_PUBLISHERS or (event['scope']=='mission' and u['role'] in MISSION_PUBLISHERS) or (event['scope']=='club' and u['role']=='director' and u['club_id']==event['club_id'])):
   raise HTTPException(403,'Not authorized')
  c.execute('DELETE FROM events WHERE id=?',(event_id,));audit(c,u,0,'delete_event',str(event_id))
 return {'ok':True}

class LogoUpload(BaseModel):
 image_base64:str
@app.post('/api/branding/master-guide-logo')
def upload_master_guide_logo(body:LogoUpload,req:Request):
 u=need(req)
 if u['role'] not in SSD_PUBLISHERS:raise HTTPException(403,'Only administrator/SSD may change the Master Guide logo')
 try:
  raw=base64.b64decode(body.image_base64.split(',',1)[-1],validate=True)
  if len(raw)>3_000_000:raise HTTPException(400,'Maximum logo size is 3 MB')
  from PIL import Image, UnidentifiedImageError
  with Image.open(io.BytesIO(raw)) as im:
   if im.format not in ('PNG','JPEG','WEBP'):raise HTTPException(400,'Use PNG/JPEG/WebP only')
   im=im.convert('RGBA')
   im.thumbnail((1024,1024))
   im.save(DATA_DIR/'master_guide_logo.png',format='PNG')
 except (ValueError,binascii.Error,UnidentifiedImageError,OSError):
  raise HTTPException(400,'Invalid logo image')
 with conn() as c:audit(c,u,0,'update_master_guide_logo')
 return {'ok':True}

@app.get('/assets/master_guide_logo.png')
def master_guide_logo(req:Request):
 need(req)
 target=DATA_DIR/'master_guide_logo.png'
 if not target.is_file():raise HTTPException(404,'Upload the official logo through the SSD administrator panel')
 return FileResponse(target,media_type='image/png',headers={'Cache-Control':'no-store'})

@app.get('/healthz')
def healthz():
 with conn() as c:
  c.execute('SELECT 1')
 return {'ok':True}
