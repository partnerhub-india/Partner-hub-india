import os, sqlite3, secrets
from datetime import datetime, timedelta
from typing import Optional
import jwt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

DB="data/partnerhub.db"
os.makedirs("data", exist_ok=True)
SECRET=os.getenv("SECRET_KEY","dev-only-change-this-secret")
pwd=CryptContext(schemes=["bcrypt"], deprecated="auto")
app=FastAPI(title="PartnerHub API", version="1.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, city TEXT, skills TEXT, investment INTEGER DEFAULT 0,
      interests TEXT, role TEXT DEFAULT 'partner', verified INTEGER DEFAULT 0,
      blocked INTEGER DEFAULT 0, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS businesses(
      id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, name TEXT NOT NULL,
      category TEXT, city TEXT, investment_required INTEGER DEFAULT 0,
      partner_investment INTEGER DEFAULT 0, partnership_pct REAL DEFAULT 0,
      profit_share REAL DEFAULT 0, description TEXT, status TEXT DEFAULT 'active',
      created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS interests(
      id INTEGER PRIMARY KEY, user_id INTEGER, business_id INTEGER,
      status TEXT DEFAULT 'pending', created_at TEXT NOT NULL,
      UNIQUE(user_id,business_id));
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER,
      body TEXT NOT NULL, created_at TEXT NOT NULL, read INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY, user_id INTEGER, text TEXT, created_at TEXT NOT NULL, read INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY, reporter_id INTEGER, reported_user_id INTEGER,
      reason TEXT, status TEXT DEFAULT 'open', created_at TEXT NOT NULL);
    """)
    admin=c.execute("SELECT id FROM users WHERE email=?",("admin@partnerhub.local",)).fetchone()
    if not admin:
        c.execute("INSERT INTO users(name,email,password,role,created_at,verified) VALUES(?,?,?,?,?,1)",
                  ("PartnerHub Admin","admin@partnerhub.local",pwd.hash("ChangeMe123!"),"admin",datetime.utcnow().isoformat()))
    c.commit(); c.close()
init()

class Register(BaseModel):
    name:str; email:EmailStr; password:str; city:str=""; skills:str=""; investment:int=0; interests:str=""; role:str="partner"
class Login(BaseModel):
    email:EmailStr; password:str
class Profile(BaseModel):
    name:Optional[str]=None; city:Optional[str]=None; skills:Optional[str]=None; investment:Optional[int]=None; interests:Optional[str]=None
class BusinessIn(BaseModel):
    name:str; category:str=""; city:str=""; investment_required:int=0; partner_investment:int=0
    partnership_pct:float=0; profit_share:float=0; description:str=""
class MessageIn(BaseModel):
    receiver_id:int; body:str
class InterestIn(BaseModel):
    business_id:int
class ReportIn(BaseModel):
    reported_user_id:int; reason:str

def token(uid):
    return jwt.encode({"sub":uid,"exp":datetime.utcnow()+timedelta(days=7)},SECRET,algorithm="HS256")
def me(authorization:Optional[str]=Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Login required")
    try: uid=jwt.decode(authorization[7:],SECRET,algorithms=["HS256"])["sub"]
    except Exception: raise HTTPException(401,"Invalid or expired token")
    c=db(); u=c.execute("SELECT * FROM users WHERE id=? AND blocked=0",(uid,)).fetchone(); c.close()
    if not u: raise HTTPException(401,"User unavailable")
    return dict(u)
def score(u,b):
    s=0
    if u["city"] and b["city"] and u["city"].lower()==b["city"].lower(): s+=25
    if u["investment"]>=b["partner_investment"]>0: s+=35
    ui=set(x.strip().lower() for x in (u["interests"] or "").split(",") if x.strip())
    bi=set(x.strip().lower() for x in (b["category"] or "").split(",") if x.strip())
    if ui and bi and ui & bi: s+=25
    if u["skills"]: s+=15
    return min(100,s)

@app.get("/")
def home(): return FileResponse("static/index.html")

@app.post("/api/register")
def register(x:Register):
 if len(x.password)<8: raise HTTPException(400,"Password must be at least 8 characters")
if len(x.password.encode("utf-8"))>72: raise HTTPException(400,"Password must be 72 bytes or less")   
    if x.role not in ("partner","owner"): raise HTTPException(400,"Invalid role")
    c=db()
    try:
        cur=c.execute("INSERT INTO users(name,email,password,city,skills,investment,interests,role,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
          (x.name,x.email,pwd.hash(x.password),x.city,x.skills,x.investment,x.interests,x.role,datetime.utcnow().isoformat()))
        c.commit(); uid=cur.lastrowid
    except sqlite3.IntegrityError: raise HTTPException(409,"Email already registered")
    finally: c.close()
    return {"token":token(uid),"user_id":uid}

@app.post("/api/login")
def login(x:Login):
    c=db(); u=c.execute("SELECT * FROM users WHERE email=? AND blocked=0",(x.email,)).fetchone(); c.close()
    if not u or not pwd.verify(x.password,u["password"]): raise HTTPException(401,"Wrong email or password")
    return {"token":token(u["id"]),"user":dict(u)}

@app.get("/api/me")
def get_me(u=Depends(me)): return {k:v for k,v in u.items() if k!="password"}

@app.put("/api/me")
def update_profile(x:Profile,u=Depends(me)):
    vals={k:v for k,v in x.model_dump().items() if v is not None}
    if not vals:return {"ok":True}
    c=db(); sets=",".join(f"{k}=?" for k in vals); c.execute(f"UPDATE users SET {sets} WHERE id=?",[*vals.values(),u["id"]]); c.commit(); c.close()
    return {"ok":True}

@app.post("/api/businesses")
def create_business(x:BusinessIn,u=Depends(me)):
    if u["role"] not in ("owner","admin"): raise HTTPException(403,"Owner account required")
    c=db(); cur=c.execute("""INSERT INTO businesses(owner_id,name,category,city,investment_required,partner_investment,partnership_pct,profit_share,description,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?)""",(u["id"],x.name,x.category,x.city,x.investment_required,x.partner_investment,x.partnership_pct,x.profit_share,x.description,datetime.utcnow().isoformat()))
    c.commit(); bid=cur.lastrowid; c.close(); return {"business_id":bid}

@app.get("/api/businesses")
def businesses(q:str="",city:str="",u=Depends(me)):
    c=db(); rows=c.execute("SELECT * FROM businesses WHERE status='active' AND name LIKE ? AND city LIKE ? ORDER BY id DESC",("%"+q+"%","%"+city+"%")).fetchall(); c.close()
    out=[]
    for b in rows:
        d=dict(b); d["match_score"]=score(u,d); out.append(d)
    return out

@app.post("/api/interests")
def interest(x:InterestIn,u=Depends(me)):
    c=db(); b=c.execute("SELECT * FROM businesses WHERE id=?",(x.business_id,)).fetchone()
    if not b: c.close(); raise HTTPException(404,"Business not found")
    try:
        c.execute("INSERT INTO interests(user_id,business_id,created_at) VALUES(?,?,?)",(u["id"],x.business_id,datetime.utcnow().isoformat()))
    except sqlite3.IntegrityError:
        c.execute("UPDATE interests SET status='pending' WHERE user_id=? AND business_id=?",(u["id"],x.business_id))
    c.execute("INSERT INTO notifications(user_id,text,created_at) VALUES(?,?,?)",(b["owner_id"],f"{u['name']} is interested in your business: {b['name']}",datetime.utcnow().isoformat()))
    c.commit(); c.close(); return {"ok":True}

@app.get("/api/matches")
def matches(u=Depends(me)):
    c=db(); rows=c.execute("""SELECT i.*,b.name,b.category,b.city,b.partner_investment,b.partnership_pct,b.owner_id
      FROM interests i JOIN businesses b ON b.id=i.business_id WHERE i.user_id=? ORDER BY i.id DESC""",(u["id"],)).fetchall(); c.close()
    return [dict(r) for r in rows]

@app.post("/api/messages")
def send_message(x:MessageIn,u=Depends(me)):
    if not x.body.strip(): raise HTTPException(400,"Empty message")
    c=db(); r=c.execute("SELECT id FROM users WHERE id=? AND blocked=0",(x.receiver_id,)).fetchone()
    if not r:c.close();raise HTTPException(404,"User not found")
    c.execute("INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)",(u["id"],x.receiver_id,x.body,datetime.utcnow().isoformat()))
    c.execute("INSERT INTO notifications(user_id,text,created_at) VALUES(?,?,?)",(x.receiver_id,f"New message from {u['name']}",datetime.utcnow().isoformat()))
    c.commit();c.close();return {"ok":True}

@app.get("/api/messages/{other_id}")
def messages(other_id:int,u=Depends(me)):
    c=db(); rows=c.execute("""SELECT * FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY id""",(u["id"],other_id,other_id,u["id"])).fetchall();c.close();return [dict(r) for r in rows]

@app.get("/api/notifications")
def notifications(u=Depends(me)):
    c=db(); rows=c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50",(u["id"],)).fetchall();c.close();return [dict(r) for r in rows]

@app.post("/api/reports")
def report(x:ReportIn,u=Depends(me)):
    c=db();c.execute("INSERT INTO reports(reporter_id,reported_user_id,reason,created_at) VALUES(?,?,?,?)",(u["id"],x.reported_user_id,x.reason,datetime.utcnow().isoformat()));c.commit();c.close();return {"ok":True}

@app.get("/api/admin/stats")
def admin_stats(u=Depends(me)):
    if u["role"]!="admin":raise HTTPException(403,"Admin only")
    c=db()
    r={"users":c.execute("SELECT count(*) n FROM users").fetchone()["n"],
       "businesses":c.execute("SELECT count(*) n FROM businesses").fetchone()["n"],
       "matches":c.execute("SELECT count(*) n FROM interests").fetchone()["n"],
       "reports":c.execute("SELECT count(*) n FROM reports WHERE status='open'").fetchone()["n"]}
    c.close();return r
