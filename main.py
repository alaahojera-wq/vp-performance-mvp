
import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, Form, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey, Boolean, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

SECRET_KEY = os.environ.get("VP_APP_SECRET", "CHANGE_ME_SUPER_SECRET")  # set env var in production
SESSION_SALT = "vp-performance-session"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
serializer = URLSafeTimedSerializer(SECRET_KEY, salt=SESSION_SALT)

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ----------------------------
# Database models
# ----------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)  # admin, principal, vp, data_team
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    vp_profile = relationship("VPProfile", back_populates="user", uselist=False)

class VPProfile(Base):
    __tablename__ = "vp_profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    position = Column(String(255), default="Vice Principal")
    employed_since = Column(String(50), default="")
    absence_days_current_year = Column(Integer, default=0)

    user = relationship("User", back_populates="vp_profile")
    metric_values = relationship("MetricValue", back_populates="vp")
    evidence_items = relationship("Evidence", back_populates="vp")

class Term(Base):
    __tablename__ = "terms"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)  # e.g. "2025-26 Term 1"
    start_date = Column(String(20), default="")
    end_date = Column(String(20), default="")
    created_at = Column(DateTime, default=datetime.utcnow)

class Pillar(Base):
    __tablename__ = "pillars"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    weight = Column(Float, nullable=False)  # 0-1
    sort_order = Column(Integer, default=0)

    metrics = relationship("Metric", back_populates="pillar", cascade="all, delete-orphan")

class Metric(Base):
    __tablename__ = "metrics"
    id = Column(Integer, primary_key=True)
    pillar_id = Column(Integer, ForeignKey("pillars.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    target_text = Column(Text, default="")
    frequency = Column(String(50), default="Termly")
    weight_within_pillar = Column(Float, default=1.0)  # relative weight (normalized per pillar)
    sort_order = Column(Integer, default=0)

    pillar = relationship("Pillar", back_populates="metrics")
    values = relationship("MetricValue", back_populates="metric", cascade="all, delete-orphan")
    evidence_items = relationship("Evidence", back_populates="metric", cascade="all, delete-orphan")

class MetricValue(Base):
    __tablename__ = "metric_values"
    id = Column(Integer, primary_key=True)
    metric_id = Column(Integer, ForeignKey("metrics.id"), nullable=False)
    vp_id = Column(Integer, ForeignKey("vp_profiles.id"), nullable=False)
    term_id = Column(Integer, ForeignKey("terms.id"), nullable=False)

    actual_value = Column(Text, default="")
    auto_score = Column(Float, nullable=True)  # 1-4
    override_score = Column(Float, nullable=True)
    override_reason = Column(Text, default="")
    updated_at = Column(DateTime, default=datetime.utcnow)

    metric = relationship("Metric", back_populates="values")
    vp = relationship("VPProfile", back_populates="metric_values")
    term = relationship("Term")

    __table_args__ = (UniqueConstraint("metric_id", "vp_id", "term_id", name="uq_metric_vp_term"),)

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    vp_id = Column(Integer, ForeignKey("vp_profiles.id"), nullable=False)
    metric_id = Column(Integer, ForeignKey("metrics.id"), nullable=False)
    term_id = Column(Integer, ForeignKey("terms.id"), nullable=False)

    kind = Column(String(20), default="file")  # file/link/note
    file_path = Column(String(500), default="")
    link_url = Column(String(500), default="")
    note = Column(Text, default="")
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    vp = relationship("VPProfile", back_populates="evidence_items")
    metric = relationship("Metric", back_populates="evidence_items")
    term = relationship("Term")

# ----------------------------
# App + templates
# ----------------------------
app = FastAPI(title="VP Performance System (Framework-based)")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ----------------------------
# Helpers
# ----------------------------
RATING_BANDS = [
    ("Outstanding", 3.6, 4.0),
    ("Very Good", 3.0, 3.59),
    ("Satisfactory", 2.0, 2.99),
    ("Unsatisfactory", 0.0, 1.99),
]

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)

def create_session_token(user_id: int) -> str:
    return serializer.dumps({"uid": user_id})

def read_session_token(token: str, max_age_seconds: int = 60*60*24*7) -> Optional[int]:
    try:
        data = serializer.loads(token, max_age=max_age_seconds)
        return int(data.get("uid"))
    except (BadSignature, SignatureExpired, Exception):
        return None

def rating_from_score(score: float) -> str:
    for name, low, high in RATING_BANDS:
        if low <= score <= high:
            return name
    return "Incomplete"

def normalize_weights(metrics):
    total = sum(m.weight_within_pillar for m in metrics) or 1.0
    return {m.id: (m.weight_within_pillar / total) for m in metrics}

def compute_metric_score(metric: Metric, actual_value: str) -> Optional[float]:
    """
    MVP scoring (edit in Admin later):
    - If actual_value looks like a percent: score based on thresholds.
    - If actual_value is blank: None
    - Otherwise: None (requires override/manual scoring)
    """
    if not actual_value or not actual_value.strip():
        return None
    v = actual_value.strip().replace("%", "")
    try:
        num = float(v)
    except ValueError:
        return None

    # Heuristic: percent-based target
    # 4: >= target+5, 3: >= target, 2: >= target-10, 1: else
    # We try to extract a target percent from target_text if present (e.g. "≥95%" or "97%")
    target = None
    import re
    m = re.search(r"(\d{2,3}(?:\.\d+)?)\s*%", (metric.target_text or ""))
    if m:
        target = float(m.group(1))
    if target is None:
        # generic percent thresholds
        if num >= 95: return 4.0
        if num >= 85: return 3.0
        if num >= 70: return 2.0
        return 1.0

    if num >= target + 5: return 4.0
    if num >= target: return 3.0
    if num >= max(target - 10, 0): return 2.0
    return 1.0

def compute_vp_term_scores(db: Session, vp: VPProfile, term: Term):
    pillars = db.query(Pillar).order_by(Pillar.sort_order).all()
    results = []
    overall = 0.0
    overall_weight = 0.0

    for p in pillars:
        metrics = db.query(Metric).filter(Metric.pillar_id == p.id).order_by(Metric.sort_order).all()
        wmap = normalize_weights(metrics)
        pillar_raw = 0.0
        pillar_w = 0.0

        for m in metrics:
            mv = db.query(MetricValue).filter_by(metric_id=m.id, vp_id=vp.id, term_id=term.id).first()
            score = None
            if mv:
                score = mv.override_score if mv.override_score is not None else mv.auto_score
            if score is None:
                continue
            pillar_raw += score * wmap[m.id]
            pillar_w += wmap[m.id]

        pillar_score = (pillar_raw / pillar_w) if pillar_w > 0 else None
        weighted = (pillar_score * p.weight) if pillar_score is not None else None
        if weighted is not None:
            overall += weighted
            overall_weight += p.weight

        results.append({
            "pillar": p,
            "pillar_score": pillar_score,
            "weighted_score": weighted,
        })

    overall_score = (overall / overall_weight) if overall_weight > 0 else None
    return results, overall_score

# ----------------------------
# Auth dependencies
# ----------------------------
def current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get("vp_session", "")
    uid = read_session_token(token) if token else None
    if not uid:
        return None
    return db.query(User).filter(User.id == uid, User.is_active == True).first()

def require_user(user: Optional[User] = Depends(current_user)) -> User:
    if not user:
        raise Exception("Not authenticated")
    return user

def require_role(roles):
    def _inner(user: User = Depends(require_user)) -> User:
        if user.role not in roles:
            raise Exception("Forbidden")
        return user
    return _inner

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Simple friendly redirect for auth errors
    msg = str(exc)
    if "Not authenticated" in msg:
        return RedirectResponse("/login", status_code=303)
    if "Forbidden" in msg:
        return HTMLResponse("Forbidden", status_code=403)
    return HTMLResponse(f"Error: {msg}", status_code=500)

# ----------------------------
# Routes
# ----------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == email.lower().strip(), User.is_active == True).first()
    if not u or not verify_password(password, u.password_hash):
        resp = RedirectResponse("/login?err=1", status_code=303)
        return resp
    token = create_session_token(u.id)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("vp_session", token, httponly=True, samesite="lax")
    return resp

@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("vp_session")
    return resp

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    # choose active term = latest created
    term = db.query(Term).order_by(Term.id.desc()).first()
    if not term:
        return RedirectResponse("/admin/terms", status_code=303)

    if user.role == "vp":
        vp = user.vp_profile
        return RedirectResponse(f"/vp/{vp.id}?term_id={term.id}", status_code=303)

    # Principal/Admin view: list all VPs with scores
    vps = db.query(VPProfile).all()
    rows = []
    for vp in vps:
        pillar_rows, overall_score = compute_vp_term_scores(db, vp, term)
        rows.append({
            "vp": vp,
            "overall_score": overall_score,
            "rating": rating_from_score(overall_score) if overall_score is not None else "Incomplete"
        })

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "term": term,
        "rows": rows,
    })

@app.get("/vp/{vp_id}", response_class=HTMLResponse)
def vp_detail(request: Request, vp_id: int, term_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(require_user)):
    vp = db.query(VPProfile).filter(VPProfile.id == vp_id).first()
    if not vp:
        return HTMLResponse("VP not found", status_code=404)

    # Access control
    if user.role == "vp" and (not user.vp_profile or user.vp_profile.id != vp_id):
        raise Exception("Forbidden")

    term = db.query(Term).filter(Term.id == (term_id or 0)).first() if term_id else db.query(Term).order_by(Term.id.desc()).first()
    if not term:
        return RedirectResponse("/admin/terms", status_code=303)

    pillars = db.query(Pillar).order_by(Pillar.sort_order).all()
    pillar_blocks = []
    for p in pillars:
        metrics = db.query(Metric).filter(Metric.pillar_id == p.id).order_by(Metric.sort_order).all()
        items = []
        for m in metrics:
            mv = db.query(MetricValue).filter_by(metric_id=m.id, vp_id=vp.id, term_id=term.id).first()
            if not mv:
                mv = MetricValue(metric_id=m.id, vp_id=vp.id, term_id=term.id, actual_value="")
                mv.auto_score = None
                db.add(mv)
                db.commit()
                db.refresh(mv)

            # compute auto-score if possible and no override
            if mv.override_score is None:
                auto = compute_metric_score(m, mv.actual_value)
                if auto != mv.auto_score:
                    mv.auto_score = auto
                    mv.updated_at = datetime.utcnow()
                    db.commit()

            evidence_count = db.query(Evidence).filter_by(vp_id=vp.id, metric_id=m.id, term_id=term.id).count()
            items.append({
                "metric": m,
                "mv": mv,
                "score": mv.override_score if mv.override_score is not None else mv.auto_score,
                "evidence_count": evidence_count
            })
        pillar_blocks.append({"pillar": p, "items": items})

    pillar_rows, overall_score = compute_vp_term_scores(db, vp, term)
    rating = rating_from_score(overall_score) if overall_score is not None else "Incomplete"

    terms = db.query(Term).order_by(Term.id.desc()).all()

    return templates.TemplateResponse("vp_detail.html", {
        "request": request,
        "user": user,
        "vp": vp,
        "term": term,
        "terms": terms,
        "pillar_blocks": pillar_blocks,
        "pillar_rows": pillar_rows,
        "overall_score": overall_score,
        "rating": rating,
    })

@app.post("/vp/{vp_id}/metric/{metric_id}/update")
def update_metric(vp_id: int, metric_id: int,
                  term_id: int = Form(...),
                  actual_value: str = Form(""),
                  override_score: str = Form(""),
                  override_reason: str = Form(""),
                  db: Session = Depends(get_db),
                  user: User = Depends(require_user)):
    vp = db.query(VPProfile).filter(VPProfile.id == vp_id).first()
    if not vp:
        return HTMLResponse("VP not found", status_code=404)

    if user.role == "vp" and user.vp_profile.id != vp_id:
        raise Exception("Forbidden")

    mv = db.query(MetricValue).filter_by(metric_id=metric_id, vp_id=vp_id, term_id=term_id).first()
    if not mv:
        mv = MetricValue(metric_id=metric_id, vp_id=vp_id, term_id=term_id)
        db.add(mv)

    mv.actual_value = actual_value

    # Only principal/admin can override score
    if user.role in ["admin", "principal"]:
        override_score = override_score.strip()
        if override_score:
            try:
                mv.override_score = float(override_score)
                mv.override_reason = override_reason.strip()
            except ValueError:
                pass
        else:
            mv.override_score = None
            mv.override_reason = ""

    mv.auto_score = compute_metric_score(db.query(Metric).get(metric_id), mv.actual_value)
    mv.updated_at = datetime.utcnow()
    db.commit()

    return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=303)

@app.post("/vp/{vp_id}/metric/{metric_id}/evidence")
async def add_evidence(vp_id: int, metric_id: int,
                       term_id: int = Form(...),
                       kind: str = Form("note"),
                       link_url: str = Form(""),
                       note: str = Form(""),
                       file: UploadFile = File(None),
                       db: Session = Depends(get_db),
                       user: User = Depends(require_user)):
    if user.role == "vp" and user.vp_profile.id != vp_id:
        raise Exception("Forbidden")

    ev = Evidence(vp_id=vp_id, metric_id=metric_id, term_id=term_id, kind=kind)

    if kind == "file" and file is not None:
        filename = f"{vp_id}_{term_id}_{metric_id}_{int(datetime.utcnow().timestamp())}_{file.filename}"
        safe = "".join([c for c in filename if c.isalnum() or c in "._-"])
        path = os.path.join(UPLOAD_DIR, safe)
        with open(path, "wb") as f:
            f.write(await file.read())
        ev.file_path = f"/uploads/{safe}"
    elif kind == "link":
        ev.link_url = link_url.strip()
    else:
        ev.note = note.strip()

    db.add(ev)
    db.commit()

    return RedirectResponse(f"/vp/{vp_id}?term_id={term_id}", status_code=303)

@app.get("/admin/terms", response_class=HTMLResponse)
def admin_terms(request: Request, db: Session = Depends(get_db), user: User = Depends(require_role(["admin", "principal"]))):
    terms = db.query(Term).order_by(Term.id.desc()).all()
    return templates.TemplateResponse("terms.html", {"request": request, "user": user, "terms": terms})

@app.post("/admin/terms")
def admin_terms_create(name: str = Form(...), start_date: str = Form(""), end_date: str = Form(""),
                       db: Session = Depends(get_db), user: User = Depends(require_role(["admin", "principal"]))):
    t = Term(name=name.strip(), start_date=start_date.strip(), end_date=end_date.strip())
    db.add(t)
    db.commit()
    return RedirectResponse("/admin/terms", status_code=303)

@app.get("/admin/metrics", response_class=HTMLResponse)
def admin_metrics(request: Request, db: Session = Depends(get_db), user: User = Depends(require_role(["admin"]))):
    pillars = db.query(Pillar).order_by(Pillar.sort_order).all()
    return templates.TemplateResponse("admin_metrics.html", {"request": request, "user": user, "pillars": pillars})

# ----------------------------
# Seed framework (from your doc)
# ----------------------------
def seed_framework(db: Session):
    if db.query(Pillar).count() > 0:
        return

    pillars = [
        Pillar(name="Student Achievement & Progress", weight=0.60, sort_order=1),
        Pillar(name="Student Attendance, Behaviour & Engagement", weight=0.20, sort_order=2),
        Pillar(name="Academic Quality, Leadership & Compliance", weight=0.20, sort_order=3),
    ]
    db.add_all(pillars)
    db.commit()

    p1, p2, p3 = db.query(Pillar).order_by(Pillar.sort_order).all()

    # Pillar 1 metrics (from doc tables + bullets)
    p1_metrics = [
        Metric(pillar_id=p1.id, name="Students achieving ≥80% in core subjects", target_text="≥80% in Math, English, Science, Arabic (Termly)", frequency="Termly", sort_order=1),
        Metric(pillar_id=p1.id, name="Reduction of students scoring below 60%", target_text="Reduction each term", frequency="Termly", sort_order=2),
        Metric(pillar_id=p1.id, name="Core subject pass rate", target_text="97% pass rate (G3–5)", frequency="Termly", sort_order=3),
        Metric(pillar_id=p1.id, name="Benchmark exam performance monitored", target_text="Monitored termly with actions documented", frequency="Termly", sort_order=4),
        Metric(pillar_id=p1.id, name="100% of at-risk students have IAPs", target_text="100% IAP coverage", frequency="Termly", sort_order=5),
        Metric(pillar_id=p1.id, name="Measurable termly progress for at-risk students", target_text="Termly progress documented", frequency="Termly", sort_order=6),
        Metric(pillar_id=p1.id, name="Gifted & Talented identified and tracked", target_text="Identified & tracked", frequency="Termly", sort_order=7),
        Metric(pillar_id=p1.id, name="Enrichment and stretch provision documented", target_text="Documented", frequency="Termly", sort_order=8),
        Metric(pillar_id=p1.id, name="Monthly attendance target", target_text="Monthly attendance target (%)", frequency="Monthly", sort_order=9),
        Metric(pillar_id=p1.id, name="Parent contact within 48 hours for at-risk students", target_text="100% within 48 hours", frequency="Monthly", sort_order=10),
        Metric(pillar_id=p1.id, name="Monthly reduction in lateness cases", target_text="Reduction month-on-month", frequency="Monthly", sort_order=11),
        Metric(pillar_id=p1.id, name="Communication logs maintained", target_text="Documented logs maintained", frequency="Monthly", sort_order=12),
    ]

    # Pillar 2: broad statement in doc — keep as metrics to be scored (manual or percent-based)
    p2_metrics = [
        Metric(pillar_id=p2.id, name="Attendance is data-driven & systematically tracked", target_text="Systems in place + evidence", frequency="Monthly", sort_order=1),
        Metric(pillar_id=p2.id, name="Behaviour incidents tracked & actions documented", target_text="Tracking + interventions + evidence", frequency="Monthly", sort_order=2),
        Metric(pillar_id=p2.id, name="Student well-being supported with parent collaboration", target_text="Documented comms + pastoral collaboration", frequency="Monthly", sort_order=3),
    ]

    # Pillar 3 metrics (from bullets)
    p3_metrics = [
        Metric(pillar_id=p3.id, name="Subject leadership meetings per term", target_text="Minimum 4 per term", frequency="Termly", sort_order=1),
        Metric(pillar_id=p3.id, name="Weekly plans/assessments submitted on time", target_text="≥95% on time", frequency="Weekly", sort_order=2),
        Metric(pillar_id=p3.id, name="Classroom observation per teacher per term", target_text="Minimum 1 per teacher per term", frequency="Termly", sort_order=3),
        Metric(pillar_id=p3.id, name="Curriculum maps completed before Week 0", target_text="100% before Week 0", frequency="Annual", sort_order=4),
        Metric(pillar_id=p3.id, name="Zero unresolved parent complaints", target_text="0 unresolved", frequency="Monthly", sort_order=5),
        Metric(pillar_id=p3.id, name="Coaching for new/underperforming teachers", target_text="Coaching documented", frequency="Monthly", sort_order=6),
        Metric(pillar_id=p3.id, name="Teacher turnover", target_text="≤25% annually", frequency="Annual", sort_order=7),
        Metric(pillar_id=p3.id, name="Teacher attendance rate", target_text="≥96%", frequency="Monthly", sort_order=8),
        Metric(pillar_id=p3.id, name="Documented absence follow-up", target_text="100% follow-up documented", frequency="Monthly", sort_order=9),
        Metric(pillar_id=p3.id, name="Policy implementation compliance", target_text="100% compliance", frequency="Ongoing", sort_order=10),
        Metric(pillar_id=p3.id, name="ADEK & safeguarding emails response time", target_text="Respond within 24–48 hours", frequency="Ongoing", sort_order=11),
        Metric(pillar_id=p3.id, name="All safeguarding/compliance cases documented & resolved", target_text="All cases documented & resolved", frequency="Ongoing", sort_order=12),
        Metric(pillar_id=p3.id, name="Assessments completed and moderated on time", target_text="100% on time", frequency="Termly", sort_order=13),
        Metric(pillar_id=p3.id, name="Compliance with examination regulations", target_text="Full compliance", frequency="Termly", sort_order=14),
        Metric(pillar_id=p3.id, name="Weekly collaboration with Assessment Coordinator", target_text="Weekly collaboration documented", frequency="Weekly", sort_order=15),
    ]

    db.add_all(p1_metrics + p2_metrics + p3_metrics)
    db.commit()

def seed_users(db: Session):
    if db.query(User).count() > 0:
        return

    admin = User(email="admin@local", full_name="System Admin", role="admin", password_hash=hash_password("admin123"))
    principal = User(email="principal@local", full_name="School Principal", role="principal", password_hash=hash_password("principal123"))
    vp_user = User(email="vp@local", full_name="VP Example", role="vp", password_hash=hash_password("vp123"))

    db.add_all([admin, principal, vp_user])
    db.commit()

    vp_profile = VPProfile(user_id=vp_user.id, position="Vice Principal", employed_since="2023", absence_days_current_year=0)
    db.add(vp_profile)
    db.commit()

def seed_terms(db: Session):
    if db.query(Term).count() > 0:
        return
    db.add(Term(name="2025-26 Term 1", start_date="2025-09-01", end_date="2025-12-15"))
    db.commit()

@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        seed_framework(db)
        seed_users(db)
        seed_terms(db)
    finally:
        db.close()
