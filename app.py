import threading
import json
import time
import random
import string
import os
import resend
import io
from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# import serial   # Uncomment and install if needed locally; disable on Render

# ─── CONFIG ───────────────────────────────────────────────────────────────
SERIAL_ENABLED = False          # Set to True only for local dev with serial port
SERIAL_PORT    = "COM6"         # Only used when SERIAL_ENABLED=True
BAUD_RATE      = 9600
SERIAL_TIMEOUT_SEC = 0.2

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ─── DATABASE CONFIGURATION ───────────────────────────────────────────────
db_uri = os.environ.get('DATABASE_URL')
if db_uri and 'postgres' in db_uri.lower():
    db_uri = db_uri.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:041323@localhost:3306/farmlinkdb'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 3600,
    'pool_pre_ping': True
}

db = SQLAlchemy(app)

# ─── FLASK-MAIL CONFIG ────────────────────────────────────────────────────
app.config['MAIL_SERVER']       = 'smtp.gmail.com'
app.config['MAIL_PORT']         = 587
app.config['MAIL_USE_TLS']      = True
app.config['MAIL_USERNAME']     = 'farmlinktech.ph@gmail.com'
app.config['MAIL_PASSWORD']     = 'qhfbxiirttjzkrzd'
app.config['MAIL_DEFAULT_SENDER'] = 'farmlinktech.ph@gmail.com'
app.config['MAIL_DEBUG']        = True

#os.environ.get('MAIL_APP_PASSWORD'
mail = Mail(app)

# ─── RESEND CONFIG ────────────────────────────────────────────────────────
resend.api_key = os.environ.get('RESEND_API_KEY')

# ─── JWT CONFIG ───────────────────────────────────────────────────────────
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key-please-change-this-in-production')
jwt = JWTManager(app)

# ─── MODELS ───────────────────────────────────────────────────────────────

class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    fullname      = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), default="sakada")  # sakada or owner
    verified      = db.Column(db.Boolean, default=False)
    access_code   = db.Column(db.String(30))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"

class Log(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    title     = db.Column(db.String(100), nullable=False)
    message   = db.Column(db.Text, nullable=False)
    log_type  = db.Column(db.String(20), default="info")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f"<Log {self.title}>"

class PalayanConfig(db.Model):
    id                  = db.Column(db.Integer, primary_key=True)
    min_moisture        = db.Column(db.Float, default=40.0)
    max_moisture        = db.Column(db.Float, default=70.0)
    auto_mode           = db.Column(db.Boolean, default=True)
    auto_water_time     = db.Column(db.String(5), default="06:00")
    duration_minutes    = db.Column(db.Integer, default=10)
    max_temperature     = db.Column(db.Float, default=35.0)
    min_humidity        = db.Column(db.Float, default=50.0)
    last_updated        = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    current_moisture    = db.Column(db.Float, default=0.0)
    current_temperature = db.Column(db.Float, default=0.0)
    current_humidity    = db.Column(db.Float, default=0.0)
    current_light       = db.Column(db.Float, default=0.0)
    solenoid_open       = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return "<PalayanConfig (single row)>"

class Alert(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(100), nullable=False)
    message     = db.Column(db.Text, nullable=False)
    alert_type  = db.Column(db.String(20), default="info")
    severity    = db.Column(db.Integer, default=1)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    is_read     = db.Column(db.Boolean, default=False)
    resolved    = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "type": self.alert_type,
            "severity": self.severity,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %I:%M %p"),
            "is_read": self.is_read,
            "resolved": self.resolved
        }

    def __repr__(self):
        return f"<Alert {self.title}>"

class IrrigationEvent(db.Model):
    id                = db.Column(db.Integer, primary_key=True)
    start_time        = db.Column(db.DateTime, default=datetime.utcnow)
    duration_minutes  = db.Column(db.Integer, nullable=False)
    triggered_by      = db.Column(db.String(20), default="auto")  # auto, manual, user
    user_id           = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    solenoid_opened   = db.Column(db.Boolean, default=True)
    notes             = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref='irrigation_events')

    def __repr__(self):
        return f"<IrrigationEvent {self.start_time}>"

class SensorReading(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    moisture    = db.Column(db.Float)
    temperature = db.Column(db.Float)
    humidity    = db.Column(db.Float)
    light       = db.Column(db.Float)

    def __repr__(self):
        return f"<SensorReading {self.timestamp}>"

# ─── HELPERS ──────────────────────────────────────────────────────────────

def add_log(title, message, log_type="info", user_email=None):
    user = None
    if user_email:
        user = User.query.filter_by(email=user_email).first()
    new_log = Log(
        title=title,
        message=message,
        log_type=log_type,
        user_id=user.id if user else None
    )
    db.session.add(new_log)
    db.session.commit()
    print(f"[LOG ADDED] {title} - {message}")

def send_access_code_email(recipient_email, access_code):
    # Detect if running on Render
    #is_render = 'RENDER' in os.environ or 'RENDER_SERVICE_ID' in os.environ

    #if is_render:
        # ─── Resend API (production on Render) ────────────────────────────────
    #    if not resend.api_key:
    #        print("[EMAIL] RESEND_API_KEY missing on Render – skipping send")
    #        return False

        try:
            params = {
                "from": "FarmLink <onboarding@resend.dev>",  # shared domain
                "to": [recipient_email],
                "subject": "Your FarmLink Access Code",
                "text": f"""
Dear user,

Your access code is: {access_code}

Use this code when logging in or verifying your account.
Keep it secure — do not share.

Best regards,
FarmLink Team
                """.strip()
            }

            email_resp = resend.Emails.send(params)
            print(f"[EMAIL SUCCESS via Resend] to {recipient_email} - ID: {email_resp.get('id')}")
            return True

        except Exception as e:
            print(f"[EMAIL FAILURE via Resend] {str(e)}")
            return False

    #else:
        # ─── Gmail SMTP (local development) ───────────────────────────────────
        try:
            print(f"[EMAIL DEBUG local] Attempting to send to {recipient_email} with code {access_code}")
            msg = Message(
                subject="Your FarmLink Access Code",
                recipients=[recipient_email],
                body=f"""
Dear user,

Your access code is: {access_code}

Use this code when logging in or verifying your account.
Keep it secure — do not share.

Best regards,
FarmLink Team
                """.strip()
            )
            mail.send(msg)
            print(f"[EMAIL SUCCESS local Gmail] Sent to {recipient_email}")
            return True
        except Exception as e:
            import traceback
            print("[EMAIL CRITICAL FAILURE local]")
            print(traceback.format_exc())
            return False

# ─── SERIAL WORKER ────────────────────────────────────────────────────────

def serial_worker():
    if not SERIAL_ENABLED:
        print("[SERIAL] Disabled in config")
        return

    print(f"[SERIAL] Starting on {SERIAL_PORT} @ {BAUD_RATE} baud")

    try:
        import serial  # Lazy import to avoid issues on Render
        ser = serial.Serial(
            port=SERIAL_PORT,
            baudrate=BAUD_RATE,
            timeout=SERIAL_TIMEOUT_SEC
        )
        print("[SERIAL] Port opened successfully")
        time.sleep(2)
        ser.reset_input_buffer()

        while True:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if not line:
                continue

            print(f"[SERIAL RAW] {line}")

            if "LoRa Receiver Ready" in line:
                continue

            try:
                packet = json.loads(line)
                data_str = packet.get("data", "")
                if not data_str:
                    continue

                parts = data_str.split(",")
                if len(parts) < 6:
                    continue

                moisture_raw = int(parts[1])
                humidity = float(parts[2])
                temperature = float(parts[3])
                light = float(parts[4])
                solenoid = int(parts[5])

                moisture_percent = round(100 - (moisture_raw / 10.23), 1)

                config = PalayanConfig.query.first()
                if config:
                    config.current_moisture = moisture_percent
                    config.current_temperature = temperature
                    config.current_humidity = humidity
                    config.current_light = light
                    config.solenoid_open = bool(solenoid)
                    config.last_updated = datetime.utcnow()
                    db.session.commit()

                reading = SensorReading(
                    moisture=moisture_percent,
                    temperature=temperature,
                    humidity=humidity,
                    light=light
                )
                db.session.add(reading)
                db.session.commit()

                print(f"[DB] Updated Palayan & saved reading: Moisture {moisture_percent}%")

            except Exception as e:
                print(f"[SERIAL ERROR] {e} on line: {line}")

    except ImportError:
        print("[SERIAL ERROR] serial module not available (expected on Render)")
    except serial.SerialException as e:
        print(f"[SERIAL ERROR] Cannot open port: {e}")
    except Exception as e:
        print(f"[SERIAL CRASH] {e}")

# Start serial in background (only if enabled)
threading.Thread(target=serial_worker, daemon=True).start()

# ─── AUTO-CREATE TABLES & SEED ON MODULE LOAD ──────────────────────────────
with app.app_context():
    try:
        print("[STARTUP] Creating tables if they don't exist...")
        db.create_all()
        print("[STARTUP] Tables created or already exist")

        # Seed default PalayanConfig if missing
        if not PalayanConfig.query.first():
            default = PalayanConfig()
            db.session.add(default)
            db.session.commit()
            print("[STARTUP] Created default PalayanConfig")
        else:
            print("[STARTUP] PalayanConfig already exists")

        # ─── Seed initial owner account (only if no owners exist) ──────
        if not User.query.filter_by(role='owner').first():
            print("[STARTUP] No owner account found → creating default owner")

            owner_email    = os.environ.get('DEFAULT_OWNER_EMAIL',    'owner@farmlink.ph')
            owner_fullname = os.environ.get('DEFAULT_OWNER_NAME',     'Initial Farm Owner')
            owner_password = os.environ.get('DEFAULT_OWNER_PASSWORD', 'ChangeThis123Secure!')
            owner_code     = os.environ.get('DEFAULT_OWNER_CODE',     'FRMLNK-INIT-001')

            if owner_password == 'ChangeThis123Secure!':
                print("[SEED WARNING] Using fallback password → HIGHLY RECOMMENDED: set DEFAULT_OWNER_PASSWORD env var!")

            hashed_pw = generate_password_hash(owner_password)

            default_owner = User(
                email         = owner_email,
                fullname      = owner_fullname,
                password_hash = hashed_pw,
                role          = 'owner',
                access_code   = owner_code,
                verified      = True,
                created_at    = datetime.utcnow()
            )

            db.session.add(default_owner)
            db.session.commit()

            print("[STARTUP] Default owner created successfully:")
            print(f"  Email:       {owner_email}")
            print(f"  Full name:   {owner_fullname}")
            print(f"  Access code: {owner_code}")
            print( "  Password:    (hashed from env var or fallback)")
            print( "  → Log in as owner using these credentials.")
        else:
            print("[STARTUP] At least one owner already exists → skipping owner seed")

    except Exception as e:
        print(f"[STARTUP ERROR] Failed during table creation or seeding: {str(e)}")

# ─── API ROUTES ───────────────────────────────────────────────────────────

@app.route("/api/data")
@jwt_required(optional=True)
def api_data():
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "message": "No configuration"}), 500
    return jsonify({
        "ok": True,
        "zoneA": {
            "moisture": config.current_moisture,
            "temperature": config.current_temperature,
            "humidity": config.current_humidity,
            "light": config.current_light,
            "solenoid_open": config.solenoid_open,
            "timestamp": config.last_updated.timestamp() if config.last_updated else 0
        }
    })

@app.route("/api/alerts")
@jwt_required(optional=True)
def api_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([a.to_dict() for a in alerts])

@app.route("/api/status")
@jwt_required(optional=True)
def api_status():
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"lora": False, "mcu1": False, "mcu2": False, "auto_mode": False})

    delta = (datetime.utcnow() - config.last_updated).total_seconds()
    is_online = delta < 60  # Online if updated in last minute

    return jsonify({
        "lora": is_online,
        "mcu1": is_online,  # Assume same for now
        "mcu2": is_online,
        "auto_mode": config.auto_mode
    })

@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    current_user = get_jwt_identity()
    if current_user['role'] != 'owner':
        return jsonify({'ok': False, 'error': 'Owners only'}), 403

    log_entries = Log.query.order_by(Log.timestamp.desc()).limit(50).all()

    logs_list = [{
        "title": log.title,
        "message": log.message,
        "timestamp": log.timestamp.strftime("%Y-%m-%d %I:%M %p"),
        "type": log.log_type
    } for log in log_entries]

    return jsonify({
        "ok": True,
        "logs": logs_list
    })

@app.route('/api/update_profile', methods=['POST'])
@jwt_required()
def update_profile():
    current_user = get_jwt_identity()
    data = request.get_json()
    fullname = data.get('fullname')
    email = current_user['email']

    if not fullname:
        return jsonify({"ok": False, "error": "Full name required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    user.fullname = fullname
    db.session.commit()

    return jsonify({"ok": True, "message": "Profile updated", "fullname": fullname})

@app.route('/api/access-codes', methods=['GET'])
@jwt_required()
def get_access_codes():
    current_user = get_jwt_identity()
    if current_user['role'] != 'owner':
        return jsonify({'ok': False, 'error': 'Owners only'}), 403

    users = User.query.filter_by(role='owner').all()
    codes = [{'email': u.email, 'code': u.access_code} for u in users if u.access_code]
    return jsonify({'ok': True, 'codes': codes})

@app.route('/debug-env')
def debug_env():
    env_value = os.environ.get('DATABASE_URL', 'MISSING_ENV_VAR')
    uri_used = app.config.get('SQLALCHEMY_DATABASE_URI', 'NOT_SET')
    return jsonify({
        'env_DATABASE_URL': env_value[:60] + '...' if len(env_value) > 60 else env_value,
        'actual_uri_used': uri_used[:60] + '...' if len(uri_used) > 60 else uri_used,
        'is_postgres': 'postgresql' in uri_used if uri_used else False
    })

@app.route('/api/settings', methods=['GET', 'POST'])
@jwt_required()
def api_settings():
    current_user = get_jwt_identity()
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "message": "No configuration"}), 500

    if request.method == 'POST':
        if current_user['role'] != 'owner':
            return jsonify({'ok': False, 'error': 'Owners only'}), 403
        data = request.get_json()
        config.min_moisture = data.get('threshold_zoneA_min', config.min_moisture)
        config.max_moisture = data.get('threshold_zoneA_max', config.max_moisture)
        # Add Zone B if you expand model, else ignore or add fields
        config.auto_water_time = data.get('auto_water_time', config.auto_water_time)
        config.duration_minutes = data.get('duration', config.duration_minutes)
        config.max_temperature = data.get('max_temp', config.max_temperature)
        config.min_humidity = data.get('min_humidity', config.min_humidity)
        config.auto_mode = data.get('auto_mode', config.auto_mode)
        db.session.commit()
        return jsonify({"ok": True, "message": "Settings updated"})

    # GET
    return jsonify({
        "ok": True,
        "threshold_zoneA_min": config.min_moisture,
        "threshold_zoneA_max": config.max_moisture,
        "threshold_zoneB_min": 35,  # Hardcode or add to model
        "threshold_zoneB_max": 65,
        "auto_water_time": config.auto_water_time,
        "duration": config.duration_minutes,
        "max_temp": config.max_temperature,
        "min_humidity": config.min_humidity,
        "auto_mode": config.auto_mode,
        "solenoid_open": config.solenoid_open
    })

@app.route('/api/report')
@jwt_required()
def api_report():
    current_user = get_jwt_identity()
    if current_user['role'] != 'owner':
        return jsonify({'ok': False, 'error': 'Owners only'}), 403

    # Get last 30 days readings
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=30)
    readings = SensorReading.query.filter(SensorReading.timestamp >= cutoff).order_by(SensorReading.timestamp.desc()).all()

    output = io.StringIO()
    output.write("Timestamp,Moisture,Temperature,Humidity,Light\n")
    for r in readings:
        output.write(f"{r.timestamp},{r.moisture},{r.temperature},{r.humidity},{r.light}\n")

    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=farmlink_report.csv"})

# ─── REGISTRATION ─────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)
    
    if data is None:
        return jsonify({'ok': False, 'error': 'Invalid JSON payload'}), 400

    email       = data.get('email')
    fullname    = data.get('fullname')
    password    = data.get('password')
    role        = data.get('role', 'sakada')
    access_code = data.get('access_code')  # required only for owner

    # Basic field validation
    if not all([email, fullname, password]):
        missing = [k for k, v in {'email': email, 'fullname': fullname, 'password': password}.items() if not v]
        return jsonify({
            'ok': False,
            'error': f'Missing required fields: {", ".join(missing)}'
        }), 400

    # Validate role
    if role not in ['sakada', 'owner']:
        return jsonify({'ok': False, 'error': 'Invalid role. Must be "sakada" or "owner"'}), 400

    # Owner must provide access_code
    if role == 'owner' and not access_code:
        return jsonify({'ok': False, 'error': 'Access code is required for owner registration'}), 400

    # Check email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'ok': False, 'error': 'Email already registered'}), 409

    # Validate access code for owner
    if role == 'owner':
        owner_record = User.query.filter_by(access_code=access_code, role='owner').first()
        if not owner_record:
            return jsonify({'ok': False, 'error': 'Invalid or expired access code'}), 400
        
        # Optional: make code one-time use (uncomment if desired)
        # owner_record.access_code = None
        # db.session.commit()

    # Create the user
    hashed_pw = generate_password_hash(password)

    new_user = User(
        email=email,
        fullname=fullname,
        password_hash=hashed_pw,
        role=role,
        verified=False
    )

    # Generate and send access code ONLY if registering a NEW owner
    # (not when using an existing code to register)
    sent_access_code = None
    if role == 'owner':
        # Generate a new access code for this new owner account
        sent_access_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        new_user.access_code = sent_access_code
        
        # Send email
        success = send_access_code_email(email, sent_access_code)
        if not success:
            print(f"[WARNING] Failed to send access code email to {email}")

    try:
        db.session.add(new_user)
        db.session.commit()
        
        message = 'Registered successfully'
        if role == 'owner' and sent_access_code:
            message += ' — your new access code has been sent to your email'

        return jsonify({
            'ok': True,
            'message': message,
            'role': role
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"[REGISTER ERROR] Database commit failed: {str(e)}")
        return jsonify({'ok': False, 'error': 'Failed to create account. Please try again.'}), 500
    

@app.route('/api/resend-owner-code', methods=['POST'])
def resend_owner_code():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'ok': False, 'error': 'Email required'}), 400

    user = User.query.filter_by(email=email, role='owner').first()
    if not user:
        return jsonify({'ok': False, 'error': 'No owner account found with this email'}), 404

    if not user.access_code:
        return jsonify({'ok': False, 'error': 'No access code found for this account'}), 400

    success = send_access_code_email(
        recipient_email = email,
        access_code     = user.access_code
    )

    if success:
        return jsonify({
            'ok': True,
            'message': 'Access code re-sent to your email'
        }), 200
    else:
        return jsonify({
            'ok': False,
            'error': 'Failed to send access code email. Please try again later.'
        }), 500
    
# ─── LOGIN ────────────────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email     = data.get('email')
    password  = data.get('password')
    role      = data.get('role')
    admincode = data.get('admincode') if role == 'owner' else None

    if not email or not password or not role:
        return jsonify({'ok': False, 'error': 'Missing required fields'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'ok': False, 'error': 'Invalid email or password'}), 401

    if user.role != role:
        return jsonify({'ok': False, 'error': 'Role mismatch for this account'}), 403

    if role == 'owner':
        if not user.access_code or admincode != user.access_code:
            return jsonify({'ok': False, 'error': 'Invalid or missing access code'}), 403
        
        # Mark as verified on first successful owner login
        if not user.verified:
            user.verified = True
            db.session.commit()

        # ─── SEND EMAIL ON SUCCESSFUL OWNER LOGIN ────────────────────────
        success = send_access_code_email(
            recipient_email = email,
            access_code     = user.access_code
        )
        if success:
            print(f"[LOGIN EMAIL] Access code re-sent to owner: {email}")
        else:
            print(f"[LOGIN EMAIL] Failed to send to owner: {email}")

    token = create_access_token(identity={'email': user.email, 'role': user.role})

    return jsonify({
        'ok': True,
        'token': token,
        'fullname': user.fullname,
        'email': user.email,
        'role': user.role,
        'message': 'Login successful' + (' — access code re-sent to email' if role == 'owner' else '')
    }), 200