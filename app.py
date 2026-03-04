import threading
import json
import time
import random
import string
import os
import io
import csv
import secrets
from flask import Flask, jsonify, request, Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask import send_from_directory
from flask import send_file, make_response
from io import StringIO
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

load_dotenv()  # Loads .env automatically

print(f"[START] PORT from env: {os.environ.get('PORT', 'NOT SET')}")
print(f"[START] Binding to 0.0.0.0:{os.environ.get('PORT', '10000')}")

SERIAL_RECONNECT_REQUEST = False

# ─── CONFIG ───────────────────────────────────────────────────────────────
SERIAL_ENABLED = os.environ.get("SERIAL_ENABLED", "false").lower() in ("true", "1", "yes", "t")
SERIAL_PORT    = os.environ.get("SERIAL_PORT", "COM9")
BAUD_RATE      = int(os.environ.get("BAUD_RATE", "115200"))
SERIAL_TIMEOUT_SEC = 1.0

print("[APP START] File loaded - no crash on import")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    base_dir = '/www'
    if path != "" and os.path.exists(os.path.join(base_dir, path)):
        return send_from_directory(base_dir, path)

    return send_from_directory(base_dir, 'login.html')  # For production on Render

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "port": os.environ.get('PORT')}), 200

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
    'pool_pre_ping': True,
    'pool_size': 5,
    'max_overflow': 10
}

SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_timeout": 20
}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ─── FLASK-MAIL CONFIG ────────────────────────────────────────────────────
app.config['MAIL_SERVER']       = 'smtp.gmail.com'
app.config['MAIL_PORT']         = 587
app.config['MAIL_USE_TLS']      = True
app.config['MAIL_USERNAME']     = 'farmlinktech.ph@gmail.com'
app.config['MAIL_PASSWORD']     = 'qhfbxiirttjzkrzd'
app.config['MAIL_DEFAULT_SENDER'] = 'farmlinktech.ph@gmail.com'
app.config['MAIL_DEBUG']        = True

mail = Mail(app)

# ─── JWT CONFIG ───────────────────────────────────────────────────────────
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', '4vD5vmuI36XehMOVd9fRqkqeZerwo4HAobPwSt1E-ygHP2H1EOfbxtRwW_ihjVpx')

app.config['JWT_ACCESS_TOKEN_EXPIRES']     = 86400         
app.config['JWT_REFRESH_TOKEN_EXPIRES']    = 7 * 24 * 60 * 60

jwt = JWTManager(app)

# JWT error callbacks
@jwt.invalid_token_loader
def invalid_token_callback(error):
    print("[JWT] Invalid token error:", error)
    return jsonify({'ok': False, 'error': 'Invalid token - please log in again'}), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
    print("[JWT] Unauthorized:", error)
    return jsonify({'ok': False, 'error': 'Missing or invalid Authorization header'}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print("[JWT] Token expired:", jwt_payload)
    return jsonify({'ok': False, 'error': 'Token expired - please log in again'}), 401

# ─── MODELS ───────────────────────────────────────────────────────────────

class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    fullname      = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), default="sakada")
    verified      = db.Column(db.Boolean, default=False)
    access_code   = db.Column(db.String(30))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    avatar_base64 = db.Column(db.Text, nullable=True)

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

# ─── PASSWORD RESET MODEL ── MUST BE HERE BEFORE ANY ROUTE USES IT ────────
class PasswordResetToken(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(120), nullable=False, index=True)
    token      = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_valid(self):
        return datetime.utcnow() < self.expires_at

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
    last_solenoid_open_at      = db.Column(db.DateTime, nullable=True)
    last_solenoid_duration_sec = db.Column(db.Integer, nullable=True)

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
    triggered_by      = db.Column(db.String(20), default="auto")
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
    try:
        print(f"[EMAIL] Sending to {recipient_email}")
        msg = Message(
            subject="Your FarmLink Access Code",
            sender=('FarmLink', 'farmlinktech.ph@gmail.com'),
            recipients=[recipient_email],
            body=f"""
Dear user,

Your access code is: {access_code}

Use this when logging in as Owner.
Keep it secure — do not share.

Best regards,
FarmLink Team
            """.strip()
        )
        mail.send(msg)
        print(f"[EMAIL SUCCESS via Gmail] Sent to {recipient_email}")
        return True
    except Exception as e:
        print("[EMAIL FAILURE via Gmail]")
        import traceback
        print(traceback.format_exc())
        return False

# ─── SERIAL WORKER ────────────────────────────────────────────────────────

def serial_worker():
    global SERIAL_RECONNECT_REQUEST

    if not SERIAL_ENABLED:
        print("[SERIAL] SERIAL_ENABLED = False → serial worker disabled")
        return

    try:
        import serial
    except ImportError:
        print("[SERIAL] pyserial not installed → skipping serial worker")
        return

    print(f"[SERIAL] Starting worker thread - attempting {SERIAL_PORT} @ {BAUD_RATE} baud")

    ser = None

    while True:
        try:
            if ser is None or not ser.is_open or SERIAL_RECONNECT_REQUEST:
                print(" Reconnecting to Serial/LoRa...")
                SERIAL_RECONNECT_REQUEST = False

                if ser and ser.is_open:
                    try:
                        ser.close()
                    except:
                        pass

                ser = serial.Serial(
                    port=SERIAL_PORT,
                    baudrate=BAUD_RATE,
                    timeout=SERIAL_TIMEOUT_SEC,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE
                )
                print(f"[SERIAL] Opened {ser.name}")
                time.sleep(2.5)  
                ser.reset_input_buffer()
                ser.reset_output_buffer()

            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if not line:
                    continue

                print(f"[SERIAL RX] {line}")

                data = {}
                updated = False

                if line.startswith('{') and line.endswith('}'):
                    try:
                        data = json.loads(line)
                        updated = True
                    except json.JSONDecodeError as je:
                        print(f"[SERIAL JSON ERROR] {je} → raw: {line}")

                else:
                    try:
                        for part in line.split():
                            if ':' in part:
                                k, v = part.split(':', 1)
                                data[k.strip().lower()] = v.strip()
                        if len(data) >= 2:
                            updated = True
                    except Exception as pe:
                        print(f"[SERIAL PLAIN PARSE FAIL] {pe} → raw: {line}")

                if updated and any(k in data for k in ['moisture', 'temperature', 'humidity', 'light']):
                    with app.app_context():
                        config = PalayanConfig.query.first()
                        if not config:
                            print("[SERIAL] No PalayanConfig row found!")
                            continue

                        # Update sensor values
                        config.current_moisture    = float(data.get('moisture',    config.current_moisture))
                        config.current_temperature = float(data.get('temperature', config.current_temperature))
                        config.current_humidity    = float(data.get('humidity',    config.current_humidity))
                        config.current_light       = float(data.get('light',       config.current_light))

                        # Handle solenoid state reported from device
                        solenoid_new = data.get('solenoid_open') or data.get('solenoid')
                        if solenoid_new is not None:
                            new_state = solenoid_new in [1, '1', True, 'true', 'on', 'OPEN']
                            if new_state != config.solenoid_open:
                                if new_state:
                                    config.last_solenoid_open_at = datetime.utcnow()
                                    config.last_solenoid_duration_sec = None
                                    add_log("Solenoid Opened", "Reported by device", "irrigation")
                                else:
                                    if config.last_solenoid_open_at:
                                        duration = (datetime.utcnow() - config.last_solenoid_open_at).total_seconds()
                                        config.last_solenoid_duration_sec = int(duration)
                                        add_log("Solenoid Closed", f"Was open for {duration//60:.0f} min {duration%60:.0f} sec", "irrigation")
                            config.solenoid_open = new_state

                        config.last_updated = datetime.utcnow()

                        # Auto watering logic (runs every time we get new data)
                        if config.auto_mode:
                            if config.current_moisture < config.min_moisture and not config.solenoid_open:
                                config.solenoid_open = True
                                config.last_solenoid_open_at = datetime.utcnow()
                                add_log("Auto Watering", "Soil dry → solenoid opened", "irrigation")
                                try:
                                    ser.write(b'OPEN\n')
                                    print("[SERIAL TX] OPEN")
                                except:
                                    print("[SERIAL TX] Failed to send OPEN command")
                            elif config.current_moisture > config.max_moisture and config.solenoid_open:
                                if config.last_solenoid_open_at:
                                    duration = (datetime.utcnow() - config.last_solenoid_open_at).total_seconds()
                                    config.last_solenoid_duration_sec = int(duration)
                                    add_log("Auto Watering", f"Soil wet → solenoid closed after {duration//60:.0f} min", "irrigation")
                                config.solenoid_open = False
                                try:
                                    ser.write(b'CLOSE\n')
                                    print("[SERIAL TX] CLOSE")
                                except:
                                    print("[SERIAL TX] Failed to send CLOSE command")

                        # Save reading history
                        reading = SensorReading(
                            moisture    = config.current_moisture,
                            temperature = config.current_temperature,
                            humidity    = config.current_humidity,
                            light       = config.current_light,
                            timestamp   = datetime.utcnow()
                        )
                        db.session.add(reading)

                        try:
                            db.session.commit()
                        except Exception as dbe:
                            print(f"[DB UPDATE ERROR] {dbe}")
                            db.session.rollback()

            time.sleep(0.08)

        except Exception as e:
            print(f"[SERIAL ERROR] {e}")
            if ser and ser.is_open:
                try:
                    ser.close()
                except:
                    pass
            ser = None
            time.sleep(5)

# Start serial thread
if SERIAL_ENABLED:
    print("[MAIN] Starting Serial thread...")
    threading.Thread(target=serial_worker, daemon=True, name="SerialReader").start()

    # ─── Force table creation with logging ─────────────────────────────────────
with app.app_context():
    try:
        db.create_all()
        print("[DB STARTUP] Successfully ran db.create_all() → tables should now exist")
        
        # Quick check if PasswordResetToken table exists
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        if 'password_reset_token' in tables:
            print("[DB STARTUP] Confirmed: password_reset_token table exists")
        else:
            print("[DB STARTUP] WARNING: password_reset_token table STILL MISSING after create_all!")
            
    except Exception as db_err:
        print("[DB STARTUP CRASH] Failed to create tables!")
        import traceback
        print(traceback.format_exc())

# ─── KEEP-ALIVE THREAD ────────────────────────────────────────────────────
def keep_alive():
    while True:
        print("[KEEP ALIVE] Server still running - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        time.sleep(60)

threading.Thread(target=keep_alive, daemon=True).start()

# ─── STARTUP ──────────────────────────────────────────────────────────────
print("[APP START] Entering startup block")
try:
    with app.app_context():
        print("[STARTUP] Creating tables...")
        db.create_all()
        print("[STARTUP] Tables created or already exist")

        # Ensure default config exists
        if not PalayanConfig.query.first():
            default = PalayanConfig()
            db.session.add(default)
            db.session.commit()
            print("[STARTUP] Created default PalayanConfig")

        # Seed initial owner if none exists
        if not User.query.filter_by(role='owner').first():
            print("[STARTUP] No owner account found → creating default owner")
            owner_email    = os.environ.get('DEFAULT_OWNER_EMAIL',    'owner@farmlink.ph')
            owner_fullname = os.environ.get('DEFAULT_OWNER_NAME',     'Initial Farm Owner')
            owner_password = os.environ.get('DEFAULT_OWNER_PASSWORD', 'BennyLantacon')
            owner_code     = os.environ.get('DEFAULT_OWNER_CODE',     'FRMLNK-INIT-413')

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
            print("[STARTUP] Default owner created successfully")

except Exception as startup_err:
    print("[STARTUP CRASH] Failed during startup")
    print("[STARTUP CRASH] Error:", str(startup_err))
    import traceback
    print("[STARTUP CRASH] Full traceback:")
    print(traceback.format_exc())

# ─── API ROUTES ───────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"ok": False, "error": "Missing JSON payload"}), 400

        email = data.get("email", "").strip().lower()
        password = data.get("password", "").strip()
        role = data.get("role", "sakada")
        access_code = data.get("access_code", "").strip() 

        if not email or not password:
            return jsonify({"ok": False, "error": "Email and password required"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"ok": False, "error": "Account not found"}), 404

        # Password check
        if not check_password_hash(user.password_hash, password):
            return jsonify({"ok": False, "error": "Incorrect password"}), 401

        # Owner-specific check
        if user.role == "owner":
            if not access_code:
                return jsonify({"ok": False, "error": "Access code required for owner login"}), 401
            if user.access_code != access_code:
                return jsonify({"ok": False, "error": "Invalid access code"}), 401

        # Success – generate tokens
        access = create_access_token(identity=user.email)
        refresh = create_refresh_token(identity=user.email)

        add_log(
            "User Login",
            f"{user.email} logged in successfully",
            "auth",
            user_email=user.email
        )

        return jsonify({
            "ok": True,
            "message": "Login successful",
            "token": access,
            "refresh_token": refresh,
            "user": {
                "email": user.email,
                "fullname": user.fullname,
                "role": user.role,
                "avatar": user.avatar_base64
            }
        }), 200

    except Exception as e:
        print("[LOGIN ERROR]", e)
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": "Server error during login"}), 500

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

@app.route('/api/history', methods=['GET'])
@jwt_required()
def get_sensor_history():
    sensor = request.args.get('sensor', 'moisture').lower()
    time_range = request.args.get('range', '7days')

    now = datetime.utcnow()
    if time_range == 'today':
        start_time = now - timedelta(hours=24)
    elif time_range == '30days':
        start_time = now - timedelta(days=30)
    else:  # default 7days
        start_time = now - timedelta(days=7)

    valid_sensors = ['moisture', 'temperature', 'humidity', 'light']
    if sensor not in valid_sensors:
        return jsonify({'ok': False, 'error': 'Invalid sensor'}), 400

    readings = SensorReading.query.filter(
        SensorReading.timestamp >= start_time
    ).order_by(SensorReading.timestamp.asc()).limit(20000).all()

    data = [{
        'timestamp': r.timestamp.isoformat(),
        'value': getattr(r, sensor)
    } for r in readings if getattr(r, sensor) is not None]

    return jsonify({
        'ok': True,
        'sensor': sensor,
        'range': time_range,
        'data': data,
        'count': len(data)
    })

@app.route('/api/ingest', methods=['POST'])
def ingest_sensor_data():
    """
    Endpoint for devices (LoRa gateway, MCU, etc.) to push current sensor readings.
    Handles updates, solenoid state changes, auto-logging, alerts, and history.
    """
    data = request.get_json()
    if not data:
        return jsonify({"ok": False, "error": "No JSON payload received"}), 400

    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "error": "No configuration found in database"}), 500

    now = datetime.utcnow()

    # ─── Extract and safely convert values ─────────────────────────────────────
    moisture    = data.get('moisture')
    temperature = data.get('temperature')
    humidity    = data.get('humidity')
    light       = data.get('light')
    solenoid_new = data.get('solenoid_open') or data.get('solenoid')  

    try:
        if moisture    is not None: moisture    = float(moisture)
        if temperature is not None: temperature = float(temperature)
        if humidity    is not None: humidity    = float(humidity)
        if light       is not None: light       = float(light)
        if solenoid_new is not None:
            solenoid_new = solenoid_new in [1, '1', True, 'true', 'on', 'OPEN', 'open']
    except (ValueError, TypeError):
        pass  

    # ─── Remember previous solenoid state for change detection ─────────────────
    was_open = config.solenoid_open

    # ─── Update current sensor values (only if new valid data sent) ────────────
    if moisture    is not None: config.current_moisture    = moisture
    if temperature is not None: config.current_temperature = temperature
    if humidity    is not None: config.current_humidity    = humidity
    if light       is not None: config.current_light       = light

    # ─── Handle solenoid state change + duration tracking ──────────────────────
    if solenoid_new is not None:
        new_state = bool(solenoid_new)

        if new_state != was_open:
            if new_state:
                # Opened
                config.last_solenoid_open_at = now
                config.last_solenoid_duration_sec = None
                add_log(
                    title="Solenoid Opened",
                    message="Water pump / solenoid turned ON (reported by device)",
                    log_type="irrigation"
                )
            else:
                # Closed
                if config.last_solenoid_open_at:
                    duration_sec = (now - config.last_solenoid_open_at).total_seconds()
                    config.last_solenoid_duration_sec = int(duration_sec)
                    min_part = int(duration_sec // 60)
                    sec_part = int(duration_sec % 60)
                    add_log(
                        title="Solenoid Closed",
                        message=f"Water pump was open for {min_part} min {sec_part} sec",
                        log_type="irrigation"
                    )

        config.solenoid_open = new_state

    # ─── Update last seen timestamp ────────────────────────────────────────────
    config.last_updated = now

    # ─── Generate alerts for technical issues ──────────────────────────────────
    alerts_created = 0

    # 1. Device offline / no recent data
    if config.last_updated:  
        offline_seconds = (now - config.last_updated).total_seconds()
        if offline_seconds > 180:  
            alert = Alert(
                title="LoRa/MCU Offline",
                message=f"No data received for ~{offline_seconds//60} minutes – possible disconnect",
                alert_type="connection",
                severity=8
            )
            db.session.add(alert)
            alerts_created += 1

    # 2. Invalid moisture reading
    if moisture is not None and (moisture < 0 or moisture > 100):
        alert = Alert(
            title="Invalid Moisture Reading",
            message=f"Received moisture = {moisture}% (valid range: 0–100)",
            alert_type="sensor",
            severity=6
        )
        db.session.add(alert)
        alerts_created += 1

    # You can add similar checks for temperature, humidity, light here if desired

    # ─── Save to history table ─────────────────────────────────────────────────
    reading = SensorReading(
        moisture    = config.current_moisture,
        temperature = config.current_temperature,
        humidity    = config.current_humidity,
        light       = config.current_light,
        timestamp   = now
    )
    db.session.add(reading)

    # ─── Commit everything ─────────────────────────────────────────────────────
    try:
        db.session.commit()

        response_data = {
            "ok": True,
            "message": "Data ingested successfully",
            "alerts_created": alerts_created,
            "current": {
                "moisture": round(config.current_moisture, 1) if config.current_moisture else None,
                "temperature": round(config.current_temperature, 1) if config.current_temperature else None,
                "humidity": round(config.current_humidity, 1) if config.current_humidity else None,
                "light": round(config.current_light, 0) if config.current_light else None,
                "solenoid_open": config.solenoid_open,
                "last_updated": config.last_updated.isoformat()
            }
        }

        if config.last_solenoid_open_at:
            response_data["current"]["last_solenoid_open"] = config.last_solenoid_open_at.isoformat()

        if config.last_solenoid_duration_sec is not None:
            response_data["current"]["last_duration_sec"] = config.last_solenoid_duration_sec

        return jsonify(response_data), 200

    except Exception as e:
        db.session.rollback()
        print(f"[INGEST COMMIT ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": "Database error during ingest"}), 500

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify({'ok': True, 'token': access_token}), 200

@app.route("/api/alerts")
@jwt_required(optional=True)
def api_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([a.to_dict() for a in alerts])

@app.route('/api/alerts/clear', methods=['POST'])
@jwt_required()
def clear_alerts():
    current_user = User.query.filter_by(email=get_jwt_identity()).first()
    if not current_user or current_user.role != 'owner':
        return jsonify({'ok': False, 'error': 'Owners only'}), 403

    Alert.query.delete()
    db.session.commit()
    return jsonify({'ok': True, 'message': 'All alerts cleared'})

@app.route('/api/start-auto', methods=['POST'])
@jwt_required()
def start_auto():
    current_email = get_jwt_identity()
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({'ok': False, 'error': 'No configuration found'}), 500

    config.auto_mode = True
    try:
        db.session.commit()
        add_log(
            title="Auto Watering Started",
            message="Owner manually activated auto mode",
            log_type="irrigation",
            user_email=current_email
        )
        return jsonify({'ok': True, 'message': 'Auto watering mode activated'})
    except:
        db.session.rollback()
        return jsonify({'ok': False, 'error': 'Failed to activate'}), 500

@app.route("/api/status")
@jwt_required(optional=True)
def api_status():
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"lora": False, "mcu1": False, "mcu2": False, "auto_mode": False})

    now_utc = datetime.now(timezone.utc)
    last_updated = config.last_updated

    if last_updated.tzinfo is None:
        last_updated = last_updated.replace(tzinfo=timezone.utc)

    delta = (now_utc - last_updated).total_seconds()
    is_online = delta < 60

    return jsonify({
        "lora": is_online,
        "mcu1": is_online,
        "mcu2": is_online,
        "auto_mode": config.auto_mode
    })

@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()
    if not current_user:
        return jsonify({'ok': False, 'error': 'User not found'}), 404
    if current_user.role != 'owner':
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

@app.route('/api/settings', methods=['GET', 'POST'])
@jwt_required()
def api_settings():
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()
    if not current_user:
        return jsonify({'ok': False, 'error': 'User not found'}), 404

    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "error": "No configuration found"}), 500

    if request.method == 'POST':
        if current_user.role != 'owner':
            return jsonify({'ok': False, 'error': 'Only owners can edit settings'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'ok': False, 'error': 'Invalid JSON payload'}), 400

        # Log before saving
        changes = []
        if 'threshold_zoneA_min' in data and data['threshold_zoneA_min'] != config.min_moisture:
            changes.append(f"min_moisture → {data['threshold_zoneA_min']}")
        if 'threshold_zoneA_max' in data and data['threshold_zoneA_max'] != config.max_moisture:
            changes.append(f"max_moisture → {data['threshold_zoneA_max']}")
        if 'auto_water_time' in data and data['auto_water_time'] != config.auto_water_time:
            changes.append(f"auto_water_time → {data['auto_water_time']}")
        if 'duration' in data and data['duration'] != config.duration_minutes:
            changes.append(f"duration → {data['duration']} min")
        if 'max_temp' in data and data['max_temp'] != config.max_temperature:
            changes.append(f"max_temp → {data['max_temp']}°C")
        if 'min_humidity' in data and data['min_humidity'] != config.min_humidity:
            changes.append(f"min_humidity → {data['min_humidity']}%")

        config.min_moisture     = data.get('threshold_zoneA_min', config.min_moisture)
        config.max_moisture     = data.get('threshold_zoneA_max', config.max_moisture)
        config.auto_water_time  = data.get('auto_water_time',     config.auto_water_time)
        config.duration_minutes = data.get('duration',            config.duration_minutes)
        config.max_temperature  = data.get('max_temp',            config.max_temperature)
        config.min_humidity     = data.get('min_humidity',        config.min_humidity)

        try:
            db.session.commit()
            if changes:
                add_log(
                    title="Settings Updated",
                    message=f"Owner changed: {', '.join(changes)}",
                    log_type="settings",
                    user_email=current_email
                )
            else:
                add_log(
                    title="Settings Viewed",
                    message="Owner viewed settings (no changes)",
                    log_type="info",
                    user_email=current_email
                )
            return jsonify({"ok": True, "message": "Settings saved"})
        except Exception as e:
            db.session.rollback()
            print(f"[SETTINGS SAVE ERROR] {e}")
            return jsonify({"ok": False, "error": "Failed to save settings"}), 500

    # GET
    return jsonify({
        "ok": True,
        "threshold_zoneA_min": config.min_moisture,
        "threshold_zoneA_max": config.max_moisture,
        "auto_water_time": config.auto_water_time,
        "duration": config.duration_minutes,
        "max_temp": config.max_temperature,
        "min_humidity": config.min_humidity,
        "auto_mode": config.auto_mode,
        "solenoid_open": config.solenoid_open,
        "read_only": current_user.role != 'owner'
    })

@app.route('/api/reconnect-lora', methods=['POST'])
@jwt_required()
def reconnect_lora():
    current_email = get_jwt_identity()
    global SERIAL_RECONNECT_REQUEST
    SERIAL_RECONNECT_REQUEST = True

    add_log(
        title="LoRa Reconnect Requested",
        message="Owner triggered LoRa reconnect",
        log_type="connection",
        user_email=current_email
    )

    return jsonify({'ok': True, 'message': 'Reconnect requested'})

@app.route('/api/water', methods=['POST'])
@jwt_required()
def manual_water():
    data = request.get_json() or {}
    duration = data.get('duration', 10)  # minutes

    add_log("Manual Watering", f"Started for {duration} minutes by user", "irrigation")

    # Optional: send command if serial is active
    # In real implementation you might want a queue or direct write here

    return jsonify({
        'ok': True,
        'message': f'Watering started for {duration} minutes'
    })

# ─── Remote Valve Control ─────────────────────────────────────────────────
pending_command = None  # Global queue for next command

@app.route('/api/control', methods=['POST'])
@jwt_required()
def control_valve():
    global pending_command
    data = request.get_json()
    action = data.get('action')

    if not action:
        return jsonify({"ok": False, "error": "Missing 'action' field"}), 400

    action = action.lower()
    if action not in ['open', 'close']:
        return jsonify({"ok": False, "error": "Action must be 'open' or 'close'"}), 400

    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    # Log who requested it (both roles allowed)
    add_log(
        title="Manual Valve Command",
        message=f"Valve {action.upper()} requested by {current_email} ({user.role})",
        log_type="irrigation",
        user_email=current_email
    )

    pending_command = "OPEN" if action == "open" else "CLOSE"

    return jsonify({
        "ok": True,
        "message": f"Valve {action.upper()} command queued"
    }), 200


@app.route('/api/get-command', methods=['GET'])
def get_pending_command():
    global pending_command
    if pending_command:
        cmd = pending_command
        pending_command = None  # Consume the command
        return jsonify({"command": cmd})
    return jsonify({"command": None})

# ─── AUTH ─────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'ok': False, 'error': 'Invalid JSON payload'}), 400

    email       = data.get('email')
    fullname    = data.get('fullname')
    password    = data.get('password')
    role        = data.get('role', 'sakada')
    access_code = data.get('access_code')

    if not all([email, fullname, password]):
        return jsonify({'ok': False, 'error': 'Missing required fields'}), 400

    if role not in ['sakada', 'owner']:
        return jsonify({'ok': False, 'error': 'Invalid role'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'ok': False, 'error': 'Email already registered'}), 409

    hashed_pw = generate_password_hash(password)

    new_user = User(
        email=email,
        fullname=fullname,
        password_hash=hashed_pw,
        role=role,
        verified=False
    )

    sent_access_code = None
    if role == 'owner':
        sent_access_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        new_user.access_code = sent_access_code
        send_access_code_email(email, sent_access_code)

    try:
        db.session.add(new_user)
        db.session.commit()
        message = 'Registered successfully'
        if role == 'owner' and sent_access_code:
            message += ' — access code sent to email'
        return jsonify({'ok': True, 'message': message, 'role': role}), 201
    except:
        db.session.rollback()
        return jsonify({'ok': False, 'error': 'Failed to create account'}), 500

@app.route('/api/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    return jsonify({
        "ok": True,
        "email": user.email,
        "fullname": user.fullname,
        "role": user.role,
        "avatar": user.avatar_base64
    })

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()

        if not email:
            return jsonify({"ok": False, "error": "Email required"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"ok": True, "message": "If the email exists, a reset link has been sent."}), 200

        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=2)

        reset = PasswordResetToken(
            email=email,
            token=token,
            expires_at=expires
        )
        db.session.add(reset)
        db.session.commit()

        reset_url = f"https://farmlink-backend-rx5g.onrender.com/reset-password.html?token={token}&email={email}"

        msg = Message(
            subject="FarmLink Password Reset",
            sender=('FarmLink', 'farmlinktech.ph@gmail.com'),
            recipients=[email],
            body=f"Reset link: {reset_url}\n\nExpires in 2 hours."
        )
        mail.send(msg)

        return jsonify({"ok": True, "message": "Reset link sent — check inbox"}), 200

    except Exception as e:
        db.session.rollback()
        import traceback
        error_trace = traceback.format_exc()
        print("[FORGOT-PASSWORD CRASH]", error_trace)   # ← this will appear in Render logs!
        return jsonify({
            "ok": False,
            "error": "Internal server error – check logs",
            "details": str(e)   # optional – remove in production
        }), 500


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    email = data.get('email', '').strip().lower()
    new_password = data.get('new_password')

    if not all([token, email, new_password]):
        return jsonify({"ok": False, "error": "Missing required fields"}), 400

    if len(new_password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters"}), 400

    reset_token = PasswordResetToken.query.filter_by(token=token, email=email).first()
    if not reset_token:
        return jsonify({"ok": False, "error": "Invalid or expired reset token"}), 400

    if not reset_token.is_valid():
        db.session.delete(reset_token)
        db.session.commit()
        return jsonify({"ok": False, "error": "This reset link has expired"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"ok": False, "error": "Account not found"}), 404

    user.password_hash = generate_password_hash(new_password)

    # Clean up used token
    db.session.delete(reset_token)
    db.session.commit()

    add_log(
        title="Password Reset Successful",
        message=f"User {email} reset their password",
        log_type="auth",
        user_email=email
    )

    return jsonify({"ok": True, "message": "Password has been reset successfully. Please log in."}), 200

@app.route('/api/update_avatar', methods=['POST'])  # ← MUST have methods=['POST']
@jwt_required()
def update_avatar():
    print("[DEBUG] UPDATE_AVATAR ROUTE REACHED! Method:", request.method)
    print("[DEBUG] Headers:", dict(request.headers))
    print("[DEBUG] JSON body:", request.get_json(silent=True))

    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    data = request.get_json(silent=True)
    if not data or 'avatar' not in data:
        return jsonify({"ok": False, "error": "Missing 'avatar' field (base64 data URL expected)"}), 400

    avatar_base64 = data['avatar']

    # Basic validation
    if not isinstance(avatar_base64, str) or not avatar_base64.startswith('data:image/'):
        return jsonify({"ok": False, "error": "Invalid image format - must be data:image/...;base64,..."}), 400

    # Size limit (~1.2 MB base64 → ~900 KB binary)
    if len(avatar_base64) > 1_200_000:
        return jsonify({"ok": False, "error": "Image too large (max ~900KB after base64)"}), 400

    try:
        user.avatar_base64 = avatar_base64
        db.session.commit()

        add_log(
            title="Avatar Updated",
            message=f"User {user.email} updated their profile picture",
            log_type="profile",
            user_email=user.email
        )

        return jsonify({
            "ok": True,
            "message": "Avatar updated successfully",
            "avatar": user.avatar_base64
        }), 200

    except Exception as e:
        db.session.rollback()
        print("[UPDATE_AVATAR ERROR]", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": "Failed to save avatar"}), 500

@app.route('/api/update_profile', methods=['POST'])
@jwt_required()
def update_profile():
    print("[DEBUG] UPDATE_PROFILE ROUTE REACHED! Method:", request.method)  # ← For debugging
    print("[DEBUG] Headers:", dict(request.headers))
    print("[DEBUG] JSON:", request.get_json(silent=True))

    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()

    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    data = request.get_json(silent=True)
    if not data or 'fullname' not in data:
        return jsonify({"ok": False, "error": "Missing 'fullname' field"}), 400

    new_fullname = data['fullname'].strip()
    if not new_fullname or len(new_fullname) < 2:
        return jsonify({"ok": False, "error": "Full name too short or empty"}), 400

    try:
        old_fullname = user.fullname
        user.fullname = new_fullname
        db.session.commit()

        # Log the change
        add_log(
            title="Profile Updated",
            message=f"User {user.email} changed fullname from '{old_fullname}' to '{new_fullname}'",
            log_type="profile",
            user_email=user.email
        )

        return jsonify({
            "ok": True,
            "message": "Profile updated successfully",
            "fullname": new_fullname
        }), 200

    except Exception as e:
        db.session.rollback()
        print("[UPDATE_PROFILE ERROR]", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": "Failed to update profile"}), 500
    
@app.route('/api/report', methods=['GET'])
@jwt_required()
def api_report():
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()

    if not current_user or current_user.role != 'owner':
        return jsonify({'ok': False, 'error': 'Owners only'}), 403

    # Read parameters
    mode   = request.args.get('mode', 'full')           # full, daily, today
    fmt    = request.args.get('format', 'csv').lower()  # csv or pdf
    days   = request.args.get('days', default=30, type=int)
    date_str = request.args.get('date')                  # YYYY-MM-DD for specific day

    end_date = datetime.utcnow()
    if date_str:
        try:
            start_date = datetime.strptime(date_str, '%Y-%m-%d')
            end_date = start_date + timedelta(days=1)
        except ValueError:
            return jsonify({'ok': False, 'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    else:
        start_date = end_date - timedelta(days=days)

    # Fetch data
    readings = SensorReading.query.filter(
        SensorReading.timestamp >= start_date,
        SensorReading.timestamp <= end_date
    ).order_by(SensorReading.timestamp.asc()).all()

    events = IrrigationEvent.query.filter(
        IrrigationEvent.start_time >= start_date,
        IrrigationEvent.start_time <= end_date
    ).order_by(IrrigationEvent.start_time.asc()).all()

    alerts = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).order_by(Alert.timestamp.asc()).all()

    # ─── PDF with Chart ────────────────────────────────────────────────
    if fmt == 'pdf':
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from io import BytesIO

            buffer = BytesIO()
            
            # Turn off compression → fixes many "corrupted" viewer issues
            from reportlab import rl_config
            rl_config.pageCompression = 0

            p = canvas.Canvas(buffer, pagesize=letter)
            width, height = letter

            # Header - make it obvious
            p.setFont("Helvetica-Bold", 20)
            p.drawString(100, height - 80, "FarmLink Sensor Report (Test)")
            p.setFont("Helvetica", 14)
            p.drawString(100, height - 120, f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
            p.drawString(100, height - 150, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
            p.drawString(100, height - 180, f"Readings count: {len(readings)}")

            # Add some dummy content to ensure structure
            p.setFont("Helvetica", 12)
            y = height - 220
            p.drawString(100, y, "This is a test line to confirm PDF rendering.")
            y -= 30
            p.drawString(100, y, "If you see this, basic PDF generation works.")
            y -= 60

            if readings:
                last = readings[-1]
                p.drawString(100, y, f"Latest moisture: {last.moisture or 'N/A'}%")
                y -= 25
                p.drawString(100, y, f"Latest temperature: {last.temperature or 'N/A'}°C")
            else:
                p.drawString(100, y, "No sensor readings in this period.")

            p.showPage()
            p.save()

            buffer.seek(0)
            pdf_bytes = buffer.getvalue()
            
            # Debug: log size (check Render logs after you download!)
            print(f"[PDF DEBUG] Generated size: {len(pdf_bytes)} bytes | First 10 bytes: {pdf_bytes[:10]}")

            response = make_response(pdf_bytes)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename="farmlink_test_report_{datetime.utcnow().strftime("%Y%m%d")}.pdf"'
            response.headers['Content-Length'] = str(len(pdf_bytes))
            return response

        except Exception as pdf_err:
            import traceback
            print("[PDF GENERATION ERROR]", str(pdf_err))
            traceback.print_exc()
            return jsonify({"ok": False, "error": f"PDF generation failed: {str(pdf_err)}"}), 500

    else:
        # ─── CSV Generation ────────────────────────────────────────
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(['FarmLink Report'])
        writer.writerow(['Period', start_date.strftime('%Y-%m-%d'), 'to', end_date.strftime('%Y-%m-%d')])
        writer.writerow(['Generated', datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')])
        writer.writerow([])

        if mode == 'daily':
            from collections import defaultdict
            daily_data = defaultdict(lambda: {'moist': [], 'temp': [], 'hum': [], 'light': [], 'water_min': 0})

            for r in readings:
                day = r.timestamp.date()
                if r.moisture is not None: daily_data[day]['moist'].append(r.moisture)
                if r.temperature is not None: daily_data[day]['temp'].append(r.temperature)
                if r.humidity is not None: daily_data[day]['hum'].append(r.humidity)
                if r.light is not None: daily_data[day]['light'].append(r.light)

            for e in events:
                day = e.start_time.date()
                daily_data[day]['water_min'] += e.duration_minutes

            writer.writerow(['Daily Summary'])
            writer.writerow(['Date', 'Avg Moisture (%)', 'Avg Temp (°C)', 'Avg Humidity (%)', 'Avg Light', 'Total Water (min)'])

            for day in sorted(daily_data.keys()):
                d = daily_data[day]
                moist = round(sum(d['moist'])/len(d['moist']), 1) if d['moist'] else '-'
                temp  = round(sum(d['temp'])/len(d['temp']), 1) if d['temp'] else '-'
                hum   = round(sum(d['hum'])/len(d['hum']), 1) if d['hum'] else '-'
                light = round(sum(d['light'])/len(d['light']), 0) if d['light'] else '-'
                writer.writerow([day, moist, temp, hum, light, d['water_min']])

        else:
            # Full detailed
            writer.writerow(['Detailed Sensor Readings'])
            writer.writerow(['Timestamp', 'Moisture (%)', 'Temperature (°C)', 'Humidity (%)', 'Light'])
            for r in readings:
                writer.writerow([
                    r.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    r.moisture if r.moisture is not None else '',
                    r.temperature if r.temperature is not None else '',
                    r.humidity if r.humidity is not None else '',
                    r.light if r.light is not None else ''
                ])

            writer.writerow([])
            writer.writerow(['Irrigation Events'])
            writer.writerow(['Start Time', 'Duration (min)', 'Triggered By'])
            for e in events:
                writer.writerow([
                    e.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    e.duration_minutes,
                    e.triggered_by
                ])

            writer.writerow([])
            writer.writerow(['Alerts'])
            writer.writerow(['Timestamp', 'Title', 'Message', 'Severity'])
            for a in alerts:
                writer.writerow([
                    a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    a.title,
                    a.message,
                    a.severity
                ])

        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        filename = f"farmlink_report_{mode}_{end_date.strftime('%Y%m%d')}.csv"
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

# ─── MAIN ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[MAIN] Starting Flask on port {port}")
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False
    )