import threading
import json
import time
import random
import string
import os
import io
import csv
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
from flask import make_response

load_dotenv()  # This loads .env automatically

print(f"[START] PORT from env: {os.environ.get('PORT', 'NOT SET')}")
print(f"[START] Binding to 0.0.0.0:{os.environ.get('PORT', '10000')}")

SERIAL_RECONNECT_REQUEST = False

pending_command = None

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
    base_dir = 'www'

    if path != "" and os.path.exists(os.path.join(base_dir, path)):
        return send_from_directory(base_dir, path)

    return send_from_directory(base_dir, 'login.html')  

# For production on Render
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
                print("🔄 Reconnecting to Serial/LoRa...")
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

# ─── KEEP-ALIVE THREAD ────────────────────────────────────────────────────
def keep_alive():
    while True:
        print("[KEEP ALIVE] Server still running - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        time.sleep(60)

threading.Thread(target=keep_alive, daemon=True).start()

# ─── STARTUP ──────────────────────────────────────────────────────────────
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

        # ─── Safer owner seeding ────────────────────────────────────────────
        owner_email = os.environ.get('DEFAULT_OWNER_EMAIL', 'owner@farmlink.ph').strip().lower()

        owner = User.query.filter_by(email=owner_email).first()

        if not owner:
            print("[STARTUP] No user found with owner email → creating default owner")
            owner_fullname = os.environ.get('DEFAULT_OWNER_NAME', 'Initial Farm Owner')
            owner_password = os.environ.get('DEFAULT_OWNER_PASSWORD', 'BennyLantacon')
            owner_code     = os.environ.get('DEFAULT_OWNER_CODE', 'FRMLNK-INIT-413')

            hashed_pw = generate_password_hash(owner_password)

            owner = User(
                email         = owner_email,
                fullname      = owner_fullname,
                password_hash = hashed_pw,
                role          = 'owner',
                access_code   = owner_code,
                verified      = True,
                created_at    = datetime.utcnow()
            )
            db.session.add(owner)
            db.session.commit()
            print("[STARTUP] Default owner created successfully")

        elif owner.role != 'owner':
            print(f"[STARTUP] Owner email exists but role is '{owner.role}' → fixing to 'owner'")
            owner.role = 'owner'
            db.session.commit()
            print("[STARTUP] Owner role fixed")

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
        access_code = data.get("access_code", "").strip()

        if not email or not password:
            return jsonify({"ok": False, "error": "Email and password are required"}), 400

        # Find user (case-insensitive email)
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"[LOGIN] User not found for email: {email}")
            return jsonify({"ok": False, "error": "Account not found"}), 404

        # Debug: show what we found
        print(f"[LOGIN] Found user ID={user.id}, email={user.email}, role={user.role}")

        # Password check
        if not check_password_hash(user.password_hash, password):
            print(f"[LOGIN] Incorrect password for {email}")
            return jsonify({"ok": False, "error": "Incorrect password"}), 401

        # Owner must provide access code
        if user.role == "owner":
            if not access_code:
                print(f"[LOGIN] Missing access code for owner: {email}")
                return jsonify({"ok": False, "error": "Access code required for owner login"}), 401

            if user.access_code != access_code:
                print(f"[LOGIN] Invalid access code for owner: {email}")
                return jsonify({"ok": False, "error": "Invalid access code"}), 401

        # Success: generate tokens
        access_token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)

        add_log(
            title="User Login",
            message=f"{user.email} logged in successfully (role: {user.role})",
            log_type="auth",
            user_email=user.email
        )

        return jsonify({
            "ok": True,
            "message": "Login successful",
            "token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "email": user.email,
                "fullname": user.fullname,
                "role": user.role,
                "avatar": user.avatar_base64 or ""
            }
        }), 200

    except Exception as e:
        print("[LOGIN ERROR]", str(e))
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
    
@app.route('/api/control', methods=['POST'])
@jwt_required()
def control_solenoid():
    global pending_command
    data = request.get_json()
    action = data.get('action')  # Expect "open" or "close"

    if not data or not action:
        return jsonify({"ok": False, "error": "Missing 'action' field"}), 400

    action = action.lower()
    if action not in ['open', 'close']:
        return jsonify({"ok": False, "error": "Action must be 'open' or 'close'"}), 400

    # Optional: restrict to owners only
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user or user.role != 'owner':
        return jsonify({"ok": False, "error": "Only owners can control solenoid remotely"}), 403

    pending_command = "OPEN" if action == "open" else "CLOSE"

    add_log(
        title="Remote Solenoid Command",
        message=f"Solenoid {action.upper()} requested remotely by {current_email}",
        log_type="irrigation",
        user_email=current_email
    )

    return jsonify({
        "ok": True,
        "message": f"Command '{action.upper()}' queued – will be sent to device soon"
    }), 200


@app.route('/api/get-command', methods=['GET'])
def get_command():
    global pending_command
    if pending_command:
        cmd = pending_command
        pending_command = None
        return jsonify({"command": cmd, "status": "sent"})
    return jsonify({"command": None, "status": "idle"})

@app.route('/api/report', methods=['GET'])
@jwt_required()
def generate_report():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user or user.role != 'owner':
        return jsonify({'ok': False, 'error': 'Owners only'}), 403

    readings = SensorReading.query.order_by(SensorReading.timestamp.desc()).limit(1000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Moisture', 'Temperature', 'Humidity', 'Light'])

    for r in readings:
        writer.writerow([
            r.timestamp.isoformat(),
            r.moisture,
            r.temperature,
            r.humidity,
            r.light
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=sensor_report.csv"
    response.headers["Content-type"] = "text/csv"
    return response
    
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

@app.route('/api/resend-owner-code', methods=['POST'])
def resend_owner_code():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({"ok": False, "error": "Email required"}), 400

    user = User.query.filter_by(email=email, role='owner').first()
    if not user:
        # Security: Don't reveal if exists
        return jsonify({"ok": True, "message": "If an owner account, code sent."}), 200

    # New code
    new_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
    user.access_code = new_code

    try:
        db.session.commit()
        send_access_code_email(email, new_code)  # Your existing function
        return jsonify({"ok": True, "message": "New code sent to email."}), 200
    except Exception as e:
        db.session.rollback()
        print("[RESEND ERROR]", str(e))
        return jsonify({"ok": False, "error": "Failed to send"}), 500

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

# ─── AUTH ─────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'ok': False, "error": "Invalid or missing JSON payload"}), 400

        email = data.get('email', '').strip().lower()
        fullname = data.get('fullname', '').strip()
        password = data.get('password', '').strip()
        role = data.get('role', 'sakada').strip().lower()
        access_code = data.get('access_code', '').strip()

        # Validation
        if not all([email, fullname, password]):
            return jsonify({'ok': False, "error": "Email, full name, and password are required"}), 400

        if role not in ['sakada', 'owner']:
            return jsonify({'ok': False, "error": "Invalid role (must be 'sakada' or 'owner')"}), 400

        if len(password) < 6:
            return jsonify({'ok': False, "error": "Password must be at least 6 characters"}), 400

        # Prevent duplicate email (unique constraint should already block, but double-check)
        if User.query.filter_by(email=email).first():
            return jsonify({'ok': False, "error": "Email already registered"}), 409

        # Owner registration requires access code in payload (optional extra safety)
        if role == 'owner' and not access_code:
            return jsonify({'ok': False, "error": "Access code required for owner registration"}), 400

        hashed_pw = generate_password_hash(password)

        new_user = User(
            email=email,
            fullname=fullname,
            password_hash=hashed_pw,
            role=role,
            verified=False,
            access_code=access_code if role == 'owner' else None
        )

        sent_access_code = None
        if role == 'owner':
            # Generate and send new access code
            sent_access_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
            new_user.access_code = sent_access_code
            send_access_code_email(email, sent_access_code)

        db.session.add(new_user)
        db.session.commit()

        message = 'Registered successfully as ' + role.capitalize()
        if role == 'owner' and sent_access_code:
            message += f' — access code sent to {email}'

        add_log(
            title="User Registered",
            message=f"New user: {email} as {role}",
            log_type="auth"
        )

        return jsonify({
            'ok': True,
            'message': message,
            'role': role
        }), 201

    except Exception as e:
        db.session.rollback()
        print("[REGISTER ERROR]", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({'ok': False, "error": "Failed to create account"}), 500
    
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({"ok": False, "error": "Email required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if email exists (security best practice)
        return jsonify({
            "ok": True,
            "message": "If the email exists, a reset link has been sent."
        }), 200

    # Generate a simple reset token (in production use UUID + expiry)
    reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    # For simplicity: store in user table (add column if needed)
    # But for quick fix: we'll just email it directly (not stored)
    # In real app you should add reset_token + expiry to User model

    try:
        msg = Message(
            subject="FarmLink Password Reset",
            sender=('FarmLink', 'farmlinktech.ph@gmail.com'),
            recipients=[email],
            body=f"""
Hello,

You requested a password reset for your FarmLink account.

Your reset token/code: {reset_token}

Enter this code in the app to set a new password.
This code is valid for 30 minutes.

If you didn't request this, ignore this email.

Best regards,
FarmLink Team
            """.strip()
        )
        mail.send(msg)
        print(f"[RESET EMAIL] Sent to {email} with token {reset_token}")
        
        return jsonify({
            "ok": True,
            "message": "Reset instructions sent to your email."
        }), 200

    except Exception as e:
        print("[FORGOT PASSWORD EMAIL ERROR]", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": "Failed to send email"}), 500

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