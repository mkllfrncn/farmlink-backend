import threading
import json
import time
import random
import string
import os
import io
from flask import Flask, jsonify, request, Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from flask_migrate import Migrate

load_dotenv()  # This loads .env automatically

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

# For production on Render/Heroku/etc.
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
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key-please-change-this-in-production')
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
                time.sleep(2.5)  # give device time to reset
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
    data = request.get_json()
    if not data:
        return jsonify({"ok": False, "error": "No JSON payload received"}), 400

    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "error": "No configuration found"}), 500

    now = datetime.utcnow()

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
            solenoid_new = solenoid_new in [1, '1', True, 'true', 'on', 'OPEN']
    except:
        pass

    was_open = config.solenoid_open

    if moisture    is not None: config.current_moisture    = moisture
    if temperature is not None: config.current_temperature = temperature
    if humidity    is not None: config.current_humidity    = humidity
    if light       is not None: config.current_light       = light

    if solenoid_new is not None:
        config.solenoid_open = solenoid_new
        if solenoid_new and not was_open:
            config.last_solenoid_open_at = now
            config.last_solenoid_duration_sec = None
            add_log("Solenoid Opened", "Water pump / solenoid turned ON", "irrigation")
        elif not solenoid_new and was_open:
            if config.last_solenoid_open_at:
                duration_sec = (now - config.last_solenoid_open_at).total_seconds()
                config.last_solenoid_duration_sec = int(duration_sec)
                add_log("Solenoid Closed", f"Was open for {duration_sec//60} min {duration_sec%60} sec", "irrigation")

    config.last_updated = now

    reading = SensorReading(
        moisture    = config.current_moisture,
        temperature = config.current_temperature,
        humidity    = config.current_humidity,
        light       = config.current_light,
        timestamp   = now
    )
    db.session.add(reading)

    try:
        db.session.commit()
        return jsonify({
            "ok": True,
            "message": "Data ingested successfully",
            "current": {
                "moisture": config.current_moisture,
                "temperature": config.current_temperature,
                "humidity": config.current_humidity,
                "light": config.current_light,
                "solenoid_open": config.solenoid_open,
                "last_updated": config.last_updated.isoformat()
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"[INGEST ERROR] {str(e)}")
        return jsonify({"ok": False, "error": "Database error during ingest"}), 500

@app.route("/api/alerts")
@jwt_required(optional=True)
def api_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([a.to_dict() for a in alerts])

@app.route('/api/start-auto', methods=['POST'])
@jwt_required()
def start_auto():
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({'ok': False, 'error': 'No configuration found'}), 500

    config.auto_mode = True
    try:
        db.session.commit()
        add_log("Auto Watering", "Manually triggered by user", "irrigation")
        return jsonify({'ok': True, 'message': 'Auto watering mode activated'})
    except:
        db.session.rollback()
        return jsonify({'ok': False, 'error': 'Failed to activate auto mode'}), 500

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

        config.min_moisture     = data.get('threshold_zoneA_min', config.min_moisture)
        config.max_moisture     = data.get('threshold_zoneA_max', config.max_moisture)
        config.auto_water_time  = data.get('auto_water_time',     config.auto_water_time)
        config.duration_minutes = data.get('duration',            config.duration_minutes)
        config.max_temperature  = data.get('max_temp',            config.max_temperature)
        config.min_humidity     = data.get('min_humidity',        config.min_humidity)

        try:
            db.session.commit()
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
    global SERIAL_RECONNECT_REQUEST
    SERIAL_RECONNECT_REQUEST = True
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

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email     = data.get('email')
    password  = data.get('password')
    role      = data.get('role')
    admincode = data.get('admincode') if role == 'owner' else None

    if not all([email, password, role]):
        return jsonify({'ok': False, 'error': 'Missing required fields'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'ok': False, 'error': 'Invalid email or password'}), 401

    if user.role != role:
        return jsonify({'ok': False, 'error': 'Role mismatch'}), 403

    if role == 'owner':
        if not user.access_code or admincode != user.access_code:
            return jsonify({'ok': False, 'error': 'Invalid or missing access code'}), 403
        if not user.verified:
            user.verified = True
            db.session.commit()

    token = create_access_token(identity=user.email)

    return jsonify({
        'ok': True,
        'token': token,
        'fullname': user.fullname,
        'email': user.email,
        'role': user.role,
        'message': 'Login successful'
    }), 200

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