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

# ─── CONFIG ───────────────────────────────────────────────────────────────
#SERIAL_ENABLED = True          # Set to True only for local dev with serial port
SERIAL_ENABLED = False
SERIAL_PORT    = "COM9"         # Only used when SERIAL_ENABLED=True
BAUD_RATE      = 115200
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

# JWT error callbacks (logs why token fails)
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
    last_solenoid_open = db.Column(db.DateTime, nullable=True)
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
    if not SERIAL_ENABLED:
        print("[SERIAL] Disabled by SERIAL_ENABLED = False")
        return

    try:
        import serial
        from serial import SerialException
    except ImportError:
        print("[SERIAL] pyserial not installed → skipping serial worker")
        return

    print(f"[SERIAL] Starting worker thread - attempting {SERIAL_PORT} @ {BAUD_RATE} baud")

    while True:  # outer retry loop - keeps trying forever if port disappears
        ser = None
        try:
            ser = serial.Serial(
                port=SERIAL_PORT,
                baudrate=BAUD_RATE,
                timeout=SERIAL_TIMEOUT_SEC,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )
            print(f"[SERIAL] Successfully opened {ser.name}")
            
            # Give Arduino/ESP time to reset & send initial data
            time.sleep(3.5)  # common value after bootloader delay
            ser.reset_input_buffer()
            ser.reset_output_buffer()
            print("[SERIAL] Buffers flushed")

            # Try to read something quickly to confirm it's alive
            initial = ser.readline().decode('utf-8', errors='ignore').strip()
            if initial:
                print(f"[SERIAL] First line after open: {initial}")
            else:
                print("[SERIAL] No immediate data after open - waiting...")

            while True:  # inner read loop - only breaks on fatal serial error
                try:
                    if ser.in_waiting > 0:
                        line = ser.readline().decode('utf-8', errors='ignore').rstrip()
                        if not line:
                            continue

                        print(f"[SERIAL RX] {line}")

                        # ─── Parse incoming data ───────────────────────────────────────
                        data = {}
                        updated = False

                        # Preferred format: JSON
                        if line.startswith('{') and line.endswith('}'):
                            try:
                                data = json.loads(line)
                                updated = True
                            except json.JSONDecodeError as je:
                                print(f"[SERIAL JSON ERROR] {je} → raw: {line}")

                        # Fallback: plain text "key:value key2:value2 ..."
                        else:
                            try:
                                for part in line.split():
                                    if ':' in part:
                                        k, v = part.split(':', 1)
                                        data[k.strip().lower()] = v.strip()
                                if len(data) >= 2:  # at least moisture + one more
                                    updated = True
                            except Exception as pe:
                                print(f"[SERIAL PLAIN PARSE FAIL] {pe} → raw: {line}")

                        # ─── If we got usable data → update database ────────────────
                        if updated and any(k in data for k in ['moisture', 'temperature', 'humidity', 'light']):
                            try:
                                with app.app_context():  # needed because we're in thread
                                    config = PalayanConfig.query.first()
                                    if not config:
                                        print("[SERIAL] No PalayanConfig row found!")
                                        continue

                                    # Update current values (use .get() with fallback)
                                    config.current_moisture    = float(data.get('moisture',    config.current_moisture))
                                    config.current_temperature = float(data.get('temperature', config.current_temperature))
                                    config.current_humidity    = float(data.get('humidity',    config.current_humidity))
                                    config.current_light       = float(data.get('light',       config.current_light))
                                    
                                    # Inside the if updated and ... block, after config update:
                                    if 'solenoid_open' in data or 'solenoid' in data:
                                        new_state = bool(data.get('solenoid') or data.get('solenoid_open') in [1, '1', True, 'true', 'on'])
                                        
                                        if new_state and not config.solenoid_open:
                                            # Just turned ON → record time
                                            config.last_solenoid_open_at = datetime.utcnow()
                                            config.last_solenoid_duration_sec = None  # will be set when it closes
                                        elif not new_state and config.solenoid_open:
                                            # Just turned OFF → calculate how long it was open
                                            if config.last_solenoid_open_at:
                                                duration = (datetime.utcnow() - config.last_solenoid_open_at).total_seconds()
                                                config.last_solenoid_duration_sec = int(duration)
                                                # Optional: create log entry
                                                add_log(
                                                    title="Solenoid Closed",
                                                    message=f"Water pump was open for {duration//60:.0f} min {duration%60:.0f} sec",
                                                    log_type="irrigation"
                                                )
                                        
                                        config.solenoid_open = new_state

                                    # Optional: also take solenoid status if sent
                                    if 'solenoid' in data or 'solenoid_open' in data:
                                        val = data.get('solenoid') or data.get('solenoid_open')
                                        config.solenoid_open = bool(val in [1, '1', 'true', 'on', True])

                                    config.last_updated = datetime.utcnow()
                                    db.session.commit()

                                    # Inside /api/ingest, after updating other values

                                    solenoid_new = data.get('solenoid_open') or data.get('solenoid')

                                    if solenoid_new is not None:
                                        try:
                                            new_state = solenoid_new in [1, '1', True, 'true', 'on', 'OPEN']
                                        except:
                                            new_state = config.solenoid_open  # fallback

                                        was_open = config.solenoid_open

                                        if new_state != was_open:
                                            if new_state:
                                                # Just turned ON
                                                add_log(
                                                    title="Solenoid Opened",
                                                    message="Water pump / solenoid turned ON (manual or auto)",
                                                    log_type="irrigation"
                                                )
                                            else:
                                                # Just turned OFF
                                                add_log(
                                                    title="Solenoid Closed",
                                                    message="Water pump / solenoid turned OFF",
                                                    log_type="irrigation"
                                                )

                                        config.solenoid_open = new_state

                                    # ─── Also save to history table ──────────────────────
                                    reading = SensorReading(
                                        moisture    = config.current_moisture,
                                        temperature = config.current_temperature,
                                        humidity    = config.current_humidity,
                                        light       = config.current_light,
                                        timestamp   = datetime.utcnow()
                                    )
                                    db.session.add(reading)
                                    db.session.commit()

                                    print(f"[SERIAL → DB] Updated: moisture={config.current_moisture:.1f}%, "
                                          f"temp={config.current_temperature:.1f}°C, "
                                          f"hum={config.current_humidity:.1f}%, light={config.current_light:.0f}")

                            except Exception as dbe:
                                print(f"[DB UPDATE ERROR] {dbe}")
                                db.session.rollback()

                    time.sleep(0.08)  # gentle polling rate (~12 Hz max)

                except SerialException as se:
                    print(f"[SERIAL ERROR - inner loop] {se}")
                    break  # break inner → will retry open in outer loop

                except Exception as e:
                    print(f"[SERIAL UNEXPECTED] {e}")
                    time.sleep(1)

        except SerialException as outer_se:
            print(f"[SERIAL OPEN/IO ERROR] {outer_se} → retrying in 8 seconds")
        except Exception as big_e:
            print(f"[SERIAL FATAL] {big_e} → retrying in 10 seconds")
            import traceback
            traceback.print_exc()

        finally:
            if ser and ser.is_open:
                try:
                    ser.close()
                    print("[SERIAL] Port closed cleanly")
                except:
                    pass

        time.sleep(8)  # delay before retrying to open port again

# ─── START SERIAL THREAD HERE (now safe) ──────────────────────────────────
if SERIAL_ENABLED:
    print("[MAIN] Starting Serial thread...")
    threading.Thread(target=serial_worker, daemon=True, name="SerialReader").start()

# ─── Keep-alive thread ─────────────────────────────────────────────────────
def keep_alive():
    while True:
        print("[KEEP ALIVE] Server still running - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        time.sleep(60)

threading.Thread(target=keep_alive, daemon=True).start()

# ─── STARTUP DEBUG & TABLES ───────────────────────────────────────────────

print("[APP START] Entering startup block")
try:
    with app.app_context():
        print("[STARTUP] Creating tables...")
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

        # Seed initial owner account (only if no owners exist)
        if not User.query.filter_by(role='owner').first():
            print("[STARTUP] No owner account found → creating default owner")

            owner_email    = os.environ.get('DEFAULT_OWNER_EMAIL',    'owner@farmlink.ph')
            owner_fullname = os.environ.get('DEFAULT_OWNER_NAME',     'Initial Farm Owner')
            owner_password = os.environ.get('DEFAULT_OWNER_PASSWORD', 'BennyLantacon')
            owner_code     = os.environ.get('DEFAULT_OWNER_CODE',     'FRMLNK-INIT-413')

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
            print("  Password:    (hashed from env var or fallback)")
            print("  → Log in as owner using these credentials.")
        else:
            print("[STARTUP] At least one owner already exists → skipping owner seed")

        print("[STARTUP] Completed successfully")

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
    """
    Endpoint for devices (LoRa gateway, MCU, etc.) to push current sensor readings.
    Also handles solenoid state changes and creates alerts when needed.
    """
    data = request.get_json()
    if not data:
        return jsonify({"ok": False, "error": "No JSON payload received"}), 400

    # ─── Get current config (there should be only one row) ───────────────────────
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "error": "No configuration found in database"}), 500

    now = datetime.utcnow()

    # ─── Extract values with safe fallbacks ──────────────────────────────────────
    moisture    = data.get('moisture')
    temperature = data.get('temperature')
    humidity    = data.get('humidity')
    light       = data.get('light')
    solenoid_new = data.get('solenoid_open') or data.get('solenoid')   # accept both names

    # Convert to proper types (be forgiving with incoming data)
    try:
        if moisture    is not None: moisture    = float(moisture)
        if temperature is not None: temperature = float(temperature)
        if humidity    is not None: humidity    = float(humidity)
        if light       is not None: light       = float(light)
        if solenoid_new is not None:
            solenoid_new = solenoid_new in [1, '1', True, 'true', 'on', 'OPEN']
    except (ValueError, TypeError):
        pass  # keep old value if conversion fails

    # ─── Remember previous solenoid state ────────────────────────────────────────
    was_open = config.solenoid_open

    # ─── Update current values (only if new value was actually sent) ─────────────
    if moisture    is not None: config.current_moisture    = moisture
    if temperature is not None: config.current_temperature = temperature
    if humidity    is not None: config.current_humidity    = humidity
    if light       is not None: config.current_light       = light

    # ─── Handle solenoid state change + track last open time ─────────────────────
    if solenoid_new is not None:
        config.solenoid_open = solenoid_new

        if solenoid_new and not was_open:
            # Just opened → record timestamp
            config.last_solenoid_open_at = now
            config.last_solenoid_duration_sec = None
            add_log(
                title="Solenoid Opened",
                message="Water pump / solenoid turned ON",
                log_type="irrigation"
            )

        elif not solenoid_new and was_open:
            # Just closed → calculate duration
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

    # ─── Always update last_updated timestamp ────────────────────────────────────
    config.last_updated = now

    # Inside /api/ingest, after updating other values

    solenoid_new = data.get('solenoid_open') or data.get('solenoid')

    if solenoid_new is not None:
            try:
                new_state = solenoid_new in [1, '1', True, 'true', 'on', 'OPEN']
            except:
                new_state = config.solenoid_open  # fallback

            was_open = config.solenoid_open

            if new_state != was_open:
                if new_state:
                    # Just turned ON
                    add_log(
                        title="Solenoid Opened",
                        message="Water pump / solenoid turned ON (manual or auto)",
                        log_type="irrigation"
                    )
                else:
                    # Just turned OFF
                    add_log(
                        title="Solenoid Closed",
                        message="Water pump / solenoid turned OFF",
                        log_type="irrigation"
                    )

            config.solenoid_open = new_state

    # ─── Basic alert generation (when data looks suspicious) ─────────────────────
    alerts_created = 0

    # Were we offline for a long time before this packet?
    if config.last_updated:  # avoid first packet edge case
        offline_seconds = (now - config.last_updated).total_seconds()
        if offline_seconds > 180:  # > 3 minutes
            alert = Alert(
                title="Device was offline",
                message=f"No data received for ~{offline_seconds//60} minutes – possible LoRa/MCU disconnect",
                alert_type="connection",
                severity=7
            )
            db.session.add(alert)
            alerts_created += 1

    # Very basic sensor sanity check
    if moisture is not None and (moisture < 0 or moisture > 100):
        alert = Alert(
            title="Invalid moisture reading",
            message=f"Received moisture = {moisture}% (out of range)",
            alert_type="sensor",
            severity=5
        )
        db.session.add(alert)
        alerts_created += 1

    # You can add similar checks for temperature, humidity, light if desired

    # ─── Save sensor history (even if some values are missing) ───────────────────
    reading = SensorReading(
        moisture    = config.current_moisture,
        temperature = config.current_temperature,
        humidity    = config.current_humidity,
        light       = config.current_light,
        timestamp   = now
    )
    db.session.add(reading)

    # ─── Commit everything ───────────────────────────────────────────────────────
    try:
        db.session.commit()

        response_data = {
            "ok": True,
            "message": "Data ingested successfully",
            "alerts_created": alerts_created,
            "current": {
                "moisture": config.current_moisture,
                "temperature": config.current_temperature,
                "humidity": config.current_humidity,
                "light": config.current_light,
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
        print(f"[INGEST ERROR] {str(e)}")
        return jsonify({"ok": False, "error": "Database error during ingest"}), 500
    
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

    # Use utcnow() → naive datetime to match DB column
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

@app.route('/api/update_profile', methods=['POST'])
@jwt_required()
def update_profile():
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()
    if not current_user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    data = request.get_json()
    fullname = data.get('fullname')
    if not fullname:
        return jsonify({"ok": False, "error": "Full name required"}), 400

    current_user.fullname = fullname
    db.session.commit()

    return jsonify({"ok": True, "message": "Profile updated", "fullname": fullname})

@app.route('/api/update_avatar', methods=['POST', 'OPTIONS'])
@jwt_required()
def update_avatar():
    if request.method == 'OPTIONS':
        return jsonify({}), 200  # Handle CORS preflight

    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    data = request.get_json()
    if not data or 'avatar' not in data:
        return jsonify({"ok": False, "error": "Missing 'avatar' field"}), 400

    avatar_base64 = data['avatar']
    if not isinstance(avatar_base64, str) or not avatar_base64.startswith('data:image'):
        return jsonify({"ok": False, "error": "Invalid image format"}), 400

    # Optional: prevent huge images crashing the DB
    if len(avatar_base64) > 2_000_000:  # roughly 1.5MB after base64 overhead
        return jsonify({"ok": False, "error": "Image too large (max ~1.5MB)"}), 413

    user.avatar_base64 = avatar_base64
    db.session.commit()

    return jsonify({"ok": True, "message": "Avatar updated"})

@app.route('/api/access-codes', methods=['GET'])
@jwt_required()
def get_access_codes():
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()
    if not current_user:
        return jsonify({'ok': False, 'error': 'User not found'}), 404
    if current_user.role != 'owner':
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
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()
    if not current_user:
        return jsonify({'ok': False, 'error': 'User not found'}), 404

    print("[SETTINGS] User:", {'email': current_user.email, 'role': current_user.role})

    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "error": "No configuration found"}), 500

    if request.method == 'POST':
        if current_user.role != 'owner':
            return jsonify({'ok': False, 'error': 'Only owners can edit settings'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'ok': False, 'error': 'Invalid JSON payload'}), 400

        # Use ACTUAL model field names
        config.min_moisture = data.get('threshold_zoneA_min', config.min_moisture)
        config.max_moisture = data.get('threshold_zoneA_max', config.max_moisture)
        # If you have zoneB fields, add them here or remove from payload
        config.auto_water_time = data.get('auto_water_time', config.auto_water_time)
        config.duration_minutes = data.get('duration', config.duration_minutes)
        config.max_temperature = data.get('max_temp', config.max_temperature)
        config.min_humidity = data.get('min_humidity', config.min_humidity)
        config.auto_mode = data.get('auto_mode', config.auto_mode)

        db.session.commit()
        return jsonify({"ok": True, "message": "Settings saved"})

    # GET: return actual fields
    return jsonify({
        "ok": True,
        "threshold_zoneA_min": config.min_moisture,
        "threshold_zoneA_max": config.max_moisture,
        "threshold_zoneB_min": 35,  # hardcoded fallback (add fields to model if needed)
        "threshold_zoneB_max": 65,
        "auto_water_time": config.auto_water_time,
        "duration": config.duration_minutes,
        "max_temp": config.max_temperature,
        "min_humidity": config.min_humidity,
        "auto_mode": config.auto_mode,
        "solenoid_open": config.solenoid_open,
        "read_only": current_user.role != 'owner'
    })

@app.route('/api/report')
@jwt_required()
def api_report():
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()
    if not current_user:
        return jsonify({'ok': False, 'error': 'User not found'}), 404
    if current_user.role != 'owner':
        return jsonify({'ok': False, 'error': 'Owners only'}), 403

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
    access_code = data.get('access_code')

    if not all([email, fullname, password]):
        missing = [k for k, v in {'email': email, 'fullname': fullname, 'password': password}.items() if not v]
        return jsonify({
            'ok': False,
            'error': f'Missing required fields: {", ".join(missing)}'
        }), 400

    if role not in ['sakada', 'owner']:
        return jsonify({'ok': False, 'error': 'Invalid role. Must be "sakada" or "owner"'}), 400

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

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'ok': False, 'error': 'No account found with this email'}), 404

    if not user.access_code:
        user.access_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        db.session.commit()

    success = send_access_code_email(
        recipient_email = email,
        access_code     = user.access_code
    )

    if success:
        return jsonify({
            'ok': True,
            'message': 'Access code sent to your email'
        }), 200
    else:
        return jsonify({
            'ok': False,
            'error': 'Failed to send access code email'
        }), 500

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
        
        if not user.verified:
            user.verified = True
            db.session.commit()

        #success = send_access_code_email(email, user.access_code)
        #if success:
        #    print(f"[LOGIN EMAIL] Access code re-sent to owner: {email}")
        #else:
        #    print(f"[LOGIN EMAIL] Failed to send to owner: {email}")

    token = create_access_token(identity=user.email)  # FIXED: string email

    return jsonify({
        'ok': True,
        'token': token,
        'fullname': user.fullname,
        'email': user.email,
        'role': user.role,
        'message': 'Login successful' + (' — access code re-sent to email' if role == 'owner' else '')
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
        "avatar": user.avatar_base64   # ← ADD THIS LINE
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