import threading
import json
import time
import random
import string
import os
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import serial

# ─── CONFIG ───────────────────────────────────────────────────────────────
SERIAL_ENABLED = True
SERIAL_PORT = "COM6"
BAUD_RATE = 9600
SERIAL_TIMEOUT_SEC = 0.2

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:041323@localhost:3306/farmlinkdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Recommended MySQL connection pool settings
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 3600,
    'pool_pre_ping': True
}

db = SQLAlchemy(app)

# ─── FLASK-MAIL CONFIGURATION ────────────────────────────────────────────
app.config['MAIL_SERVER']      = 'smtp.gmail.com'
app.config['MAIL_PORT']        = 587
app.config['MAIL_USE_TLS']     = True
app.config['MAIL_USERNAME']    = 'farmlinktech.ph@gmail.com'
app.config['MAIL_PASSWORD']    = 'dudjhqizwxdpjlgb'
app.config['MAIL_DEFAULT_SENDER'] = 'farmlinktech.ph@gmail.com'

app.config['MAIL_DEBUG']         = True
app.config['TESTING']            = False
app.config['MAIL_SUPPRESS_SEND'] = False

mail = Mail(app)

# ─── DATABASE MODELS ─────────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="sakada")  # sakada or owner
    verified = db.Column(db.Boolean, default=False)
    access_code = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    log_type = db.Column(db.String(20), default="info")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f"<Log {self.title}>"

class PalayanConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    min_moisture = db.Column(db.Float, default=40.0)
    max_moisture = db.Column(db.Float, default=70.0)
    auto_mode = db.Column(db.Boolean, default=True)
    auto_water_time = db.Column(db.String(5), default="06:00")  # HH:MM
    duration_minutes = db.Column(db.Integer, default=10)
    max_temperature = db.Column(db.Float, default=35.0)
    min_humidity = db.Column(db.Float, default=50.0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Latest sensor values (updated live)
    current_moisture = db.Column(db.Float, default=0.0)
    current_temperature = db.Column(db.Float, default=0.0)
    current_humidity = db.Column(db.Float, default=0.0)
    current_light = db.Column(db.Float, default=0.0)
    solenoid_open = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return "<PalayanConfig (single row)>"

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    alert_type = db.Column(db.String(20), default="info")   # info, warning, critical, resolved
    severity = db.Column(db.Integer, default=1)             # 1=low, 2=medium, 3=high
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    resolved = db.Column(db.Boolean, default=False)
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
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    duration_minutes = db.Column(db.Integer, nullable=False)
    triggered_by = db.Column(db.String(20), default="auto")  # auto, manual, user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    solenoid_opened = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref='irrigation_events')

    def __repr__(self):
        return f"<IrrigationEvent {self.start_time}>"

class SensorReading(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    moisture = db.Column(db.Float)
    temperature = db.Column(db.Float)
    humidity = db.Column(db.Float)
    light = db.Column(db.Float)

    def __repr__(self):
        return f"<SensorReading {self.timestamp}>"

# ─── LOGGING HELPER ──────────────────────────────────────────────────────
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

# ─── EMAIL FUNCTION ──────────────────────────────────────────────────────
def send_access_code_email(recipient_email, access_code):
    try:
        print(f"[EMAIL DEBUG] Attempting to send to {recipient_email} with code {access_code}")
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
        with app.app_context():
            mail.send(msg)
        print(f"[EMAIL SUCCESS] Sent to {recipient_email}")
        return True
    except Exception as e:
        import traceback
        print("[EMAIL CRITICAL FAILURE]")
        print(traceback.format_exc())
        return False

# ─── SERIAL WORKER ───────────────────────────────────────────────────────
def serial_worker():
    if not SERIAL_ENABLED:
        print("[SERIAL] Disabled in config")
        return

    print(f"[SERIAL] Starting on {SERIAL_PORT} @ {BAUD_RATE} baud")

    try:
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

                # Update config (single row)
                config = PalayanConfig.query.first()
                if config:
                    config.current_moisture = moisture_percent
                    config.current_temperature = temperature
                    config.current_humidity = humidity
                    config.current_light = light
                    config.solenoid_open = bool(solenoid)
                    config.last_updated = datetime.utcnow()
                    db.session.commit()

                # Save historical reading
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

    except serial.SerialException as e:
        print(f"[SERIAL ERROR] Cannot open port: {e}")
    except Exception as e:
        print(f"[SERIAL CRASH] {e}")

threading.Thread(target=serial_worker, daemon=True).start()

# ─── API ROUTES ──────────────────────────────────────────────────────────

@app.route("/api/data")
def api_data():
    config = PalayanConfig.query.first()
    if not config:
        return jsonify({"ok": False, "message": "No configuration", "zoneA": {}})

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
def api_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([a.to_dict() for a in alerts])

@app.route("/api/status")
def api_status():
    config = PalayanConfig.query.first()
    return jsonify({
        "lora": True,  # placeholder
        "mcu1": True,
        "mcu2": True,
        "auto_mode": config.auto_mode if config else True
    })

# Your existing routes (signup, login, update_profile, etc.) remain unchanged below
# ...

if __name__ == "__main__":
    with app.app_context():
        print("[DEBUG] Checking/creating all tables...")
        db.create_all()

        # Seed single Palayan config if missing
        if not PalayanConfig.query.first():
            default = PalayanConfig()
            db.session.add(default)
            db.session.commit()
            print("[SEED] Created default Palayan config")

        print("[DB] Database ready")

    app.run(host="0.0.0.0", port=5000, threaded=True, use_reloader=False)