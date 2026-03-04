#include <SPI.h>
#include <LoRa.h>
#include <DHT.h>

// ─── PINS ────────────────────────────────────────
#define DHTPIN          3
#define DHTTYPE         DHT22
#define SOIL_PIN        A0
#define LIGHT_PIN       A2
#define RELAY_PIN       5

#define LORA_SS         10
#define LORA_RST        9
#define LORA_DIO0       2

const int MOISTURE_DRY_RAW = 650;

DHT dht(DHTPIN, DHTTYPE);

void setup() {
  Serial.begin(9600);
  while (!Serial);

  dht.begin();

  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, HIGH);

  Serial.println("Arduino Uno LoRa Sender starting...");

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);

  if (!LoRa.begin(433E6)) {
    Serial.println("LoRa init failed!");
    while (1);
  }

  LoRa.setSyncWord(0xF3);
  LoRa.setSpreadingFactor(12);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(5);

  Serial.println("Sender ready");
}

void loop() {
    // ─── Read sensors first (your existing code) ────────────────────────
    float humidity    = dht.readHumidity();
    float temperature = dht.readTemperature();
    int soilRaw       = analogRead(SOIL_PIN);
    int lightRaw      = analogRead(LIGHT_PIN);

    if (isnan(humidity) || isnan(temperature)) {
        Serial.println("DHT read error!");
        delay(5000);
        return;
    }

    bool solenoidOn = (soilRaw > MOISTURE_DRY_RAW);
    digitalWrite(RELAY_PIN, solenoidOn ? LOW : HIGH);

    // Build payload
    String payload = "{";
    payload += "\"moisture\":" + String(map(soilRaw, 1023, 0, 0, 100)) + ",";
    payload += "\"temperature\":" + String(temperature, 1) + ",";
    payload += "\"humidity\":" + String(humidity, 1) + ",";
    payload += "\"light\":" + String(map(lightRaw, 0, 1023, 0, 1000)) + ",";
    payload += "\"solenoid_open\":" + String(solenoidOn ? "true" : "false");
    payload += "}";

    // ─── Handle BOTH incoming packets and sending ───────────────────────
    int packetSize = LoRa.parsePacket();   // ← ONLY ONE declaration here

    if (packetSize) {
        String received = "";
        while (LoRa.available()) {
            received += (char)LoRa.read();
        }
        received.trim();

        Serial.print("Received via LoRa: [");
        Serial.print(received);
        Serial.print("]  RSSI: ");
        Serial.println(LoRa.packetRssi());

        // Check if this is a COMMAND from gateway (OPEN / CLOSE)
        String cmd = received;
        cmd.toUpperCase();

        if (cmd == "OPEN") {
            digitalWrite(RELAY_PIN, LOW);
            solenoidOn = true;
            Serial.println("Solenoid OPENED remotely");
        }
        else if (cmd == "CLOSE") {
            digitalWrite(RELAY_PIN, HIGH);
            solenoidOn = false;
            Serial.println("Solenoid CLOSED remotely");
        }
        // You can add more commands later, e.g. "STATUS", "AUTO"
    }

    // ─── Send telemetry (every loop, as before) ─────────────────────────
    LoRa.beginPacket();
    LoRa.print(payload);
    LoRa.endPacket();

    Serial.print("Sent telemetry: ");
    Serial.println(payload);

    delay(10000);  // or your preferred interval
}