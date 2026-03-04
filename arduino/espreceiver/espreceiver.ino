#include <SPI.h>
#include <LoRa.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

// ─── WiFi Credentials ────────────────────────────────────────────────
//const char* ssid     = "Smart_Bro_6EEA1A";
//const char* password = "smartbro";          

const char* ssid     = "HUAWEI-tM2x";
const char* password  = "jnnmzQ4v";

// ─── Backend Endpoints ───────────────────────────────────────────────
const String ingestUrl   = "https://farmlink-backend-rx5g.onrender.com/api/ingest";
const String commandUrl  = "https://farmlink-backend-rx5g.onrender.com/api/get-command";

// ─── LoRa Pins (for ESP8266 / NodeMCU) ───────────────────────────────
#define LORA_SS     15   // D8 
#define LORA_RST    16   // D0 
#define LORA_DIO0    4   // D2 

// Timing for polling commands from server
unsigned long lastCommandPoll = 0;
const unsigned long commandPollInterval = 15000;  // 15 seconds

void setup() {
  Serial.begin(115200);
  delay(200);

  Serial.println("\nESP8266 LoRa Receiver + Remote Control starting...");

  // Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected - IP: " + WiFi.localIP().toString());

  // Initialize LoRa
  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);

  if (!LoRa.begin(433E6)) {  
    Serial.println("LoRa init failed!");
    while (1);
  }

  LoRa.setSyncWord(0xF3);
  LoRa.setSpreadingFactor(12);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(5);

  Serial.println("LoRa ready - waiting for packets");
}

void sendLoRaCommand(String cmd) {
  LoRa.beginPacket();
  LoRa.print(cmd);
  LoRa.endPacket();
  Serial.println("Sent via LoRa: [" + cmd + "]");
}

void pollForCommand() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected - skipping command poll");
    return;
  }

  WiFiClientSecure client;
  client.setInsecure();  // For testing with self-signed or Render HTTPS

  HTTPClient http;
  if (http.begin(client, commandUrl)) {
    int httpCode = http.GET();
    if (httpCode == 200) {
      String payload = http.getString();
      payload.trim();

      Serial.print("Command poll response: ");
      Serial.println(payload);

      // Very simple string matching - you can improve with ArduinoJson later
      if (payload.indexOf("\"OPEN\"") >= 0 || payload.indexOf("OPEN") >= 0) {
        sendLoRaCommand("OPEN");
      }
      else if (payload.indexOf("\"CLOSE\"") >= 0 || payload.indexOf("CLOSE") >= 0) {
        sendLoRaCommand("CLOSE");
      }
      // You can add more commands like "AUTO", "STATUS", etc. later
    } else {
      Serial.printf("Command GET failed, code: %d\n", httpCode);
    }
    http.end();
  } else {
    Serial.println("HTTP begin failed for command endpoint");
  }
}

void loop() {
  // ─── Receive data from Arduino ─────────────────────────────────────
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    String received = "";
    while (LoRa.available()) {
      received += (char)LoRa.read();
    }

    Serial.println("Received: " + received);
    Serial.print("RSSI: " + String(LoRa.packetRssi()) + " | SNR: " + String(LoRa.packetSnr()));

    // Forward to backend
    if (WiFi.status() == WL_CONNECTED) {
      WiFiClientSecure client;
      client.setInsecure();

      HTTPClient http;
      if (http.begin(client, ingestUrl)) {
        http.addHeader("Content-Type", "application/json");

        int httpCode = http.POST(received);
        if (httpCode > 0) {
          String response = http.getString();
          Serial.println("POST success: HTTP " + String(httpCode));
          Serial.println("Server response: " + response);
        } else {
          Serial.println("POST failed, error: " + http.errorToString(httpCode));
        }
        http.end();
      } else {
        Serial.println("HTTP begin failed");
      }
    } else {
      Serial.println("WiFi lost - skipping POST");
    }
  }

  // ─── Poll for remote commands from backend ─────────────────────────
  unsigned long now = millis();
  if (now - lastCommandPoll >= commandPollInterval) {
    lastCommandPoll = now;
    pollForCommand();
  }

  // ─── Optional: manual testing via serial monitor ───────────────────
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    input.toUpperCase();

    if (input == "OPEN" || input == "O") {
      sendLoRaCommand("OPEN");
    }
    else if (input == "CLOSE" || input == "C") {
      sendLoRaCommand("CLOSE");
    }
    else if (input == "STATUS" || input == "S") {
      Serial.println("Polling status not implemented yet");
    }
  }

  // Small delay to prevent tight loop
  delay(50);
}