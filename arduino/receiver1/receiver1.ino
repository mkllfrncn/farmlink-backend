#include <SPI.h>
#include <LoRa.h>
#include <WiFi.h>
#include <HTTPClient.h>

const char* ssid     = "HUAWEI-tM2x";      // ← change this
const char* password = "jnnmzQ4v";  // ← change this

const String ingestUrl = "https://farmlink-backend-rx5g.onrender.com/api/ingest";

#define LORA_SS     5
#define LORA_RST    14
#define LORA_DIO0   2

void setup() {
  Serial.begin(115200);
  delay(200);

  Serial.println("\nESP32 LoRa Receiver starting...");

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);

  if (!LoRa.begin(433E6)) {
    Serial.println("LoRa init failed!");
    while (1);
  }

  LoRa.setSyncWord(0xF3);
  LoRa.setSpreadingFactor(12);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(5);

  Serial.println("Ready");
}

void loop() {
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    String received = "";
    while (LoRa.available()) {
      received += (char)LoRa.read();
    }

    Serial.println("Received: " + received);

    if (WiFi.status() == WL_CONNECTED) {
      HTTPClient http;
      http.begin(ingestUrl);
      http.addHeader("Content-Type", "application/json");

      int httpCode = http.POST(received);

      if (httpCode > 0) {
        Serial.println("POST OK: " + String(httpCode));
      } else {
        Serial.println("POST failed");
      }
      http.end();
    }
  }
}