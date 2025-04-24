#include <Wire.h>

const uint8_t  EE_ADDR = 0x54;
const uint32_t START = 0;
const uint32_t TOTAL = 4096;

void setup() {
    Wire.begin();
    Serial.begin(115200);
    delay(100);
}

void loop() {
    for (uint32_t addr = START; addr < TOTAL; addr += 1) {
        Wire.beginTransmission(EE_ADDR);
        Wire.write(uint8_t(addr & 0xFF));
        Wire.write(uint8_t(addr >> 8));
        Wire.endTransmission(false);
        uint8_t  chunk = 1;
        Wire.requestFrom(EE_ADDR, chunk);
        for (int i = 0; i < chunk; i++) {
            while (!Wire.available()) delayMicroseconds(1);
            Serial.write(Wire.read());
        }
    }
    while (1);
}