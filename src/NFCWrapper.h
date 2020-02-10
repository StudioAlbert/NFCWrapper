
//
// Used with PNC532 Shield (https://www.seeedstudio.com/NFC-Shield-V2.0-p-1370.html)
// BUT with adafruit-lib (https://github.com/adafruit/Adafruit-PN532)
//
// Some good reading before starting
// Adafruit tutorial : https://learn.adafruit.com/adafruit-pn532-rfid-nfc/overview
// French Wikipedia reference : https://fr.wikipedia.org/wiki/Communication_en_champ_proche
//

// Only Mifare Classic Tag format
// So Value string max size (16 bytes)
//

#pragma once

#include <Arduino.h>

// ------------------------------------------------------------------------
#include <Wire.h>
#include <SPI.h>
#include <Adafruit_PN532.h>

// If using the breakout with SPI, define the pins for SPI communication.
#define PN532_SCK  (2)
#define PN532_MOSI (3)
#define PN532_SS   (10)
#define PN532_MISO (5)

// If using the breakout or shield with I2C, define just the pins connected
// to the IRQ and reset lines.  Use the values below (2, 3) for the shield!
#define PN532_IRQ   (2)
#define PN532_RESET (3)  // Not connected by default on the NFC Shield

// 3 kind of declarations -
// Uncomment just _one_ line below depending on how your breakout or shield
// is connected to the Arduino:
// Use this line for a breakout with a SPI connection:
//Adafruit_PN532 nfc(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);
//Adafruit_PN532 nfc(PN532_SS);
//Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET);


#define NR_SHORTSECTOR          32    // Number of short sectors on Mifare 1K/4K
#define NR_LONGSECTOR           8     // Number of long sectors on Mifare 4K
#define NR_BLOCK_OF_SHORTSECTOR 4     // Number of blocks in a short sector
#define NR_BLOCK_OF_LONGSECTOR  16    // Number of blocks in a long sector

// Determine the sector trailer block based on sector number
#define BLOCK_NUMBER_OF_SECTOR_TRAILER(sector) (((sector)<NR_SHORTSECTOR)? \
((sector)*NR_BLOCK_OF_SHORTSECTOR + NR_BLOCK_OF_SHORTSECTOR-1):\
(NR_SHORTSECTOR*NR_BLOCK_OF_SHORTSECTOR + (sector-NR_SHORTSECTOR)*NR_BLOCK_OF_LONGSECTOR + NR_BLOCK_OF_LONGSECTOR-1))

// Determine the sector's first block based on the sector number
#define BLOCK_NUMBER_OF_SECTOR_1ST_BLOCK(sector) (((sector)<NR_SHORTSECTOR)? \
((sector)*NR_BLOCK_OF_SHORTSECTOR):\
(NR_SHORTSECTOR*NR_BLOCK_OF_SHORTSECTOR + (sector-NR_SHORTSECTOR)*NR_BLOCK_OF_LONGSECTOR))

// The default Mifare Classic key
static const uint8_t KEY_DEFAULT_KEYAB[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#if defined(ARDUINO_ARCH_SAMD)
// for Zero, output on USB Serial console, remove line below if using programming port to program the Zero!
// also change #define in Adafruit_PN532.cpp library file
#define Serial SerialUSB
#endif



class NFCMifareWrapper{

public:

  NFCMifareWrapper();

  // Setup
  void setup();
  // Check tag presence
  bool isTagPresent();

  // Write
  void formatMifare();
  void writeMifareBlock(int _numBlock, String _blockValue);

  // Read
  String readMifareBlock(int _numBlock);

private:
  Adafruit_PN532 nfc;

  uint8_t uid[7] = { 0, 0, 0, 0, 0, 0, 0 };   // Buffer to store the returned UID
  uint8_t uidLength;                          // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  uint8_t numOfSector;                        // Assume Mifare Classic 1K for now (16 4-block sectors)

  String readMifareClassic(int _numBlock);
  //String readMifareUltralight(int _numBlock);

};
