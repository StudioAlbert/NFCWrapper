#include "NCNS-NFCWrapper.h"

// Uncomment to verbose and debug
//#define WRAP_DEBUG

NFCMifareWrapper::NFCMifareWrapper() :
nfc(PN532_SS)
{
  //uid = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  numOfSector = 16;                 // Assume Mifare Classic 1K for now (16 4-block sectors)
}

// Setup
void NFCMifareWrapper::setup(){

  Serial.println("Looking for PN532...");

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }

  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX);
  Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);

  // configure board to read RFID tags
  nfc.SAMConfig();

}

/* ------------------------------------------------------
// Wait for an ISO14443A type card (Mifare, etc.).  When one is found
// 'uid' will be populated with the UID, and uidLength will indicate
// if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
------------------------------------------------------ */
bool NFCMifareWrapper::isTagPresent(){

  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 250))
  {
    // We seem to have a tag ...
    // Display some basic information about it
    #ifdef WRAP_DEBUG
    Serial.print("Found an ISO14443A card/tag");
    Serial.print("  UID Length: ");Serial.print(uidLength, DEC);Serial.print(" bytes");
    Serial.print("  UID Value: ");
    nfc.PrintHex(uid, uidLength);
    Serial.println("");
    #endif
    return true;

  }else{

    //Serial.println("Card/Tag not found");

    return false;

  }

}


// Write
void NFCMifareWrapper::formatMifare(){

  bool authenticated = false;               // Flag to indicate if the sector is authenticated
  uint8_t blockBuffer[16];                  // Buffer to store block contents
  uint8_t blankAccessBits[3] = { 0xff, 0x07, 0x80 };
  uint8_t idx = 0;

  uint8_t formatSuccess;                          // Flag to check if there was an error with the PN532

  // Make sure this is a Mifare Classic card
  if (uidLength != 4)
  {
    Serial.println("Ooops ... this doesn't seem to be a Mifare Classic card!");
    return;
  }
  #ifdef WRAP_DEBUG
  Serial.println("Seems to be a Mifare Classic card (4 byte UID)");
  Serial.println("");
  Serial.println("Reformatting card for Mifare Classic (please don't touch it!) ... ");
  #endif

  // Now run through the card sector by sector
  for (idx = 0; idx < numOfSector; idx++)
  {
    // Step 1: Authenticate the current sector using key B 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
    formatSuccess = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, BLOCK_NUMBER_OF_SECTOR_TRAILER(idx), 1, (uint8_t *)KEY_DEFAULT_KEYAB);
    if (!formatSuccess)
    {
      Serial.print("Authentication failed for sector "); Serial.println(numOfSector);
      return;
    }

    // Step 2: Write to the other blocks
    if (idx == 16)
    {
      memset(blockBuffer, 0, sizeof(blockBuffer));
      if (!(nfc.mifareclassic_WriteDataBlock((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 3, blockBuffer)))
      {
        Serial.print("Unable to write to sector "); Serial.println(numOfSector);
        return;
      }
    }
    if ((idx == 0) || (idx == 16))
    {
      memset(blockBuffer, 0, sizeof(blockBuffer));
      if (!(nfc.mifareclassic_WriteDataBlock((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 2, blockBuffer)))
      {
        Serial.print("Unable to write to sector "); Serial.println(numOfSector);
        return;
      }
    }
    else
    {
      memset(blockBuffer, 0, sizeof(blockBuffer));
      if (!(nfc.mifareclassic_WriteDataBlock((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 3, blockBuffer)))
      {
        Serial.print("Unable to write to sector "); Serial.println(numOfSector);
        return;
      }
      if (!(nfc.mifareclassic_WriteDataBlock((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 2, blockBuffer)))
      {
        Serial.print("Unable to write to sector "); Serial.println(numOfSector);
        return;
      }
    }
    memset(blockBuffer, 0, sizeof(blockBuffer));
    if (!(nfc.mifareclassic_WriteDataBlock((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)) - 1, blockBuffer)))
    {
      Serial.print("Unable to write to sector "); Serial.println(numOfSector);
      return;
    }

    // Step 3: Reset both keys to 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
    memcpy(blockBuffer, KEY_DEFAULT_KEYAB, sizeof(KEY_DEFAULT_KEYAB));
    memcpy(blockBuffer + 6, blankAccessBits, sizeof(blankAccessBits));
    blockBuffer[9] = 0x69;
    memcpy(blockBuffer + 10, KEY_DEFAULT_KEYAB, sizeof(KEY_DEFAULT_KEYAB));

    // Step 4: Write the trailer block
    if (!(nfc.mifareclassic_WriteDataBlock((BLOCK_NUMBER_OF_SECTOR_TRAILER(idx)), blockBuffer)))
    {
      Serial.print("Unable to write trailer block of sector "); Serial.println(numOfSector);
      return;
    }
  }
}

void NFCMifareWrapper::writeMifareBlock(int _numBlock, String _blockValue){

  uint8_t writeSuccess;                          // Flag to check if there was an error with the PN532

  // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
  // 'uid' will be populated with the UID, and uidLength will indicate
  // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
  if (uidLength == 4)
  {
    // We probably have a Mifare Classic card ...
    //Serial.println("Seems to be a Mifare Classic card (4 byte UID)");

    // Now we need to try to authenticate it for read/write access
    // Try with the factory default KeyA: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
    //Serial.println("Trying to authenticate block 4 with default KEYA value");

    // Start with block 4 (the first block of sector 1) since sector 0
    // contains the manufacturer data and it's probably better just
    // to leave it alone unless you know what you're doing
    writeSuccess = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, (uint8_t *)KEY_DEFAULT_KEYAB);

    if (writeSuccess)
    {
      Serial.println("Sector 1 (Blocks 4..7) has been authenticated");
      uint8_t data[16];

      for (size_t idxChar = 0; idxChar < 16; idxChar++) {
        if(idxChar < _blockValue.length()){
          data[idxChar] = _blockValue[idxChar];
        }else{
          data[idxChar] = 0;
        }
      }

      // If you want to write something to block 4 to test with, uncomment
      // the following line and this text should be read back in a minute
      //memcpy(data, (const uint8_t[]){ 'a', 'd', 'a', 'f', 'r', 'u', 'i', 't', '.', 'c', 'o', 'm', 0, 0, 0, 0 }, sizeof data);
      writeSuccess = nfc.mifareclassic_WriteDataBlock (_numBlock, data);

      if (writeSuccess)
      {
        // Data seems to have been read ... spit it out
        Serial.print("Writing success Block :");
        Serial.println(_numBlock);

        Serial.print("Datas :");
        for (size_t idxChar = 0; idxChar < 16; idxChar++) {
          Serial.print((char)data[idxChar]);
        }
        Serial.println();

      }
      else
      {
        Serial.println("Ooops ... unable to write the requested block.  Try another key?");
      }
    }
    else
    {
      Serial.println("Ooops ... authentication failed: Try another key?");
    }
  }
}

// Read
String NFCMifareWrapper::readMifareBlock(int _numBlock){

  if (uidLength == 4)
  {
    // We probably have a Mifare Classic card ...
    #ifdef WRAP_DEBUG
    Serial.println("Seems to be a Mifare Classic card (4 byte UID)");
    #endif

    return readMifareClassic(_numBlock);
  }

  if (uidLength == 7)
  {
    // We probably have a Mifare Ultralight card ...
    #ifdef WRAP_DEBUG
    Serial.println("Seems to be a Mifare Ultralight tag (7 byte UID)");
    #endif
    //return readMifareUltralight(_numBlock);
  }
}

String NFCMifareWrapper::readMifareClassic(int _numBlock){

  bool readSuccess;
  uint8_t data[16];
  String resultString = "";

  // Now we need to try to authenticate it for read/write access
  // Try with the factory default KeyA: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  #ifdef WRAP_DEBUG
  Serial.println("Trying to authenticate block 4 with default KEYA value");
  #endif
  // Start with block 4 (the first block of sector 1) since sector 0
  // contains the manufacturer data and it's probably better just
  // to leave it alone unless you know what you're doing
  readSuccess = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, (uint8_t *)KEY_DEFAULT_KEYAB);

  if (readSuccess)
  {
    #ifdef WRAP_DEBUG
    Serial.println("Sector 1 (Blocks 4..7) has been authenticated");
    #endif

    // Try to read the contents of block 4
    readSuccess = nfc.mifareclassic_ReadDataBlock(_numBlock, data);

    if (readSuccess)
    {

      // Data seems to have been read ... spit it out
      #ifdef WRAP_DEBUG
      Serial.print("Reading Block : ");
      Serial.println(_numBlock);
      nfc.PrintHexChar(data, 16);
      Serial.println("");
      #endif

      // Concatenates all char into a String
      for (size_t idxChar = 0; idxChar < 16; idxChar++) {
        resultString += (char) data[idxChar];
      }

    }
    else
    {
      Serial.println("Ooops ... unable to read the requested block.  Try another key?");
    }
  }
  else
  {
    Serial.println("Ooops ... authentication failed: Try another key?");
  }

  return resultString;

}
/*
String NFCMifareWrapper::readMifareUltralight(int _numPage){

bool readSuccess;
uint8_t data[32];
String resultString = "";

// Try to read the first general-purpose user page (#4)
Serial.print("Reading page :");
Serial.println(_numPage);

readSuccess = nfc.mifareultralight_ReadPage (_numPage, data);

if (readSuccess)
{
// Data seems to have been read ... spit it out
nfc.PrintHexChar(data, 4);
Serial.println("");

// Wait a bit before reading the card again
delay(1000);
}
else
{
Serial.println("Ooops ... unable to read the requested page!?");
}

// Concatenates all char into a String
for (size_t idxChar = 0; idxChar < 32; idxChar++) {
resultString += (char) data[idxChar];
}
return resultString;

}
*/
