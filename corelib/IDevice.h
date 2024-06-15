#pragma once
#include "emvl2Defs.h"

class IDevice
{
public:
	virtual emvl2Ret cardReset() = 0;
	virtual emvl2Ret cardSendReceive(uint8_t* sendData, uint32_t sendDataLength, uint8_t* replyData, uint32_t* replyDataLength) = 0;
	virtual uint8_t cardProtocol() = 0;
	virtual emvl2Ret pinOfflinePlain(uint8_t *cardSws) = 0;
	virtual emvl2Ret pinOfflineEncrypted(uint8_t* publicKeyMod, uint8_t publicKeyModLength, uint8_t* publicKeyExponent, uint8_t publicKeyExponentLength, uint8_t unpredictNumber[8], uint8_t *cardSws) = 0;
	virtual emvl2Ret pinOnline(uint8_t* pan, uint8_t len) = 0;
	virtual emvl2Ret getDateTime(emvl2DateTime* datetime) = 0;
	virtual void logf(const char* format, ...) = 0;
	virtual void hexdump(void* ptr, int buflen) = 0;
	virtual emvl2Ret sha1(uint8_t* data, uint32_t length, uint8_t digest[20]) = 0;
	virtual emvl2Ret rsaDecrypt(uint8_t* modulus, uint8_t modulusLength, uint8_t* exponent, uint8_t exponentLength, uint8_t* inputData, uint8_t inputDataLength, uint8_t* decryptedData) = 0;
	virtual emvl2Ret genRand(uint8_t* unpredictNumber, int len) = 0;
};