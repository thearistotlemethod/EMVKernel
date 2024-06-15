#pragma once
#include "..\IDevice.h"
#include "../entrypoint.h"
#include <string>

using namespace std;

class DeviceImpl : public IDevice {
public:
	DeviceImpl();
	DeviceImpl(const char *readerName, LogCallbackFunction logCb, PinCallbackFunction pinCb);
	~DeviceImpl();

	emvl2Ret cardReset();
	emvl2Ret cardSendReceive(uint8_t* sendData, uint32_t sendDataLength, uint8_t* replyData, uint32_t* replyDataLength);
	uint8_t cardProtocol();
	emvl2Ret pinOfflinePlain(uint8_t *cardSws);
	emvl2Ret pinOfflineEncrypted(uint8_t* publicKeyMod, uint8_t publicKeyModLength, uint8_t* publicKeyExponent, uint8_t publicKeyExponentLength, uint8_t unpredictNumber[8], uint8_t *cardSws);
	emvl2Ret pinOnline(uint8_t* pan, uint8_t len);
	emvl2Ret getDateTime(emvl2DateTime* datetime);
	void logf(const char* format, ...);
	emvl2Ret sha1(uint8_t* data, uint32_t length, uint8_t digest[20]);
	emvl2Ret rsaDecrypt(uint8_t* modulus, uint8_t modulusLength, uint8_t* exponent, uint8_t exponentLength, uint8_t* inputData, uint8_t inputDataLength, uint8_t* decryptedData);
	emvl2Ret genRand(uint8_t* unpredictNumber, int len);
	void hexdump(void* ptr, int buflen);

private:
	void convertStrToBcd(const char* src, int len, uint8_t* dest, int RL);


private:
	SCARD_IO_REQUEST actIOProtocol;
	SCARDHANDLE card;
	SCARDCONTEXT cardContext;
	uint8_t protocol;
	std::string readerName = "Gemplus USB Smart Card Reader 0";
	LogCallbackFunction logCallback = NULL;
	PinCallbackFunction pinCallback = NULL;
};