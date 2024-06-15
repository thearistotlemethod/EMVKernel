#pragma once
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Util.h"

using namespace std;

class EmvL2SecUtil {
private:
	EmvL2SecUtil();

public:
	static EmvL2SecUtil& getInstance();
	~EmvL2SecUtil();
	int init(IDevice* device);
	uint8_t determineDataAuthType(uint8_t* authType);

	int recoverPubKeyCert(emvl2PkMode pkType, uint8_t modLen,uint8_t* exponent, int exlen, uint8_t certLen,uint8_t* certData, uint8_t* issPkModLen);
	void rsaEncrypt(emvl2PkMode pkType, uint8_t modLen, uint8_t* exponent, uint8_t exlen, uint8_t* data, uint8_t dataLength);
	int recoverICCPINEncPubKeyCert(uint8_t modLen, uint8_t* iccPinModLen);
	int recoverICCPubKeyCert(uint8_t modLen, uint8_t* iccPinModLen);
	void prepStaticTagListData(int* lstlen);	
	int verifyDynamicSign(emvl2PkMode pkType, uint8_t modLen,uint8_t* data, uint8_t dataLength);
	int genACCDATemplate80Processing();
	int genACNOCDATemplate80Processing();
	int genACCDATemplate77Processing(bool isCda);
	int genACNOCDATemplate77Processing();
	int verifyDynamicSignAC(emvl2PkMode pkType, uint8_t modLen, uint8_t* cid);

private:
	static EmvL2SecUtil* instance;
	IDevice* device;
	EmvL2Repo& repo;
	EmvL2Util& util;	
};
