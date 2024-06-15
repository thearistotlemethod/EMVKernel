#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include <string> 
#include <vector> 
#include <map> 

using namespace std;

class EmvL2Repo {
private:
	EmvL2Repo();

public:
	static EmvL2Repo& getInstance();
	~EmvL2Repo();
	emvl2Ret init(IDevice* device);


	int addCaKey(emvl2CAKey key);
	int addAidPrms(emvl2AIDPrms prms);

	void clearCaKeys();
	void clearAidPrms();
	void clearApdu();
	int searchCAKeys(void);

	void clearCardTags();

	int parseTags(uint8_t* buff, int buffLen);
	Tlv* setTag(uint32_t tag, uint8_t* src = NULL, uint8_t len = 0);
	Tlv* getTag(uint32_t tag);
	void setTagFlag(uint32_t tag, int flag);
	bool isTagFlag(uint32_t tag, int flag);
	bool isTagExist(uint32_t tag);
	uint32_t parseLen(uint8_t* data, uint8_t* lenLen = NULL);
	uint32_t parseTag(uint8_t* data, uint8_t* tagLen = NULL);
	int getTagFormat(uint32_t tag);
	void nextTag(uint8_t* data, int* idx);
	int cardBrand();

private:
	uint8_t* getTagDatas(uint32_t tag, int* i = NULL, int* j = NULL, int flag = 0);	
	uint8_t parseTag(uint8_t* buff, uint32_t* val);

public:	
	vector<emvl2AIDPrms> aidPrms;
	vector<uint8_t> script71;
	vector<uint8_t> script72;
	emvl2Apdu apdu;
	vector<uint8_t> transactionHashData;
	vector<uint8_t> staticAppData;
	bool signatureRequired;
	bool pinBypassed;

	uint8_t iccPinPkModulus[PUBKEYMODULUSLEN];
	uint8_t caPkModulus[PUBKEYMODULUSLEN];
	uint8_t issPkModulus[PUBKEYMODULUSLEN];
	uint8_t iccPkModulus[PUBKEYMODULUSLEN];
	uint8_t recPkModulus[PUBKEYMODULUSLEN];
	uint8_t recoveredData[PUBKEYMODULUSLEN];

	emvl2CAKey* activeCAKey;
	uint8_t sdaTermData[256];
	uint8_t typeOfAuth;
	uint8_t cdaIccPkModLen;
	uint8_t performImeediateSecondGenAc;
	uint8_t adviceReversal;
	uint8_t verifyDDAACFail;	
private:
	static EmvL2Repo* instance;
	IDevice* device;

	vector<emvl2CAKey> caKeys;
	map<uint32_t, Tlv> tags;
};
