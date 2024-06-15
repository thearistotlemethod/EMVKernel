#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"
#include "emvl2SecUtil.h"

using namespace std;

class EmvL2ProcessCVM {
public:
	EmvL2ProcessCVM(IDevice& device);
	~EmvL2ProcessCVM();
	uint8_t perform();

private:
	int processResult(uint8_t result, uint8_t condCode, uint8_t code);
	uint8_t init();
	void finalize(int idx);
	void nextCVMCode(int idx, uint8_t* code, uint8_t* type);
	uint8_t checkConditionCode(uint8_t condCode, uint8_t code);
	uint8_t isUnattendedTerminal(uint8_t ttype);
	uint8_t cvmIsSupported(uint8_t code);
	uint8_t isCVMCodeSupported(uint8_t code, int* isSuccess);
	uint8_t doMethod(uint8_t type, int* isSuccess);
	int offlinePlainPIN(int* isSuccess);
	int offlineEncryptedPIN(int* isSuccess);
	int getICCEncPublicKey(uint8_t* modLen);
	int getICCPublicKey(uint8_t* modLen);

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
	EmvL2SecUtil& secUtil;	
};
