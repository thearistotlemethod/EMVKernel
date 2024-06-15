#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"
#include "emvl2SecUtil.h"

using namespace std;

class EmvL2OfflineDataAuth {
public:
	EmvL2OfflineDataAuth(IDevice& device);
	~EmvL2OfflineDataAuth();
	uint8_t perform();

private:
	int performCDA();
	int performDDA();
	int performSDA();
	int verifyStaticAppData(emvl2PkMode type, uint8_t modLen);
	int recoverStaticAppData(emvl2PkMode type, uint8_t modLen);

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
	EmvL2SecUtil& secUtil;
};
