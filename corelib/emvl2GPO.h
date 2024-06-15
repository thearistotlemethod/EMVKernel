#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"
#include "emvl2SecUtil.h"

using namespace std;

class EmvL2GPO {
public:
	EmvL2GPO(IDevice& device);
	~EmvL2GPO();
	uint8_t perform(uint8_t ttype, uint8_t atype, const char* amt, const char* oamt);

private:
	int initizalizeTerminalTags(uint8_t ttype, uint8_t atype, const char* amt, const char* oamt);
	void clearNonAppSelectionTags();
	int setAmountTags(uint8_t ttype, uint8_t* bamt, uint8_t* boamt);
	void fillDynamicTags();
	int prepPDOL(uint8_t* data, uint8_t* len);
	int processGPOResponse();

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
	EmvL2SecUtil& secUtil;
};

