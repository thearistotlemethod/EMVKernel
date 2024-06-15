#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"
#include "emvl2SecUtil.h"

using namespace std;

class EmvL2ReadAppData {
public:
	EmvL2ReadAppData(IDevice& device);
	~EmvL2ReadAppData();
	uint8_t perform();

private:
	uint8_t isDateValid(uint8_t* Date);
	bool checkMandatoryTags();

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
	EmvL2SecUtil& secUtil;
};
