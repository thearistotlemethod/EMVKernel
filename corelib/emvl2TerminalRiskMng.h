#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"

using namespace std;

class EmvL2TerminalRiskMng {
public:
	EmvL2TerminalRiskMng(IDevice& device);
	~EmvL2TerminalRiskMng();
	uint8_t perform();

private:
	int randomTranSelect();
	int velocityCheck();

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
};
