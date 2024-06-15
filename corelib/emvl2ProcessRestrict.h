#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"

using namespace std;

class EmvL2ProcessRestrict {
public:
	EmvL2ProcessRestrict(IDevice& device);
	~EmvL2ProcessRestrict();
	uint8_t perform();

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
};
