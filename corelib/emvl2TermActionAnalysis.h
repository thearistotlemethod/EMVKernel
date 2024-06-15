#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"

using namespace std;

class EmvL2TermActionAnalysis {
public:
	EmvL2TermActionAnalysis(IDevice& device);
	~EmvL2TermActionAnalysis();
	uint8_t perform(uint8_t* termDecision);

private:
	void tcHash(uint8_t* data, uint8_t len);

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
};
