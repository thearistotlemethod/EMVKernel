#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"
#include "emvl2SecUtil.h"

using namespace std;

class EmvL2GenAC1 {
public:
	EmvL2GenAC1(IDevice& device);
	~EmvL2GenAC1();
	uint8_t perform(uint8_t ucTermDecision, uint8_t* ucCardDecision);

private:
	int genAC1WithCDAProccessing(uint8_t* termDecision, uint8_t* cdolData, uint8_t cdolLen);
	int genAC1WithoutCDAProccessing(uint8_t* termDecision, uint8_t* cdolData, uint8_t cdolLen);
	int genAC1DecisionProccessing(uint8_t termDecision, uint8_t* cardDecision);

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
	EmvL2SecUtil& secUtil;
};
