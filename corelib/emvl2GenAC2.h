#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Command.h"
#include "emvl2Util.h"
#include "emvl2SecUtil.h"

using namespace std;

class EmvL2GenAC2 {
public:
	EmvL2GenAC2(IDevice& device);
	~EmvL2GenAC2();
	uint8_t perform(bool isHostReject, uint8_t* decision, uint8_t* adviceReversal);

private:
	int completion(bool isHostReject, uint8_t* cardDecision, uint8_t* adviceReversal);
	void termActionAnalysisDefault(uint8_t* termDecision);
	void issuerAuthentication();
	int issuerScriptProcessing71();
	int issuerScriptProcessing72();
	int genAC2WithCDAProccessing(uint8_t* termDecision, uint8_t* cardDecision, uint8_t* cdolData, uint8_t cdolLen);
	int genAC2WithoutCDAProccessing(uint8_t* termDecision, uint8_t* cardDecision, uint8_t* cdolData, uint8_t cdolLen);
	void genAC2DecisionProccessing(bool isHostReject, uint8_t* termDecision, uint8_t* cardDecision, uint8_t* adviceReversal);

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
	EmvL2SecUtil& secUtil;

	uint8_t g_ucCmdSeqNo;
	int g_iTotalScriptMsgLen;
	uint8_t g_ucScriptIndex;
};