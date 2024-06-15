#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2Util.h"
#include "emvl2Command.h"

using namespace std;

class EmvL2AppSelection {
public:
	EmvL2AppSelection(IDevice& device);
	~EmvL2AppSelection();
	uint8_t perform();

private:
	uint8_t finalSelect(int idx);
	uint8_t applyPseSelection(vector<string> aidlist);
	uint8_t applyLstSelection(vector<string> aidlist);
	uint8_t addToList();
	uint8_t addToList(uint8_t* aid, int aidLen);
	uint8_t readPseDir(vector<string> aidlist, uint8_t* data, int dataLen);

private:
	IDevice& device;
	EmvL2Repo& repo;
	EmvL2Command& command;
	EmvL2Util& util;
	vector<emvl2AidInfo*> candList;
};