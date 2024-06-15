#pragma once
#include "emvl2Defs.h"
#include "IDevice.h"
#include "emvl2Repo.h"

using namespace std;

class EmvL2Command {
private:
	EmvL2Command();
public:
	static EmvL2Command& getInstance();	
	~EmvL2Command();
	emvl2Ret init(IDevice* device);

	emvl2Ret generateAC(uint8_t* data, uint8_t len, uint8_t cid);
	emvl2Ret getProcessingOptions(uint8_t* data, uint8_t len);
	emvl2Ret select(uint8_t* data, uint8_t len, uint8_t p2 = 0x00);
	emvl2Ret readRecord(uint8_t sfi, uint8_t idx);
	emvl2Ret internalAuthenticate(uint8_t* data, uint8_t len);
	emvl2Ret externalAuthenticate();
	emvl2Ret getData(uint32_t tag);
	emvl2Ret verify(uint8_t type, uint8_t* data, uint8_t len);
	emvl2Ret getChallenge();

private:
	emvl2Ret performCommand1(emvl2Apdu* apdu);
	emvl2Ret performCommand2(emvl2Apdu* apdu);
	emvl2Ret performCommand3(emvl2Apdu* apdu);
	emvl2Ret performCommand4(emvl2Apdu* apdu);
	emvl2Ret transmit(emvl2Apdu* apdu);

private:
	static EmvL2Command* instance;
	IDevice* device;
	EmvL2Repo& repo;
};
