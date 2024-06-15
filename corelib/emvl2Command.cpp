#include "emvl2Command.h"

EmvL2Command* EmvL2Command::instance = NULL;

EmvL2Command& EmvL2Command::getInstance() {
	if (!instance) {
		instance = new EmvL2Command();
	}
	return *instance;
}

EmvL2Command::EmvL2Command() : repo(EmvL2Repo::getInstance()) {
	device = NULL;
}

EmvL2Command::~EmvL2Command() {

}

emvl2Ret EmvL2Command::init(IDevice* device) {
	this->device = device;

	return success;
}

emvl2Ret EmvL2Command::generateAC(uint8_t* data, uint8_t len, uint8_t cid) {
	repo.clearApdu();

	repo.apdu.CLA = 0x80;
	repo.apdu.INS = 0xAE;
	repo.apdu.P1 = cid;
	repo.apdu.P2 = 0x00;
	repo.apdu.Lc = len;
	repo.apdu.forceData = false;

	if (len == 0xFF)
	{
		repo.apdu.forceData = true;
	}

	repo.apdu.sdata = data;
	repo.apdu.Le = 0x00;

	emvl2Ret rv = performCommand4(&repo.apdu);
	return rv;
}

emvl2Ret EmvL2Command::getProcessingOptions(uint8_t* data, uint8_t len) {
	repo.clearApdu();

	repo.apdu.CLA = 0x80;
	repo.apdu.INS = 0xA8;
	repo.apdu.P1 = 0x00;
	repo.apdu.P2 = 0x00;
	repo.apdu.Lc = len;
	repo.apdu.forceData = false;

	if (len == 0xFF)
	{
		repo.apdu.forceData = true;
	}

	repo.apdu.sdata = data;
	repo.apdu.Le = 0x00;

	emvl2Ret rv = performCommand4(&repo.apdu);
	return rv;
}

emvl2Ret EmvL2Command::select(uint8_t* data, uint8_t len, uint8_t p2) {
	repo.clearApdu();

	repo.apdu.CLA = 0x00;
	repo.apdu.INS = 0xA4;
	repo.apdu.P1 = 0x04;
	repo.apdu.P2 = p2;
	repo.apdu.forceData = false;

	repo.apdu.Lc = len;
	repo.apdu.Le = 0x00;
	repo.apdu.sdata = data;

	return performCommand4(&repo.apdu);
}

emvl2Ret EmvL2Command::readRecord(uint8_t sfi, uint8_t idx) {
	repo.clearApdu();

	repo.apdu.CLA = 0x00;
	repo.apdu.INS = 0xB2;
	repo.apdu.P1 = idx;
	repo.apdu.P2 = sfi + 4;
	repo.apdu.Lc = 0xFF;
	repo.apdu.Le = 0x00;
	repo.apdu.forceData = false;

	return performCommand2(&repo.apdu);
}

emvl2Ret EmvL2Command::internalAuthenticate(uint8_t* data, uint8_t len) {
	repo.clearApdu();

	repo.apdu.CLA = 0x00;
	repo.apdu.INS = 0x88;
	repo.apdu.P1 = 0x00;
	repo.apdu.P2 = 0x00;
	repo.apdu.Lc = len;
	repo.apdu.forceData = false;

	if (len == 0xFF)
	{
		repo.apdu.forceData = true;
	}

	repo.apdu.sdata = data;
	repo.apdu.Le = 0x00;
	emvl2Ret rv = performCommand4(&repo.apdu);
	return rv;
}

emvl2Ret EmvL2Command::externalAuthenticate() {
	repo.clearApdu();

	repo.apdu.CLA = 0x00;
	repo.apdu.INS = 0x82;
	repo.apdu.P1 = 0x00;
	repo.apdu.P2 = 0x00;

	Tlv* tag91 = repo.getTag(0x91);

	repo.apdu.Lc = tag91->len;
	repo.apdu.sdata = tag91->val.data();

	repo.apdu.Le = 0xFF;
	repo.apdu.forceData = false;

	return performCommand3(&repo.apdu);
}

emvl2Ret EmvL2Command::getData(uint32_t tag) {
	repo.clearApdu();

	uint8_t* data = (uint8_t *) & tag;

	repo.apdu.CLA = 0x80;
	repo.apdu.INS = 0xCA;
	repo.apdu.P1 = data[1];
	repo.apdu.P2 = data[0];
	repo.apdu.Lc = 0xFF;
	repo.apdu.Le = 0x00;
	repo.apdu.forceData = false;

	return performCommand2(&repo.apdu);
}

emvl2Ret EmvL2Command::verify(uint8_t type, uint8_t* data, uint8_t len) {
	repo.clearApdu();

	repo.apdu.CLA = 0x00;
	repo.apdu.INS = 0x20;
	repo.apdu.P1 = 0x00;
	repo.apdu.P2 = type;
	repo.apdu.Lc = len;
	repo.apdu.Le = 0xFF;
	repo.apdu.sdata = data;
	repo.apdu.forceData = false;

	return performCommand3(&repo.apdu);
}

emvl2Ret EmvL2Command::getChallenge() {
	repo.clearApdu();

	repo.apdu.CLA = 0x00;
	repo.apdu.INS = 0x84;
	repo.apdu.P1 = 0x00;
	repo.apdu.P2 = 0x00;
	repo.apdu.Lc = 0xFF;
	repo.apdu.Le = 0x00;
	repo.apdu.forceData = false;

	return performCommand2(&repo.apdu);
}

emvl2Ret EmvL2Command::performCommand1(emvl2Apdu* apdu) {
	return transmit(apdu);
}

emvl2Ret EmvL2Command::performCommand2(emvl2Apdu* apdu) {
	int index = 0;
	uint8_t readData[APDUBUFFERLEN];
	int readDataLen = 0;
	uint8_t i = 0;

	while (i <= 15)
	{
		if (transmit(apdu) != success)
		{
			return cardCommError;
		}

		if ((apdu->SW1 == 0x6C))
		{
			memcpy(&readData[index], apdu->rdata, apdu->rlen);
			index += apdu->rlen;
			readDataLen += apdu->rlen;
			apdu->Lc = 0xFF;
			apdu->Le = apdu->SW2;
		}
		else if ((apdu->SW1 == 0x61))
		{
			memcpy(&readData[index], apdu->rdata, apdu->rlen);
			index += apdu->rlen;
			readDataLen += apdu->rlen;
			apdu->CLA = 0x00;
			apdu->INS = 0xC0;
			apdu->P1 = 0x00;
			apdu->P2 = 0x00;
			apdu->Lc = 0xFF;
			apdu->Le = apdu->SW2;
		}
		else
		{
			return success;
		}
		i++;
	}

	return cardCommError;
}

emvl2Ret EmvL2Command::performCommand3(emvl2Apdu* apdu) {
	uint8_t i = 0;

	while (i <= 15)
	{
		if (transmit(apdu) != success)
		{
			return cardCommError;
		}

		if ((apdu->SW1 == 0x90) && (apdu->SW2 == 0x00))
		{
			return success;
		}
		else if (apdu->rlen - 2 == 1)
		{
			apdu->CLA = 0xFF;
			apdu->INS = 0xFF;
		}
		else
		{
			return success;
		}
		i++;
	}

	return cardCommError;
}

emvl2Ret EmvL2Command::performCommand4(emvl2Apdu* apdu) {
	int index = 0;
	uint8_t readData[APDUBUFFERLEN];
	int readDataLen = 0;
	uint8_t i = 0;

	while (i <= 15)
	{
		if (transmit(apdu) != success)
		{
			return cardCommError;
		}
		if ((apdu->SW1 == 0x90) && (apdu->SW2 == 0x00))
		{
			return success;
		}
		else if ((apdu->SW1 == 0x6C))
		{
			memcpy(&readData[index], apdu->rdata, apdu->rlen);
			index += apdu->rlen;
			readDataLen += apdu->rlen;
			apdu->Lc = 0xFF;
			apdu->Le = apdu->SW2;
		}
		else if ((apdu->SW1 == 0x61))
		{
			memcpy(&readData[index], apdu->rdata, apdu->rlen);
			index += apdu->rlen;
			readDataLen += apdu->rlen;
			apdu->CLA = 0x00;
			apdu->INS = 0xC0;
			apdu->P1 = 0x00;
			apdu->P2 = 0x00;
			apdu->Lc = 0xFF;
			apdu->Le = apdu->SW2;
		}
		else if ((apdu->SW1 == 0x62) || (apdu->SW1 == 0x63))
		{
			return success;
		}
		else if (apdu->rlen - 2 == 1)
		{
			apdu->CLA = 0xFF;
			apdu->INS = 0xFF;
		}
		else
		{
			return success;
		}
		i++;
	}

	return cardCommError;
}

emvl2Ret EmvL2Command::transmit(emvl2Apdu* apdu) {
	uint8_t commandData[APDUBUFFERLEN + 10] = { 0 };
	uint16_t indexLen = 0;
	uint8_t readData[APDUBUFFERLEN] = { 0 };
	uint32_t readDataLen = APDUBUFFERLEN;

	emvl2Ret rv = failure;

	apdu->SW1 = 0x00;
	apdu->SW2 = 0x00;
	apdu->rlen = 0x00;

	if ((apdu->CLA == 0xFF) && (apdu->INS == 0xFF))
	{
		commandData[indexLen++] = apdu->Lc;
		memcpy(&commandData[indexLen], apdu->sdata, apdu->Lc);
		indexLen += apdu->Lc;
	}
	else
	{
		commandData[indexLen++] = apdu->CLA;
		commandData[indexLen++] = apdu->INS;
		commandData[indexLen++] = apdu->P1;
		commandData[indexLen++] = apdu->P2;

		if (apdu->Lc != 0xFF || apdu->forceData)
		{
			commandData[indexLen++] = apdu->Lc;
			memcpy(&commandData[indexLen], apdu->sdata, apdu->Lc);
			indexLen += apdu->Lc;
		}

		if (device->cardProtocol() == 1 && apdu->Le != 0xFF)
		{
			commandData[indexLen++] = apdu->Le;
		}

		if (device->cardProtocol() == 0 && apdu->Le != 0)
		{
			if (apdu->Lc == 0xFF)
			{
				commandData[indexLen++] = apdu->Le;
			}
		}
	}

	rv = device->cardSendReceive(commandData, indexLen, readData, &readDataLen);
	if (rv != success)
	{
		return cardCommError;
	}

	if (readDataLen > APDUBUFFERLEN)
	{
		return cardDataLenError;
	}

	apdu->rlen = (int)readDataLen;
	apdu->SW1 = readData[readDataLen - 2];
	apdu->SW2 = readData[readDataLen - 1];
	memcpy(apdu->rdata, readData, apdu->rlen);

	return success;
}
