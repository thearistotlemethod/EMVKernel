#include "emvl2TermActionAnalysis.h"

EmvL2TermActionAnalysis::EmvL2TermActionAnalysis(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()), 
command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()) {
}

EmvL2TermActionAnalysis::~EmvL2TermActionAnalysis() {

}

uint8_t EmvL2TermActionAnalysis::perform(uint8_t* termDecision) {	
	uint8_t* tvr = repo.getTag(0x95)->val.data();

	Tlv* tag8C = repo.getTag(0x8C);
	tcHash(tag8C->val.data(), tag8C->len);

	if (repo.isTagFlag(0x95, MERCHFORCEDONLINE))
	{
		*termDecision = ARQC;
		return success;
	}

	uint8_t iacDenial[5] = { 0 };
	if (repo.isTagExist(0x9F0E))
		memcpy(iacDenial, repo.getTag(0x9F0E)->val.data(), 5);

	uint8_t tacDenial[5] = {0};
	if (repo.isTagExist(0xDF8121))
		memcpy(tacDenial, repo.getTag(0xDF8121)->val.data(), sizeof(tacDenial));

	for (int i = 0; i < 5; i++)
	{
		uint8_t cBit = 0x80;

		do
		{
			if ((tvr[i] & cBit) == cBit)
			{
				if ((tacDenial[i] & cBit) || (iacDenial[i] & cBit))
				{
					repo.setTag(0x8A, (uint8_t*)"Z1", 2);
					*termDecision = AAC;
					return success;
				}
			}
			cBit >>= 1;
		} while (cBit != 0);
	}

	uint8_t ttype = repo.getTag(0x9F35)->val.data()[0];
	if (ttype == 0x11 || ttype == 0x14 || ttype == 0x21 || ttype == 0x24)
	{
		*termDecision = ARQC;
		return success;
	}
	
	uint8_t iacOnline[5] = { 0 };
	if (repo.isTagExist(0x9F0F))
		memcpy(iacOnline, repo.getTag(0x9F0F)->val.data(), sizeof(iacOnline));

	uint8_t tacOnline[5] = { 0 };
	if (!repo.isTagExist(0xDF8122))
		memcpy(tacOnline, repo.getTag(0xDF8122)->val.data(), sizeof(tacOnline));

	for (int i = 0; i < 5; i++)
	{
		uint8_t cBit = 0x80;

		do
		{
			if (tvr[i] & cBit)
			{
				if ((tacOnline[i] & cBit) || (iacOnline[i] & cBit))
				{
					*termDecision = ARQC;
					return success;
				}
			}
			cBit >>= 1;
		} while (cBit != 0);
	}

	repo.setTag(0x8A, (uint8_t *)"Y1", 2);
	*termDecision = TC;
	return success;
}

void EmvL2TermActionAnalysis::tcHash(uint8_t* data, uint8_t len)
{	
	bool defaultTdol = false;

	Tlv* tag97 = repo.getTag(0x97);
	Tlv* tagDF8B13 = repo.getTag(0xDF8B13);

	int tdolLen = 0;
	if (tag97) {
		tdolLen = tag97->len;
	}
	else if(tagDF8B13) {
		tdolLen = tagDF8B13->len;
		defaultTdol = true;
	}

	int idx = 0;
	while (idx < len)
	{
		if (data[idx] == 0x9F || data[idx] == 0x5F ||
			data[idx] == 0xDF || data[idx] == 0xBF)
		{
			idx += 3;
		}
		else
		{
			if (data[idx] == 0x98 && tdolLen != 0 && defaultTdol)
			{
				repo.isTagFlag(0x95, DEFAULTTDOLUSED);
				break;
			}

			idx += 2;
		}
	}
}