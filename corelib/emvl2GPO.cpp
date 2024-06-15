#include "emvl2GPO.h"

#define SWAPUINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))

EmvL2GPO::EmvL2GPO(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()),
command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()), secUtil(EmvL2SecUtil::getInstance()) {
}

EmvL2GPO::~EmvL2GPO() {

}

uint8_t EmvL2GPO::perform(uint8_t ttype, uint8_t atype, const char* amt, const char* oamt) {
	uint8_t pdolData[DOLBUFFERLEN];
	uint8_t pdolDataLen = 0;
	int nRet;

	repo.staticAppData.clear();
	repo.transactionHashData.clear();

	if ((nRet = initizalizeTerminalTags(ttype, atype, amt, oamt)) != success)
	{
		return nRet;
	}

	if ((nRet = prepPDOL(pdolData, &pdolDataLen)) != success)
	{
		return nRet;
	}

	nRet = command.getProcessingOptions(pdolData, pdolDataLen);
	if (nRet != success)
	{
		return nRet;
	}

	if ((nRet = processGPOResponse()) != success)
	{
		return nRet;
	}

	repo.setTag(0x9F34, (uint8_t*)"\x3F\x00\x00", 3);
	return success;
}

int EmvL2GPO::initizalizeTerminalTags(uint8_t ttype, uint8_t atype, const char* amt, const char* oamt)
{
	int nRet = 0;
	uint8_t bamt[15] = { 0 };
	uint8_t boamt[15] = { 0 };
	
	clearNonAppSelectionTags();

	util.str2Bcd((uint8_t*)amt, (uint16_t)strlen(amt), bamt, 6);
	util.str2Bcd((uint8_t*)oamt, (uint16_t)strlen(oamt), boamt, 6);

	if ((nRet = setAmountTags(ttype, bamt, boamt)) != success)
	{
		return nRet;
	}

	fillDynamicTags();

	repo.setTag(0x5F57, &atype, 1);
	repo.setTag(0x9C, &ttype, 1);
	repo.setTag(0x95, NULL, 5);
	repo.setTag(0x9B, NULL, 2);
	repo.setTag(0x8A, NULL, 2);

	return success;
}

void EmvL2GPO::clearNonAppSelectionTags()
{
	repo.setTag(0x42);
	repo.setTag(0x57);
	repo.setTag(0x58);
	repo.setTag(0x5A);
	repo.setTag(0x6F);
	repo.setTag(0x71);
	repo.setTag(0x72);
	repo.setTag(0x73);
	repo.setTag(0x82);
	repo.setTag(0x88);
	repo.setTag(0x8C);
	repo.setTag(0x8D);
	repo.setTag(0x8E);
	repo.setTag(0x8F);
	repo.setTag(0x90);
	repo.setTag(0x91);
	repo.setTag(0x92);
	repo.setTag(0x93);
	repo.setTag(0x94);
	repo.setTag(0x97);
	repo.setTag(0x5F20);
	repo.setTag(0x5F24);
	repo.setTag(0x5F25);
	repo.setTag(0x5F28);
	repo.setTag(0x5F30);
	repo.setTag(0x5F34);
	repo.setTag(0x5F55);
	repo.setTag(0x5F56);
	repo.setTag(0x9F05);
	repo.setTag(0x9F07);
	repo.setTag(0x9F08);
	repo.setTag(0x9F0B);
	repo.setTag(0x9F0D);
	repo.setTag(0x9F0E);
	repo.setTag(0x9F0F);
	repo.setTag(0x9F10);
	repo.setTag(0x9F13);
	repo.setTag(0x9F14);
	repo.setTag(0x9F17);
	repo.setTag(0x9F19);
	repo.setTag(0x9F1F);
	repo.setTag(0x9F20);
	repo.setTag(0x9F23);
	repo.setTag(0x9F24);
	repo.setTag(0x9F25);
	repo.setTag(0x9F26);
	repo.setTag(0x9F27);
	repo.setTag(0x9F2D);
	repo.setTag(0x9F2E);
	repo.setTag(0x9F2F);
	repo.setTag(0x9F32);
	repo.setTag(0x9F36);
	repo.setTag(0x9F3B);
	repo.setTag(0x9F42);
	repo.setTag(0x9F43);
	repo.setTag(0x9F44);
	repo.setTag(0x9F45);
	repo.setTag(0x9F46);
	repo.setTag(0x9F47);
	repo.setTag(0x9F48);
	repo.setTag(0x9F49);
	repo.setTag(0x9F4A);
	repo.setTag(0x9F4B);
	repo.setTag(0x9F4C);
	repo.setTag(0x9F4D);
}

int EmvL2GPO::setAmountTags(uint8_t ttype, uint8_t* bamt, uint8_t* boamt)
{
	uint32_t  authAmt = 0, authAmtOther = 0;
	uint8_t  bcdAmt[6], otherAmt[13];
	char amt[15] = { 0 }, oamt[15] = { 0 }, trnAmt[13] = { 0 };

	util.bcd2Str(bamt, 6, (uint8_t *)amt);
	util.bcd2Str(boamt, 6, (uint8_t*)oamt);

	if (ttype == TRNCASHBACK)
	{
		sprintf(trnAmt, "%012d", atoi(amt) + atoi(oamt));
	}
	else
	{
		strcpy((char *)trnAmt, amt);
	}

	if (ttype != 0x09)
	{
		strcpy((char *)oamt, "0");
	}

	if (util.str2Bcd((uint8_t*)trnAmt, (uint16_t)strlen((char *)trnAmt), bcdAmt, 6) == NULL)
	{
		return amountError;
	}

	if (trnAmt[0] == '0' && trnAmt[1] == '0')
	{
		if (strspn(trnAmt, "0123456789") != strlen(trnAmt)) {
			return amountError;
		}

		authAmt = SWAPUINT32(atoi(trnAmt));
	}

	if (util.str2Bcd((uint8_t *)oamt, (uint16_t)strlen(oamt), otherAmt, 6) == NULL)
	{
		return amountError;
	}

	if (strlen(oamt) <= 10)
	{
		if (strspn(oamt, "0123456789") != strlen(oamt)) {
			return amountError;
		}

		authAmtOther = SWAPUINT32(atoi(oamt));
	}

	repo.setTag(0x9F02, bcdAmt, 6);
	repo.setTag(0x9F03, otherAmt, 6);
	repo.setTag(0x81, (uint8_t*) & authAmt, 4);
	repo.setTag(0x9F04, (uint8_t*) & authAmtOther, 4);
	return success;

}

void EmvL2GPO::fillDynamicTags()
{
	uint8_t UN[4];
	int ret;
	emvl2DateTime dateTime;

	ret = device.getDateTime(&dateTime);
	if (success == ret)
	{
		uint8_t tmpBuff[16];
		tmpBuff[0] = (uint8_t)util.byte2Bcd(dateTime.hour);
		tmpBuff[1] = (uint8_t)util.byte2Bcd(dateTime.minute);
		tmpBuff[2] = (uint8_t)util.byte2Bcd(dateTime.second);
		tmpBuff[3] = (uint8_t)util.byte2Bcd(util.adjustYear(dateTime.year));
		tmpBuff[4] = (uint8_t)util.byte2Bcd(dateTime.month);
		tmpBuff[5] = (uint8_t)util.byte2Bcd(dateTime.day);

		repo.setTag(0x9F21, tmpBuff, 3);
		repo.setTag(0x9A, &tmpBuff[3], 3);

		ret = device.genRand(UN, sizeof(UN));
		if (success == ret)
		{
			repo.setTag(0x9F37, UN, sizeof(UN));
		}
	}
}

int EmvL2GPO::prepPDOL(uint8_t* pdolData, uint8_t* pdolLen)
{
	int iPdolLen = 0;
	uint8_t counterPDOL = 2;
	uint8_t tempPDOLData[DOLBUFFERLEN];
	int len = 0;
	uint8_t* pucPDOL = NULL;

	Tlv* tag9F38 = repo.getTag(0x9F38);
	if (tag9F38) {
		len = tag9F38->len;
		pucPDOL = tag9F38->val.data();
	}

	iPdolLen = len;
	pdolData[0] = 0x83;

	if (iPdolLen == 0)
	{
		pdolData[1] = 0x00;
	}
	else
	{
		util.collectDolData(pucPDOL, iPdolLen, tempPDOLData, pdolLen);
		if ((*pdolLen & 0x80) == 0x80)
		{
			pdolData[1] = 0x81;
			pdolData[2] = *pdolLen;
			memcpy(&pdolData[3], tempPDOLData, *pdolLen);
			(*pdolLen)++;
			counterPDOL = 3;
		}
		else
		{
			pdolData[1] = *pdolLen;
			memcpy(&pdolData[2], tempPDOLData, *pdolLen);
		}
	}

	*pdolLen += 2;

	repo.transactionHashData.insert(repo.transactionHashData.end(), &pdolData[counterPDOL], &pdolData[counterPDOL] + (*pdolLen - counterPDOL));
	return success;
}

int EmvL2GPO::processGPOResponse()
{
	int len, iMsgIndex = 0, nRet = 0, i;
	uint8_t   lenLen, sw1, sw2;

	sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

	if ((sw1 == 0x69) && (sw2 == 0x85))
	{
		return emvSelectAppRetry;
	}

	if ((sw1 != 0x90) || (sw2 != 0x00))
	{
		return cardRejected;
	}

	while ((repo.apdu.rdata[iMsgIndex] == 0) || (repo.apdu.rdata[iMsgIndex] == 0xFF))
	{
		iMsgIndex++;
	}

	if (repo.apdu.rdata[iMsgIndex] == 0x80)
	{
		iMsgIndex++;

		if ((repo.apdu.rdata[iMsgIndex] & 0x80) == 0x80)
		{
			len = repo.parseLen(&repo.apdu.rdata[iMsgIndex], &lenLen);
			iMsgIndex += lenLen;
		}
		else
		{
			lenLen = 1;
			len = repo.apdu.rdata[iMsgIndex++];
		}

		if (len != repo.apdu.rlen - 3 - lenLen)
		{
			return emvLenError;
		}

		repo.setTag(0x82, repo.apdu.rdata + iMsgIndex, 2);
		iMsgIndex += 2;

		if (((len - 2) % 4) != 0)
		{
			return emvDataFormatError;
		}

		for (i = iMsgIndex; i < (len - 2); i = i + 4)
		{
			if (repo.apdu.rdata[i] == 0)
			{
				return emvDataFormatError;
			}
		}

		repo.setTag(0x94, repo.apdu.rdata + iMsgIndex, len - 2);
		iMsgIndex += len - 2;
	}
	else if (repo.apdu.rdata[iMsgIndex] == 0x77)
	{
		iMsgIndex++;

		if ((repo.apdu.rdata[iMsgIndex] & 0x80) == 0x80)
		{
			lenLen = repo.apdu.rdata[iMsgIndex] & 0x7F;
			len = util.bin2Int(&repo.apdu.rdata[iMsgIndex + 1], lenLen);
			iMsgIndex += lenLen + 1;
		}
		else
		{
			len = repo.apdu.rdata[iMsgIndex++];
		}

		nRet = repo.parseTags(&repo.apdu.rdata[iMsgIndex], len);
		if (nRet != success)
		{
			return nRet;
		}

		if (!repo.isTagExist(0x82))
		{
			return aipNotFound;
		}

		if (!repo.isTagExist(0x94))
		{
			return aflNotFound;
		}
	}
	else
	{
		return emvDataFormatError;
	}

	return success;
}