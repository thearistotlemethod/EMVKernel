#include "emvl2AppSelection.h"

#define PSERESPONSE         0
#define ADFRESPONSE         2

EmvL2AppSelection::EmvL2AppSelection(IDevice& device) : device(device),repo(EmvL2Repo::getInstance()), command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()) {
}

EmvL2AppSelection::~EmvL2AppSelection() {

}

uint8_t EmvL2AppSelection::perform(){
	vector<string> aidlist;

	for(const auto prm: repo.aidPrms){
		if (prm.aid[0] == 0x00) {
			repo.parseTags(prm.data, prm.len);
		}
		else {
			char aidStr[32] = {0};
			util.bcd2Str(prm.aid, prm.aidLen, (uint8_t *)aidStr);
			aidlist.push_back(string(aidStr));
		}
	}

	int rv = applyPseSelection(aidlist);
	if (candList.size() == 0)
	{
		rv = applyLstSelection(aidlist);
		if (rv != success)
		{
			return rv;
		}

		if (candList.size() == 0)
		{
			return noMatchingApp;
		}
	}

	return finalSelect(0);
}

uint8_t EmvL2AppSelection::finalSelect(int idx)
{
	repo.clearCardTags();

	for (size_t i = 0; i < repo.aidPrms.size(); i++) {
		emvl2AIDPrms prm = repo.aidPrms[i];
		if (prm.aid[0] == 0x00) {
			repo.parseTags(prm.data, prm.len);
		}
		else if(!memcmp(prm.aid, candList[idx]->tag9F06.val.data(), prm.aidLen)) {
			repo.parseTags(prm.data, prm.len);
			break;
		}
	}

	int rv = command.select(candList[idx]->tag9F06.val.data(), candList[idx]->tag9F06.len);
	if (rv != success)
	{
		return rv;
	}

	uint8_t sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	uint8_t sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

	if ((sw1 == 0x90) && (sw2 == 0x00))
	{
		uint8_t lenLen = 0;
		int len = repo.parseLen(&repo.apdu.rdata[1], &lenLen);
		rv = repo.parseTags(&repo.apdu.rdata[1 + lenLen], len);
		if (rv != success)
		{
			return rv;
		}

		repo.setTag(0x9F06, candList[idx]->tag9F06.val.data(), candList[idx]->tag9F06.len);
		return success;
	}

	return failure;
}

uint8_t EmvL2AppSelection::applyPseSelection(vector<string> aidlist)
{
	const string pseDfName = "1PAY.SYS.DDF01";
	uint8_t rv = failure;

	candList.clear();
	repo.clearCardTags();
	rv = this->command.select((uint8_t *)pseDfName.data(), (uint8_t)pseDfName.length());
	if (rv != success)
	{
		return rv;
	}

	uint8_t lenLen = 0;
	int len = repo.parseLen(&repo.apdu.rdata[1], &lenLen);
	rv = repo.parseTags(&repo.apdu.rdata[1 + lenLen], len);
	if (rv != success)
	{
		return rv;
	}

	int sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	int sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

	if ((sw1 != 0x90) || (sw2 != 0x00))
	{
		if ((sw1 == 0x6A) && (sw2 == 0x81))
		{
			return cardRejected;
		}
		return pseNotSupportedByCard;
	}

	uint8_t sfi = repo.getTag(0x88)->val.data()[0];
	if ((sfi > 10) || (sfi == 0))
	{
		return pseNotSupportedByCard;
	}

	int ucRecordNo = 0;
	while (true) {
		ucRecordNo++;
		rv = this->command.readRecord(sfi << 3, ucRecordNo);
		if (rv != success)
		{
			return rv;
		}

		sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
		sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

		if ((sw1 == 0x6A) && (sw2 == 0x83))
		{
			if (ucRecordNo == 1)
			{
				return pseNotSupportedByCard;
			}

			return success;
		}
		else if ((sw1 == 0x00) && (sw2 == 0x00))
		{
			return cardRejected;
		}
		else if ((sw1 != 0x90) || (sw2 != 0x00))
		{
			return pseNotSupportedByCard;
		}

		rv = readPseDir(aidlist, repo.apdu.rdata, repo.apdu.rlen - 2);
		if (rv != success)
			return rv;
	}
}

uint8_t EmvL2AppSelection::readPseDir(vector<string> aidlist, uint8_t* data, int dataLen) {
	int idx = 0, rv = 0, offset = 0;
	uint8_t lenLen = 0;
	uint32_t len = 0;

	while (true) {
		if (data[idx++] != 0x70)
		{
			return emvDataFormatError;
		}

		len = repo.parseLen(&data[idx], &lenLen);
		idx += lenLen;

		if ((len + idx) > (uint32_t)dataLen)
		{
			return emvDataFormatError;
		}

		if (len == 0)
		{
			return emvDataFormatError;
		}

		if (data[idx] != 0x61)
		{
			while ((idx < dataLen) && (data[idx] != 0x61))
			{
				repo.nextTag(data, &idx);
			}

			if (idx == dataLen)
			{
				return success;
			}

			if (idx >= dataLen)
			{
				return emvDataFormatError;
			}
		}

		idx++;

		len = repo.parseLen(&data[idx], &lenLen);
		idx += lenLen;
		offset = idx;
		int tmpIdx = idx;

		while ((idx < dataLen) && (data[idx] != 0x9D) && (data[idx] != 0x4F))
		{
			repo.nextTag(data, &idx);
		}

		if (idx >= dataLen || (data[idx] == 0x4F && idx >= (int)(offset + len)))
		{
			return emvDataFormatError;
		}

		if (data[idx] == 0x9D)
		{
			return emvDataFormatError;
		}
		else
		{
			repo.clearCardTags();

			idx = tmpIdx;
			rv = repo.parseTags(&data[idx], len);
			if (rv != success)
			{
				return pseNotSupportedByCard;
			}

			if (!repo.isTagExist(0x50))
			{
				return emvMissingMandatoryDataError;
			}

			for (const auto aidStr : aidlist)
			{
				uint8_t aid[32];
				int aidLen = 0;
				aidLen = aidStr.length() / 2;
				memcpy(aid, util.hexStr2ByteArray(aidStr.data()), aidLen);

				if (memcmp(repo.getTag(0x4F)->val.data(), aid, aidLen) == 0)
				{
					addToList();
					break;
				}
			}

			idx += len;

			if (idx == dataLen)
			{
				return success;
			}
			else if (idx > dataLen)
			{
				return emvDataFormatError;
			}
		}
	}
}

uint8_t EmvL2AppSelection::applyLstSelection(vector<string> aidlist)
{
	uint8_t aid[32] = {0}, rv = failure;

	candList.clear();

	for(const auto aidStr: aidlist)
	{
		repo.clearCardTags();
		memset(aid, 0, sizeof(aid));
		int aidLen = aidStr.length() / 2;
		memcpy(aid, util.hexStr2ByteArray(aidStr.data()), aidLen);

		rv = this->command.select(aid, aidLen);
		if (rv != success)
		{
			return rv;
		}

		uint8_t lenLen = 0;
		int len = repo.parseLen(&repo.apdu.rdata[1], &lenLen);
		rv = repo.parseTags(&repo.apdu.rdata[1 + lenLen], len);
		if (rv != success)
		{
			return rv;
		}

		uint8_t sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
		uint8_t sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

		if ((sw1 == 0x6A) && (sw2 == 0x81))
		{
			if (candList[0]->tag84.len == 0)
			{
				return cardBlocked;
			}
		}
		else if ((sw1 == 0x90) && (sw2 == 0x00))
		{
			addToList(aid, aidLen);
		}
	}

	return success;
}

uint8_t EmvL2AppSelection::addToList(uint8_t* aid, int aidLen)
{
	emvl2AidInfo* cand = (emvl2AidInfo*)malloc(sizeof(emvl2AidInfo));
	if (cand == NULL) {
		return failure;
	}
	candList.push_back(cand);
	memset(cand, 0, sizeof(emvl2AidInfo));

	repo.setTag(0x9F06, aid, aidLen);

	if (repo.getTag(0x9F06)) {
		cand->tag9F06.len = repo.getTag(0x9F06)->len;
		cand->tag9F06.val = repo.getTag(0x9F06)->val;
	}

	if (repo.getTag(0x84)) {
		cand->tag84.len = repo.getTag(0x84)->len;
		cand->tag84.val = repo.getTag(0x84)->val;
	}

	if (repo.getTag(0x4F)) {
		cand->tag4F.len = repo.getTag(0x4F)->len;
		cand->tag4F.val = repo.getTag(0x4F)->val;
	}

	if (repo.getTag(0x50)) {
		cand->tag50.len = repo.getTag(0x50)->len;
		cand->tag50.val = repo.getTag(0x50)->val;
	}

	if (repo.getTag(0x87)) {
		cand->tag87.len = repo.getTag(0x87)->len;
		cand->tag87.val = repo.getTag(0x87)->val;
	}

	if (repo.getTag(0x9F38)) {
		cand->tag9F38.len = repo.getTag(0x9F38)->len;
		cand->tag9F38.val = repo.getTag(0x9F38)->val;
	}

	if (repo.getTag(0x5F2D)) {
		cand->tag5F2D.len = repo.getTag(0x5F2D)->len;
		cand->tag5F2D.val = repo.getTag(0x5F2D)->val;
	}

	if (repo.getTag(0x9F11)) {
		cand->tag9F11.len = repo.getTag(0x9F11)->len;
		cand->tag9F11.val = repo.getTag(0x9F11)->val;
	}

	if (repo.getTag(0x9F12)) {
		cand->tag9F12.len = repo.getTag(0x9F12)->len;
		cand->tag9F12.val = repo.getTag(0x9F12)->val;
	}

	if (repo.getTag(0xBF0C)) {
		cand->tagBF0C.len = repo.getTag(0xBF0C)->len;
		cand->tagBF0C.val = repo.getTag(0xBF0C)->val;
	}

	if (repo.getTag(0x5F55)) {
		cand->tag5F55.len = repo.getTag(0x5F55)->len;
		cand->tag5F55.val = repo.getTag(0x5F55)->val;
	}

	if (repo.getTag(0x42)) {
		cand->tag42.len = repo.getTag(0x42)->len;
		cand->tag42.val = repo.getTag(0x42)->val;
	}

	return success;
}

uint8_t EmvL2AppSelection::addToList()
{
	Tlv* tag84 = repo.getTag(0x84);
	if (tag84) {
		return addToList(tag84->val.data(), tag84->len);
	}

	Tlv* tag4F = repo.getTag(0x4F);
	if (tag4F) {
		return addToList(tag4F->val.data(), tag4F->len);
	}

	return failure;
}




