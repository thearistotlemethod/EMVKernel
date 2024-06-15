#include "emvl2Repo.h"
#include "emvl2Util.h"
#include <iterator>

EmvL2Repo* EmvL2Repo::instance = NULL;

EmvL2Repo& EmvL2Repo::getInstance() {
	if (!instance) {
		instance = new EmvL2Repo();
	}
	return *instance;
}

EmvL2Repo::EmvL2Repo() {
	device = NULL;
}

EmvL2Repo::~EmvL2Repo() {

}

emvl2Ret EmvL2Repo::init(IDevice* device) {
	this->device = device;
	return success;
}

int EmvL2Repo::addCaKey(emvl2CAKey key) {
	this->caKeys.push_back(key);
	return success;
}

int EmvL2Repo::addAidPrms(emvl2AIDPrms prms) {
	this->aidPrms.push_back(prms);
	return success;
}

void EmvL2Repo::clearCaKeys() {
	this->caKeys.clear();
}

void EmvL2Repo::clearAidPrms() {
	this->aidPrms.clear();
}

void EmvL2Repo::clearApdu() {
	memset(&apdu, 0, sizeof(emvl2Apdu));
}

int EmvL2Repo::searchCAKeys(void)
{
	uint32_t dataLen = 0;
	uint16_t index = 0;
	int ret = success;

	Tlv* tag8F = getTag(0x8F);
	Tlv* tag84 = getTag(0x84);
	if (!tag8F || !tag84)
	{
		setTagFlag(0x95, ICCDATAMISSING);
		ret = failure;
	}

	if (failure != ret)
	{
		ret = failure;
		for (const emvl2CAKey& cakey : caKeys) {
			if (!memcmp(cakey.ucRid, tag84->val.data(), 5) && cakey.ucPKIndex == tag8F->val.data()[0]) {
				ret = success;
				activeCAKey = (emvl2CAKey*) & cakey;
				break;
			}
		}
	}

	if (failure != ret)
	{
		setTag(0x9F22, tag8F->val.data(), 1);
	}

	return ret;
}

void EmvL2Repo::clearCardTags() {
	tags.erase(0x42);
	tags.erase(0x4F);
	tags.erase(0x50);
	tags.erase(0x57);
	tags.erase(0x58);
	tags.erase(0x5A);
	tags.erase(0x5F20);
	tags.erase(0x5F24);
	tags.erase(0x5F25);
	tags.erase(0x5F28);
	tags.erase(0x5F2D);
	tags.erase(0x5F30);
	tags.erase(0x5F34);
	tags.erase(0x5F55);
	tags.erase(0x5F56);
	tags.erase(0x6F);
	tags.erase(0x71);
	tags.erase(0x72);
	tags.erase(0x73);
	tags.erase(0x82);
	tags.erase(0x84);
	tags.erase(0x87);
	tags.erase(0x88);
	tags.erase(0x8C);
	tags.erase(0x8D);
	tags.erase(0x8E);
	tags.erase(0x8F);
	tags.erase(0x90);
	tags.erase(0x91);
	tags.erase(0x92);
	tags.erase(0x93);
	tags.erase(0x94);
	tags.erase(0x97);
	tags.erase(0x9F05);
	tags.erase(0x9F07);
	tags.erase(0x9F08);
	tags.erase(0x9F0B);
	tags.erase(0x9F0D);
	tags.erase(0x9F0E);
	tags.erase(0x9F0F);
	tags.erase(0x9F10);
	tags.erase(0x9F11);
	tags.erase(0x9F12);
	tags.erase(0x9F13);
	tags.erase(0x9F14);
	tags.erase(0x9F17);
	tags.erase(0x9F19);
	tags.erase(0x9F1F);
	tags.erase(0x9F20);
	tags.erase(0x9F23);
	tags.erase(0x9F24);
	tags.erase(0x9F25);
	tags.erase(0x9F26);
	tags.erase(0x9F27);
	tags.erase(0x9F2D);
	tags.erase(0x9F2E);
	tags.erase(0x9F2F);
	tags.erase(0x9F30);
	tags.erase(0x9F32);
	tags.erase(0x9F36);
	tags.erase(0x9F38);
	tags.erase(0x9F3B);
	tags.erase(0x9F43);
	tags.erase(0x9F42);
	tags.erase(0x9F44);
	tags.erase(0x9F45);
	tags.erase(0x9F46);
	tags.erase(0x9F47);
	tags.erase(0x9F48);
	tags.erase(0x9F49);
	tags.erase(0x9F4A);
	tags.erase(0x9F4B);
	tags.erase(0x9F4C);
	tags.erase(0x9F4D);
	tags.erase(0xBF0C);
}

int EmvL2Repo::parseTags(uint8_t* buff, int buffLen) {
	int idx = 0, len, iIssScriptLen;
	uint8_t ucLenOfLen = 0, lenOfTag = 0;
	uint8_t indexOfTag = 0;
	uint32_t valueOfTag = 0;

	while (idx < buffLen)
	{
		if ((buff[idx] == 0) || (buff[idx] == 0xFF))
		{
			idx++;
			continue;
		}

		if (buff[idx] == 0x71)
		{
			if (buff[idx + 1] != 0x81) {
				iIssScriptLen = buff[idx + 1];

				script71.reserve(iIssScriptLen + 2);
				std::copy(&buff[idx], &buff[idx + iIssScriptLen + 2], std::back_inserter(script71));

				idx += iIssScriptLen + 2;

			}
			else {
				iIssScriptLen = buff[idx + 2];

				script71.reserve(iIssScriptLen + 3);
				std::copy(&buff[idx], &buff[idx + iIssScriptLen + 3], std::back_inserter(script71));

				idx += iIssScriptLen + 3;
			}

			continue;
		}

		if (buff[idx] == 0x72)
		{
			if (buff[idx + 1] != 0x81) {
				iIssScriptLen = buff[idx + 1];

				script72.reserve(iIssScriptLen + 2);
				std::copy(&buff[idx], &buff[idx + iIssScriptLen + 2], std::back_inserter(script72));

				idx += iIssScriptLen + 2;

			}
			else {
				iIssScriptLen = buff[idx + 2];

				script72.reserve(iIssScriptLen + 3);
				std::copy(&buff[idx], &buff[idx + iIssScriptLen + 3], std::back_inserter(script72));

				idx += iIssScriptLen + 3;
			}

			continue;
		}

		if (buff[idx] == 0xA5)
		{
			idx++;
			len = parseLen(&buff[idx], &ucLenOfLen);
			idx += ucLenOfLen;
			continue;
		}

		lenOfTag = parseTag(&buff[idx], &valueOfTag);
		idx += lenOfTag;

		len = parseLen(&buff[idx], &ucLenOfLen);
		idx += ucLenOfLen;

		setTag(valueOfTag, &buff[idx], len);
		idx += len;
	}

	if (idx > buffLen)
	{
		return emvDataFormatError;
	}

	return success;
}

Tlv* EmvL2Repo::setTag(uint32_t tag, uint8_t* src, uint8_t len) {
	tags.erase(tag);
	if (src != NULL) {
		if (len == 0) {
			uint8_t lenLen = 0;
			len = parseLen(src, &lenLen);

			uint8_t* data = src + lenLen;

			Tlv tlv = { tag, len, vector<uint8_t>(data, data + len) };
			tags[tag] = tlv;
		}
		else {
			Tlv tlv = { tag, len, vector<uint8_t>(src, src + len) };
			tags[tag] = tlv;
		}
	}
	else {
		if (len > 0) {
			Tlv tlv = { tag, len, vector<uint8_t>(len) };
			tags[tag] = tlv;
		}
	}

	return getTag(tag);
}

Tlv* EmvL2Repo::getTag(uint32_t tag) {
	auto it = tags.find(tag);
	if (it != tags.end()) {
		return &tags[tag];
	}

	return NULL;
}

int EmvL2Repo::getTagFormat(uint32_t tag) {
	switch (tag) {
	case 0x73:
	case 0x9A:
	case 0x9C:
	case 0x5F24:
	case 0x5F25:
	case 0x5F28:
	case 0x5F2A:
	case 0x5F30:
	case 0x5F34:
	case 0x5F36:
	case 0x9F01:
	case 0x9F02:
	case 0x9F03:
	case 0x9F15:
	case 0x9F1A:
	case 0x9F21:
	case 0x9F35:
	case 0x9F39:
	case 0x9F3B:
	case 0x9F3C:
	case 0x9F3D:
	case 0x9F41:
	case 0x9F42:
	case 0x9F43:
	case 0x9F44:
	case 0x9F4D:
		return FNUM;
	}

	switch (tag) {
	case 0x58:
	case 0x5A:
	case 0x9F20:
		return FCNM;
	}

	return FNULL;
}

bool EmvL2Repo::isTagExist(uint32_t tag) {
	auto it = tags.find(tag);
	if (it == tags.end())
		return false;
	return true;
}

void EmvL2Repo::setTagFlag(uint32_t tag, int flag) {
	int i, j;
	uint8_t* data = getTagDatas(tag, &i, &j, flag);

	if(data)
		data[i] |= j;
}

bool EmvL2Repo::isTagFlag(uint32_t tag, int flag) {
	int i, j;
	uint8_t* data = getTagDatas(tag, &i, &j, flag);

	if (data)
		return (data[i] & j) ? true : false;

	return false;
}

uint32_t EmvL2Repo::parseLen(uint8_t *data, uint8_t* lenLen)
{
	uint32_t len, lLen;

	if ((data[0] & 0x80) == 0x80)
	{
		lLen = data[0] & 0x7F;
		len = EmvL2Util::getInstance().bin2Int(&data[1], lLen);
		(lLen)++;
	}
	else
	{
		lLen = 1;
		len = (uint32_t)data[0];
	}

	if (lenLen)
		*lenLen = lLen;

	return len;
}

uint32_t EmvL2Repo::parseTag(uint8_t* data, uint8_t* tagLen)
{
	uint8_t tLen = 1;
	uint32_t tag = 0;
	int i = 0;

	tag = data[i];
	if ((data[i++] & 0x1F) == 0x1F) {
		tLen++;
		tag = (tag << 8) | data[i];
		while ((data[i++] & 0x80) == 0x80) {
			tLen++;
			tag = (tag << 8) | data[i];
		}
	}

	if (tagLen)
		*tagLen = tLen;

	return tag;
}

void EmvL2Repo::nextTag(uint8_t* data, int* idx)
{
	int   len;
	uint8_t ch = 0x00, ucLenOfLen;
	int index = (*idx);

	while (ch == 0x00)
	{
		ch = data[index++];
	}

	if (index - 1 > *idx)
	{
		(*idx) = index - 1;
	}
	else
	{
		ch = data[*idx] & 0x1F;

		if (ch == 0x1F)
		{
			(*idx)++;

			while ((data[*idx] & 0xF0) == 0xF0 || (data[*idx] & 0x81) == 0x81)
			{
				(*idx)++;
			}
		}

		(*idx)++;
		len = parseLen(&data[*idx], &ucLenOfLen);
		(*idx) += (int)ucLenOfLen;
		(*idx) += len;
	}
}

uint8_t* EmvL2Repo::getTagDatas(uint32_t tag, int *i, int *j, int flag) {
	if (i && j) {
		*i = flag / 0x100;
		*j = flag - (*i) * 0x100;
	}

	Tlv* tagData = getTag(tag);
	if (tagData) {
		return tagData->val.data();
	}
		
	return NULL;
}

uint8_t EmvL2Repo::parseTag(uint8_t* buff, uint32_t* val)
{
	uint8_t TAGLen = 1;
	uint32_t value = 0;
	int i = 0;

	value = buff[i];
	if ((buff[i++] & 0x1F) == 0x1F) {
		TAGLen++;
		value = (value << 8) | buff[i];
		while ((buff[i++] & 0x80) == 0x80) {
			TAGLen++;
			value = (value << 8) | buff[i];
		}
	}

	*val = value;
	return TAGLen;
}

int EmvL2Repo::cardBrand()
{
	int rv = 0;

	auto aid = getTag(0x84)->val.data();
	if (memcmp(aid, "\xA0\x00\x00\x00\x03\x10\x10", 7) == 0)
		rv = BVISA;
	else if (memcmp(aid, "\xA0\x00\x00\x00\x04\x10\x10", 7) == 0)
		rv = BMASTER;
	else if (memcmp(aid, "\xA0\x00\x00\x00\x04\x30\x60", 7) == 0)
		rv = BEUROPAY;
	else if ((memcmp(aid, "\xA0\x00\x00\x00\x65\x10\x10", 7) == 0) || (memcmp(aid, "\xA0\x00\x00\x00\x89\x01\x23", 7) == 0))
		rv = BJCB;

	return rv;
}