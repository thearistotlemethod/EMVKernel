#include "emvl2SecUtil.h"
#include "emvl2Defs.h"
#include "emvl2Repo.h"

EmvL2SecUtil* EmvL2SecUtil::instance = NULL;

EmvL2SecUtil& EmvL2SecUtil::getInstance() {
	if (!instance) {
		instance = new EmvL2SecUtil();
	}
	return *instance;
}

EmvL2SecUtil::EmvL2SecUtil() : repo(EmvL2Repo::getInstance()), util(EmvL2Util::getInstance()) {
	device = NULL;
}

EmvL2SecUtil::~EmvL2SecUtil() {

}

int EmvL2SecUtil::init(IDevice* device) {
	this->device = device;

	return success;
}

uint8_t EmvL2SecUtil::determineDataAuthType(uint8_t* authType)
{
	if (!repo.isTagExist(0x82) || !repo.isTagExist(0x95) || !repo.isTagExist(0x9B) || !repo.isTagExist(0x9F33))
	{
		return emvMissingMandatoryDataError;
	}

	if (repo.isTagFlag(0x82, CDASupported))
	{
		if (repo.isTagFlag(0x9F33, CDASUPPORTED))
		{
			*authType = ACDA;
			return success;
		}
	}

	if (repo.isTagFlag(0x82, DDASupported))
	{
		if (repo.isTagFlag(0x9F33, DDASUPPORTED))
		{
			*authType = ADDA;
			return success;
		}
	}

	if (repo.isTagFlag(0x82, SDASupported))
	{
		if (repo.isTagFlag(0x9F33, SDASUPPORTED))
		{
			*authType = ASDA;
			return success;
		}
	}

	repo.setTagFlag(0x95, OFFAUTHNOTPERFORMED);
	*authType = ANULL;
	return success;
}

int EmvL2SecUtil::recoverPubKeyCert(emvl2PkMode pkType, uint8_t modLen, uint8_t* exponent, int exlen, uint8_t certLen, uint8_t* certData, uint8_t* issPkModLen)
{
	uint8_t   issIdNum[4];
	uint8_t   expDate[2];
	uint8_t   digest[20], year[2];
	int   hashIdx, intExpDate, intYear, len = 0;
	emvl2DateTime dateTime;
	int ret;
	int   index;
	uint8_t  issId[32], card[32];
	uint8_t* hashData;

	memset(repo.recoveredData, 0, sizeof(repo.recoveredData));

	rsaEncrypt(pkType, modLen, exponent, exlen, certData, certLen);
	if (repo.recoveredData[0] != 0x6A)
	{
		return failure;
	}

	if (repo.recoveredData[1] != 0x02)
	{
		return failure;
	}

	if (repo.recoveredData[11] != 0x01)
	{
		return failure;
	}

	if (repo.recoveredData[12] != 0x01)
	{
		return failure;
	}

	if (repo.recoveredData[modLen - 1] != 0xBC)
	{
		return failure;
	}

	memcpy(repo.recPkModulus, repo.recoveredData + 15, modLen - 36);
	*issPkModLen = repo.recoveredData[13];

	Tlv* tag92 = repo.getTag(0x92);
	if (*issPkModLen > modLen - 36)
	{		
		if (tag92)
		{
			len = tag92->len;
			memcpy(repo.recPkModulus + modLen - 36, tag92->val.data(), tag92->len);
		}
		else
		{
			repo.setTagFlag(0x95, ICCDATAMISSING);
			return failure;
		}
	}

	Tlv* tag9F32 = repo.getTag(0x9F32);
	if (!repo.isTagExist(0x9F32))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		return failure;
	}

	hashData = (uint8_t*)malloc(14 + (modLen - 36) + len + tag9F32->len);
	if (NULL == hashData)
	{
		return failure;
	}

	hashIdx = 0;
	memcpy(hashData, repo.recoveredData + 1, 14 + modLen - 36);
	hashIdx += 14 + modLen - 36;

	if (tag92)
	{
		memcpy(hashData + hashIdx, tag92->val.data(), tag92->len);
		hashIdx += len;
	}	

	memcpy(hashData + hashIdx, tag9F32->val.data(), tag9F32->len);
	hashIdx += tag9F32->len;
	device->sha1(hashData, hashIdx, digest);
	free(hashData);

	if (memcmp(digest, &repo.recoveredData[modLen - 21], sizeof(digest)) != 0)
	{
		return failure;
	}

	memcpy(issIdNum, repo.recoveredData + 2, 4);
	util.bcd2Str(issIdNum, 4, issId);
	util.bcd2Str(repo.getTag(0x5A)->val.data(), 4, card);

	if (memcmp(issId, card, 3) != 0)
	{
		return failure;
	}

	index = 3;
	while (index < 8)
	{
		if ((issId[index] != 'F') && (issId[index] != card[index]))
		{
			return failure;
		}
		index++;
	}

	ret = device->getDateTime(&dateTime);
	if (success != ret)
	{
		return failure;
	}

	year[0] = util.byte2Bcd(util.adjustYear(dateTime.year));
	year[1] = util.byte2Bcd(dateTime.month);
	memcpy(expDate, repo.recoveredData + 6, 2);

	if (expDate[0] > 0x12)
	{
		return failure;
	}

	if (year[0] < 0x50)
	{
		intYear = year[0] + 0x100;
	}
	else
	{
		intYear = (int)year[0];
	}

	if (expDate[1] < 0x50)
	{
		intExpDate = expDate[1] + 0x100;
	}
	else
	{
		intExpDate = (int)expDate[1];
	}

	if (intExpDate < intYear)
	{
		return failure;
	}
	else if (intExpDate == intYear)
	{
		if (expDate[0] < year[1])
		{
			return failure;
		}
	}

	return success;
}

void EmvL2SecUtil::rsaEncrypt(emvl2PkMode pkType, uint8_t modLen, uint8_t* exponent, uint8_t exlen, uint8_t* data, uint8_t dataLength)
{
	uint8_t* pucN = NULL;

	switch (pkType)
	{
	case PKCAMOD:
		pucN = repo.caPkModulus;
		break;

	case PKICCMOD:
		pucN = repo.iccPkModulus;
		break;

	case PKISSMOD:
		pucN = repo.issPkModulus;
		break;

	case PKPINMOD:
		pucN = repo.iccPinPkModulus;
		break;

	default:
		break;
	}

	if (NULL != pucN)
	{
		device->rsaDecrypt(pucN, modLen, exponent, exlen, data, dataLength, repo.recoveredData);
	}
}

int EmvL2SecUtil::recoverICCPINEncPubKeyCert(uint8_t modLen, uint8_t* iccPinModLen)
{
	uint8_t  expDate[2], year[2];
	int  len, hashIdx, intYear, intExpDate, index;
	uint8_t  issIdNum[4], digest[20];
	uint8_t card[32], issId[32];
	emvl2DateTime dateTime;
	int ret;
	uint8_t* hashData;

	Tlv* tag9F32 = repo.getTag(0x9F32);
	Tlv* tag9F2D = repo.getTag(0x9F2D);

	memset(repo.recoveredData, 0, sizeof(repo.recoveredData));
	rsaEncrypt(PKISSMOD, modLen, tag9F32->val.data(), tag9F32->len
		, tag9F2D->val.data(), tag9F2D->len);

	if (repo.recoveredData[0] != 0x6A)
	{
		return failure;
	}

	if (repo.recoveredData[1] != 0x04)
	{
		return failure;
	}

	if (repo.recoveredData[18] != 0x01)
	{
		return failure;
	}

	if (repo.recoveredData[modLen - 1] != 0xBC)
	{
		return failure;
	}

	if (repo.cardBrand() == BVISA)
	{
		memcpy(repo.iccPinPkModulus, repo.recoveredData + 21, modLen - 42);
		*iccPinModLen = repo.recoveredData[19];
	}
	else
	{
		memcpy(repo.iccPinPkModulus, repo.recoveredData + 21, modLen - 42);
		*iccPinModLen = repo.recoveredData[19];
	}

	memcpy(issIdNum, repo.recoveredData + 2, 4);
	util.bcd2Str(issIdNum, 4, issId);
	util.bcd2Str(repo.getTag(0x5A)->val.data(), 4, card);

	if (memcmp(issId, card, 3) != 0)
	{
		return failure;
	}

	index = 3;
	while (index < 8)
	{
		if ((issId[index] != 'F') && (issId[index] != card[index]))
		{
			return failure;
		}
		index++;
	}

	len = 0;
	Tlv* tag9F27 = repo.getTag(0x9F2F);	
	if (tag9F27)
	{
		len = tag9F27->len;
		memcpy(repo.iccPinPkModulus + modLen - 42, tag9F27->val.data(), len);
	}
	else
	{		
		if (modLen - 42 < *iccPinModLen)
		{
			repo.setTagFlag(0x95, CDAFAILED);
			repo.setTagFlag(0x95, ICCDATAMISSING);
		}
	}

	Tlv* tag9F2E = repo.getTag(0x9F2E);

	hashData = (uint8_t*)malloc(20 + modLen - 42 + len + tag9F2E->len);
	if (NULL == hashData)
	{
		return failure;
	}

	hashIdx = 0;
	memcpy(hashData, repo.recoveredData + 1, 20 + modLen - 42);
	hashIdx += 20 + modLen - 42;

	if (len != 0)
	{
		memcpy(hashData + hashIdx, tag9F27->val.data(), len);
		hashIdx += len;
	}

	memcpy(hashData + hashIdx, tag9F2E->val.data(), tag9F2E->len);
	hashIdx += tag9F2E->len;

	device->sha1(hashData, hashIdx, digest);
	free(hashData);
	if (memcmp(digest, &repo.recoveredData[modLen - 21], 20) != 0)
	{
		return failure;
	}

	Tlv* tag5A = repo.getTag(0x5A);
	if (memcmp(repo.recoveredData + 2, tag5A->val.data(), tag5A->len) != 0)
	{
		return failure;
	}

	ret = device->getDateTime(&dateTime);
	if (success != ret)
	{
		return failure;
	}

	year[0] = util.byte2Bcd(util.adjustYear(dateTime.year) - 1);
	year[1] = util.byte2Bcd(dateTime.month);
	memcpy(expDate, repo.recoveredData + 12, 2);

	if (expDate[0] > 0x12)
	{
		return failure;
	}

	intYear = year[0] + 0x100;
	intExpDate = expDate[1] + 0x100;

	if (intExpDate < intYear)
	{
		return failure;
	}
	else if (intExpDate > intYear)
	{
		return success;
	}
	else
	{
		if (expDate[0] < year[1])
		{
			return failure;
		}
	}

	return success;	
}

int EmvL2SecUtil::recoverICCPubKeyCert(uint8_t modLen, uint8_t* iccPinModLen)
{
	uint8_t expDate[2], year[2], digest[20];
	int hashIdx, intYear, intExpDate, len, intSdaLen;
	emvl2DateTime dateTime;
	int ret;
	uint8_t* hashData;
	uint16_t lenHashData = 0;

	memset(repo.recoveredData, 0, sizeof(repo.recoveredData));
	memset(repo.iccPkModulus, 0, sizeof(repo.iccPkModulus));

	Tlv* tag9F46 = repo.getTag(0x9F46);
	Tlv* tag9F32 = repo.getTag(0x9F32);

	len = tag9F46->len;
	rsaEncrypt(PKISSMOD, modLen, tag9F32->val.data(), tag9F32->len, tag9F46->val.data(), len);

	if (repo.recoveredData[0] != 0x6A)
	{
		return failure;
	}

	if (repo.recoveredData[1] != 0x04)
	{
		return failure;
	}

	if (repo.recoveredData[18] != 0x01)
	{
		return failure;
	}

	if (repo.recoveredData[modLen - 1] != 0xBC)
	{
		return failure;
	}

	repo.setTag(0x9F45, &repo.recoveredData[3], 2);

	memcpy(repo.iccPkModulus, repo.recoveredData + 21, modLen - 42);
	*iccPinModLen = repo.recoveredData[19];

	len = 0;
	Tlv* tag9F48 = repo.getTag(0x9F48);	
	if (tag9F48)
	{
		len = tag9F48->len;
		memcpy(repo.iccPkModulus + modLen - 42, tag9F48->val.data(), len);
	}
	else
	{
		if ((modLen - 42) < *iccPinModLen)
		{
			repo.setTagFlag(0x95, ICCDATAMISSING);
			return failure;
		}
	}

	Tlv* tag9F47 = repo.getTag(0x9F47);

	lenHashData = 20 + modLen - 42 +
		len +
		tag9F47->len +
		(uint16_t)repo.staticAppData.size();
	hashData = (uint8_t*)malloc(lenHashData);
	if (NULL == hashData)
	{
		return failure;
	}

	hashIdx = 0;
	memcpy(hashData, repo.recoveredData + 1, 20 + modLen - 42);
	hashIdx += 20 + modLen - 42;

	if (len != 0)
	{
		memcpy(hashData + hashIdx, tag9F48->val.data(), len);
		hashIdx += len;
	}

	memcpy(hashData + hashIdx, tag9F47->val.data(), tag9F47->len);
	hashIdx += tag9F47->len;
	memcpy(hashData + hashIdx, repo.staticAppData.data(), repo.staticAppData.size());
	hashIdx += repo.staticAppData.size();

	Tlv* tag9F4A = repo.getTag(0x9F4A);
	if (tag9F4A)
	{
		if ((tag9F4A->len != 1) || (tag9F4A->val.data()[0] != 0x82))
		{
			return failure;
		}

		prepStaticTagListData(&intSdaLen);
		if (intSdaLen == 0)
		{
			return failure;
		}

		hashData = (uint8_t*)realloc(hashData, lenHashData + intSdaLen);
		if (NULL == hashData)
		{
			return failure;
		}
		memcpy(hashData + hashIdx, repo.sdaTermData, intSdaLen);
		hashIdx += intSdaLen;
	}

	device->sha1(hashData, hashIdx, digest);
	free(hashData);
	if (memcmp(digest, &repo.recoveredData[modLen - 21], 20) != 0)
	{
		return failure;
	}

	Tlv* tag5A = repo.getTag(0x5A);
	if (memcmp(repo.recoveredData + 2, tag5A->val.data(), tag5A->len) != 0)
	{
		return failure;
	}

	ret = device->getDateTime(&dateTime);
	if (success != ret)
	{
		return failure;
	}

	year[0] = util.byte2Bcd(util.adjustYear(dateTime.year));
	year[1] = util.byte2Bcd(dateTime.month);
	memcpy(expDate, repo.recoveredData + 12, 2);

	if (expDate[0] > 0x12)
	{
		return failure;
	}

	if (year[0] < 0x50)
	{
		intYear = year[0] + 0x100;
	}
	else
	{
		intYear = (int)year[0];
	}

	if (expDate[1] < 0x50)
	{
		intExpDate = expDate[1] + 0x100;
	}
	else
	{
		intExpDate = (int)expDate[1];
	}

	if (intExpDate < intYear)
	{
		return failure;
	}
	else if (intExpDate > intYear)
	{
		return success;
	}
	else
	{
		if (expDate[0] < year[1])
		{
			return failure;
		}
	}

	return success;
}

void EmvL2SecUtil::prepStaticTagListData(int* lstlen)
{
	int index, msgindex = 0, len, intStlLen = 0;
	uint8_t* staticTags;
	uint32_t tag = 0;

	Tlv* tag9F4A = repo.getTag(0x9F4A);
	if (!tag9F4A)
	{
		if (lstlen)
			*lstlen = msgindex;
	}
	else
	{
		intStlLen = tag9F4A->len;
		staticTags = tag9F4A->val.data();
		index = 0;
		msgindex = 0;

		do
		{
			if ((staticTags[index] == 0x9F) || (staticTags[index] == 0x5F))
			{
				tag = staticTags[index] << 8 | staticTags[index + 1];
				index += 2;
			}
			else
			{
				tag = staticTags[index++];
			}

			if (repo.isTagExist(tag)) {
				len = repo.getTag(tag)->len;
				memcpy(&repo.sdaTermData[msgindex], repo.getTag(tag)->val.data(), len);
				msgindex += len;
			}
		} while (index < intStlLen);

		if (lstlen)
			*lstlen = msgindex;
	}
}

int EmvL2SecUtil::verifyDynamicSign(emvl2PkMode pkType, uint8_t modLen, uint8_t* data, uint8_t dataLength)
{
	int hashIdx = 0, len;
	uint8_t digest[20];
	uint8_t* hashData;

	memset(repo.recoveredData, 0, sizeof(repo.recoveredData));

	Tlv* tag9F4B = repo.getTag(0x9F4B);
	if (!tag9F4B || modLen != (uint8_t)tag9F4B->len)
	{
		return failure;
	}
	len = tag9F4B->len;

	rsaEncrypt(pkType, modLen, repo.getTag(0x9F47)->val.data(), repo.getTag(0x9F47)->len, tag9F4B->val.data(), len);
	if (repo.recoveredData[0] != 0x6A)
	{
		return failure;
	}

	if (repo.recoveredData[1] != 0x05)
	{
		return failure;
	}

	if (repo.recoveredData[2] != 0x01)
	{
		return failure;
	}

	if (repo.recoveredData[modLen - 1] != 0xBC)
	{
		return failure;
	}

	repo.setTag(0x9F4C, repo.recoveredData + 5, repo.recoveredData[4]);
	repo.setTag(0x9F45);

	hashData = (uint8_t*)malloc(3 + (modLen - 25) + dataLength);
	if (NULL == hashData)
	{
		return failure;
	}

	memcpy(hashData + hashIdx, repo.recoveredData + 1, 3 + (modLen - 25));
	hashIdx += 3 + (modLen - 25);
	memcpy(hashData + hashIdx, data, dataLength);
	hashIdx += dataLength;
	device->sha1(hashData, hashIdx, digest);
	free(hashData);
	if (memcmp(digest, repo.recoveredData + modLen - 21, sizeof(digest)) != 0)
	{
		return failure;
	}

	return success;
}

int EmvL2SecUtil::genACCDATemplate80Processing()
{
	uint8_t lenLen;
	int len, msgIdx = 1;

	len = repo.parseLen(&repo.apdu.rdata[msgIdx], &lenLen);
	msgIdx += lenLen;

	if (len != (repo.apdu.rlen - 3 - lenLen))
	{
		return emvLenError;
	}

	repo.setTag(0x9F27, &repo.apdu.rdata[msgIdx++], 1);
	repo.setTag(0x9F36, &repo.apdu.rdata[msgIdx], 2);
	msgIdx += 2;
	repo.setTag(0x9F26, &repo.apdu.rdata[msgIdx], 8);
	msgIdx += 8;

	if ((len - 11) > 0)
	{
		repo.setTag(0x9F10, &repo.apdu.rdata[msgIdx], len - 11);
		msgIdx += len - 11;
	}

	if ((repo.getTag(0x9F27)->val.data()[0] == 0) && (repo.getTag(0x9F36)->val.data()[0] == 0) && (repo.getTag(0x9F36)->val.data()[1] == 0) && (repo.getTag(0x9F26)->val.data()[0] == 0))
	{
		return emvLenError;
	}

	return success;
}

int EmvL2SecUtil::genACCDATemplate77Processing(bool isCda)
{
	uint8_t lenLen;
	int rv, len, dataIdx, prevDataIdx, msgIdx = 1;

	len = repo.parseLen(&repo.apdu.rdata[msgIdx], &lenLen);
	if (repo.apdu.rlen != len + lenLen + 3)
	{
		return emvLenError;
	}

	dataIdx = 1 + lenLen;
	while (dataIdx < repo.apdu.rlen - 2)
	{
		prevDataIdx = dataIdx;
		repo.nextTag(repo.apdu.rdata, &dataIdx);

		if ((repo.apdu.rdata[prevDataIdx] != 0x9F) || (repo.apdu.rdata[prevDataIdx + 1] != 0x4B))
		{
			repo.transactionHashData.insert(repo.transactionHashData.end(), &repo.apdu.rdata[prevDataIdx], &repo.apdu.rdata[prevDataIdx] + (dataIdx - prevDataIdx));
		}
	}

	repo.setTag(0x9F20);
	repo.setTag(0x9F36);
	repo.setTag(0x9F4B);

	rv = repo.parseTags(&repo.apdu.rdata[1 + lenLen], len);
	if (rv != success)
	{
		return rv;
	}

	if (!repo.isTagExist(0x9F27) || !repo.isTagExist(0x9F36))
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return emvMissingMandatoryDataError;
	}

	if (((repo.getTag(0x9F27)->val.data()[0] & 0xC0) != AAC) && isCda && !repo.isTagExist(0x9F4B))
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return emvMissingMandatoryDataError;
	}

	if (!isCda && !repo.isTagExist(0x9F26))
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return emvMissingMandatoryDataError;
	}

	return success;
}

int EmvL2SecUtil::verifyDynamicSignAC(emvl2PkMode pkType, uint8_t modLen, uint8_t* cid)
{
	int hashIdx = 0, len;
	uint8_t digest[20];
	uint8_t dynData[PUBKEYMODULUSLEN];
	uint8_t* hashData;
	uint8_t* tcHashData;

	memset(repo.recoveredData, 0, sizeof(repo.recoveredData));

	*cid = repo.getTag(0x9F27)->val.data()[0];

	Tlv* tag9F4B = repo.getTag(0x9F4B);	
	if (!tag9F4B || modLen != (uint8_t)tag9F4B->len)
	{
		return failure;
	}
	len = tag9F4B->len;

	Tlv* tag9F47 = repo.getTag(0x9F47);
	rsaEncrypt(pkType, modLen, tag9F47->val.data(), tag9F47->len, tag9F4B->val.data(), len);
	if (repo.recoveredData[0] != 0x6A)
	{
		return failure;
	}

	if (repo.recoveredData[1] != 0x05)
	{
		return failure;
	}

	if (repo.recoveredData[2] != 0x01)
	{

		return failure;
	}

	if (repo.recoveredData[modLen - 1] != 0xBC)
	{
		return failure;
	}

	dynData[0] = repo.recoveredData[3];
	memcpy(&dynData[1], repo.recoveredData + 4, repo.recoveredData[3]);

	repo.setTag(0x9F4C, &dynData[2], dynData[1]);
	repo.setTag(0x9F26, &dynData[3 + dynData[1]], 8);

	*cid = dynData[2 + dynData[1]];

	hashData = (uint8_t*)malloc(3 + (modLen - 25) + repo.getTag(0x9F37)->len);
	if (NULL == hashData)
	{
		return failure;
	}

	memcpy(hashData + hashIdx, repo.recoveredData + 1, 3 + (modLen - 25));
	hashIdx += 3 + (modLen - 25);

	Tlv* tag9F37 = repo.getTag(0x9F37);

	memcpy(hashData + hashIdx, tag9F37->val.data(), tag9F37->len);
	hashIdx += tag9F37->len;
	device->sha1(hashData, hashIdx, digest);
	free(hashData);
	if (memcmp(digest, repo.recoveredData + modLen - 21, sizeof(digest)) != 0)
	{
		return failure;
	}

	tcHashData = (uint8_t*)malloc(repo.transactionHashData.size());
	if (NULL == tcHashData)
	{
		return failure;
	}
	memcpy(tcHashData, repo.transactionHashData.data(), repo.transactionHashData.size());
	device->sha1(tcHashData, repo.transactionHashData.size(), digest);

	if (memcmp(digest, &dynData[11 + dynData[1]], sizeof(digest)) != 0)
	{
		free(tcHashData);
		return failure;
	}
	free(tcHashData);

	if (repo.getTag(0x9F27)->val.data()[0] != *cid)
	{
		return failure;
	}

	return success;
}

int EmvL2SecUtil::genACNOCDATemplate80Processing()
{
	uint8_t lenLen;
	int len, msgIdx = 1;

	if (repo.apdu.rdata[1] < 11)
	{
		return emvMissingMandatoryDataError;
	}

	len = repo.parseLen(&repo.apdu.rdata[msgIdx], &lenLen);
	msgIdx += lenLen;

	if (len != (repo.apdu.rlen - 3 - lenLen))
	{
		return emvLenError;
	}

	repo.setTag(0x9F27, &repo.apdu.rdata[msgIdx++], 1);
	repo.setTag(0x9F36, &repo.apdu.rdata[msgIdx], 2);
	msgIdx += 2;
	repo.setTag(0x9F26, &repo.apdu.rdata[msgIdx], 8);
	msgIdx += 8;

	if ((len - 11) > 0)
	{
		repo.setTag(0x9F10, &repo.apdu.rdata[msgIdx], len - 11);
		msgIdx += len - 11;
	}
	
	if ((repo.getTag(0x9F27)->val.data()[0] == 0) && (repo.getTag(0x9F36)->val.data()[0] == 0) && (repo.getTag(0x9F36)->val.data()[1] == 0) && (repo.getTag(0x9F26)->val.data()[0] == 0))
	{
		return emvLenError;
	}

	return success;
}

int EmvL2SecUtil::genACNOCDATemplate77Processing()
{
	uint8_t lenLen;
	int rv, len, msgIdx = 1;

	len = repo.parseLen(&repo.apdu.rdata[msgIdx], &lenLen);
	if (repo.apdu.rlen != len + lenLen + 3)
	{
		return emvLenError;
	}

	repo.setTag(0x9F27);
	repo.setTag(0x9F36);
	repo.setTag(0x9F26);

	rv = repo.parseTags(&repo.apdu.rdata[1 + lenLen], len);
	if (rv != success)
	{
		return rv;
	}

	if (!repo.isTagExist(0x9F27) || !repo.isTagExist(0x9F36) || !repo.isTagExist(0x9F26))
	{
		return emvMissingMandatoryDataError;
	}

	return success;
}