#include "emvl2OfflineDataAuth.h"
#include "emvl2Command.h"

EmvL2OfflineDataAuth::EmvL2OfflineDataAuth(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()), 
command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()), secUtil(EmvL2SecUtil::getInstance()) {
}

EmvL2OfflineDataAuth::~EmvL2OfflineDataAuth() {

}

uint8_t EmvL2OfflineDataAuth::perform() {
	int rv;

	repo.typeOfAuth = ANULL;

	Tlv* tag8F = repo.getTag(0x8F);
	if (tag8F) {
		repo.setTag(0x9F22, tag8F->val.data(), tag8F->len);
	}

	rv = secUtil.determineDataAuthType(&repo.typeOfAuth);
	if (rv != success)
	{
		return rv;
	}

	if (!repo.isTagExist(0x8F))
	{
		if ((repo.isTagFlag(0x82, SDASupported)) || (repo.isTagFlag(0x82, DDASupported)) || (repo.isTagFlag(0x82, CDASupported)))
		{
			repo.setTagFlag(0x95, ICCDATAMISSING);
		}

		if (repo.isTagFlag(0x82, SDASupported))
		{
			repo.setTagFlag(0x95, SDAFAILED);
			repo.setTagFlag(0x9B, OFFAUTHPERFORMED);
		}

		if (repo.isTagFlag(0x82, DDASupported))
		{
			repo.setTagFlag(0x95, DDAFAILED);
			repo.setTagFlag(0x9B, OFFAUTHPERFORMED);
		}

		if (repo.isTagFlag(0x82, CDASupported))
		{
			repo.setTagFlag(0x95, CDAFAILED);
			repo.setTagFlag(0x9B, OFFAUTHPERFORMED);
		}

		return success;
	}

	if (repo.typeOfAuth == ASDA)
	{
		repo.setTagFlag(0x95, SDASELECTED);
		rv = performSDA();
		if (rv != success)
		{
			return rv;
		}
	}
	else if (repo.typeOfAuth == ADDA)
	{
		rv = performDDA();
		if (rv != success)
		{
			return rv;
		}
	}
	else if (repo.typeOfAuth == ACDA)
	{
		rv = performCDA();
		if (rv != success)
		{
			return rv;
		}
	}

	return success;
}

int EmvL2OfflineDataAuth::performCDA()
{
	int len, iExpLen;
	uint8_t issModLen, pkModLen;
	uint8_t exponent[3];
	uint8_t ddolData[DOLBUFFERLEN];

	memset(repo.caPkModulus, 0, sizeof(repo.caPkModulus));
	memset(repo.issPkModulus, 0, sizeof(repo.issPkModulus));
	memset(ddolData, 0, sizeof(ddolData));

	if (!repo.isTagExist(0x95) || !repo.isTagExist(0x9B))
	{
		return emvMissingMandatoryDataError;
	}

	repo.setTagFlag(0x9B, OFFAUTHPERFORMED);
	if (!repo.isTagExist(0x8F))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	if (failure == repo.searchCAKeys())
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	pkModLen = repo.activeCAKey->ucPKModuloLen;
	memcpy(repo.caPkModulus, &repo.activeCAKey->ucPKModulo, pkModLen);
	iExpLen = repo.activeCAKey->ucPKExpLen;
	memcpy(exponent, repo.activeCAKey->ucPKExp, iExpLen);

	if (!repo.isTagExist(0x90))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x9F32))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x9F46))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x9F47))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	Tlv* tag90 = repo.getTag(0x90);

	len = tag90->len;
	if (pkModLen != len)
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	if (failure == secUtil.recoverPubKeyCert(PKCAMOD, pkModLen, exponent,
		iExpLen, len, tag90->val.data(), &issModLen))
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	memcpy(repo.issPkModulus, repo.recPkModulus, issModLen);

	Tlv* tag9F46 = repo.getTag(0x9F46);
	len = tag9F46->len;
	if ((int)issModLen != len)
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	if (failure == secUtil.recoverICCPubKeyCert(issModLen, &repo.cdaIccPkModLen))
	{
		repo.setTagFlag(0x95, CDAFAILED);
		return success;
	}

	return success;
}

int EmvL2OfflineDataAuth::performDDA()
{
	int i, len, iExpLen, rv;
	uint8_t iccModLen, issModLen;
	uint8_t pkModLen;
	uint8_t exponent[3], lenLen, ddolLen;
	uint8_t sw1, sw2;
	uint8_t ddolData[DOLBUFFERLEN];

	memset(repo.caPkModulus, 0, sizeof(repo.caPkModulus));
	memset(repo.issPkModulus, 0, sizeof(repo.issPkModulus));
	memset(ddolData, 0, sizeof(ddolData));

	if (!repo.isTagExist(0x95) || !repo.isTagExist(0x9B))
	{
		return emvMissingMandatoryDataError;
	}

	repo.setTagFlag(0x9B, OFFAUTHPERFORMED);
	if (!repo.isTagExist(0x8F))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	if (failure == repo.searchCAKeys())
	{
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	pkModLen = repo.activeCAKey->ucPKModuloLen;
	memcpy(repo.caPkModulus, &repo.activeCAKey->ucPKModulo, pkModLen);
	iExpLen = repo.activeCAKey->ucPKExpLen;
	memcpy(exponent, repo.activeCAKey->ucPKExp, iExpLen);

	if (!repo.isTagExist(0x90))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x9F32))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x9F46))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x9F47))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	Tlv* tag90 = repo.getTag(0x90);

	len = tag90->len;
	if (pkModLen != len)
	{
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	if (failure == secUtil.recoverPubKeyCert(PKCAMOD, pkModLen, exponent,
		iExpLen, len, tag90->val.data(), &issModLen))
	{
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	memcpy(repo.issPkModulus, repo.recPkModulus, issModLen);

	Tlv* tag9F46 = repo.getTag(0x9F46);

	len = tag9F46->len;
	if (issModLen != len)
	{
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	if (failure == secUtil.recoverICCPubKeyCert(issModLen, &iccModLen))
	{
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	Tlv* tag9F49 = repo.getTag(0x9F49);

	if (!tag9F49)
	{
		Tlv* tagDF8B12 = repo.getTag(0xDF8B12);

		len = tagDF8B12->len;
		if (!len)
		{
			repo.setTagFlag(0x95, ICCDATAMISSING);
			repo.setTagFlag(0x95, DDAFAILED);
			return success;
		}

		for (i = 0; i < len - 1; i++)
		{
			if ((tagDF8B12->val.data()[i] == 0x9F) &&
				(tagDF8B12->val.data()[i + 1] == 0x37))
			{
				break;
			}
		}

		if (i == (len - 1))
		{
			repo.setTagFlag(0x95, DDAFAILED);
			return success;
		}

		util.collectDolData(tagDF8B12->val.data(), len, ddolData, &ddolLen);
	}
	else
	{
		len = tag9F49->len;
		uint8_t* tmpBuff = tag9F49->val.data();
		for (i = 0; i < len - 1; i++)
		{
			if ((tmpBuff[i] == 0x9F) && (tmpBuff[i + 1] == 0x37))
			{
				break;
			}
		}

		if (i == (len - 1))
		{
			repo.setTagFlag(0x95, DDAFAILED);
			return success;
		}

		util.collectDolData(tmpBuff, len, ddolData, &ddolLen);
	}

	if (repo.isTagFlag(0x95, DDAFAILED))
	{
		return success;
	}

	rv = command.internalAuthenticate(ddolData, ddolLen);
	if (rv != success)
	{
		return rv;
	}

	sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

	if ((sw1 != 0x90) || (sw2 != 0x00))
	{
		return cardRejected;
	}

	if (repo.apdu.rdata[0] == 0x80)
	{
		if ((repo.apdu.rdata[1] & 0x80) == 0x80)
		{
			len = repo.parseLen(&repo.apdu.rdata[1], &lenLen);
		}
		else
		{
			lenLen = 1;
			len = repo.apdu.rdata[1];
		}

		if (len != repo.apdu.rlen - 3 - lenLen)
		{
			return emvLenError;
		}

		if (len == 0)
		{
			return emvMissingMandatoryDataError;
		}

		repo.setTag(0x9F4B, &repo.apdu.rdata[1]);
	}
	else if (repo.apdu.rdata[0] == 0x77)
	{
		len = repo.parseLen(&repo.apdu.rdata[1], &lenLen);
		rv = repo.parseTags(&repo.apdu.rdata[1 + lenLen], len);

		if (rv != success)
		{
			return rv;
		}

		if (!repo.isTagExist(0x9F4B))
		{
			return emvMissingMandatoryDataError;
		}
	}
	else
	{
		return emvDataFormatError;
	}

	if (failure == secUtil.verifyDynamicSign(PKICCMOD, iccModLen, ddolData, ddolLen))
	{
		repo.setTagFlag(0x95, DDAFAILED);
		return success;
	}

	return success;
}

int EmvL2OfflineDataAuth::performSDA()
{
	int len, iExpLen;
	uint8_t issModLen, pkModLen;
	uint8_t exponent[3];

	memset(repo.caPkModulus, 0, sizeof(repo.caPkModulus));
	memset(repo.issPkModulus, 0, sizeof(repo.issPkModulus));

	if (!repo.isTagExist(0x95) || !repo.isTagExist(0x9B))
	{
		return emvMissingMandatoryDataError;
	}

	repo.setTagFlag(0x9B, OFFAUTHPERFORMED);

	if (!repo.isTagExist(0x8F))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}

	if (failure == repo.searchCAKeys())
	{
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}

	pkModLen = repo.activeCAKey->ucPKModuloLen;
	memcpy(repo.caPkModulus, &repo.activeCAKey->ucPKModulo, pkModLen);
	iExpLen = repo.activeCAKey->ucPKExpLen;
	memcpy(exponent, repo.activeCAKey->ucPKExp, iExpLen);

	if (!repo.isTagExist(0x90))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x9F32))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}

	if (!repo.isTagExist(0x93))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}

	Tlv* tag90 = repo.getTag(0x90);
	if (!tag90 || pkModLen != tag90->len)
	{
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}
	len = tag90->len;

	if (failure == secUtil.recoverPubKeyCert(PKCAMOD, pkModLen, exponent, iExpLen, len, tag90->val.data(), &issModLen))
	{
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}

	memcpy(repo.issPkModulus, repo.recPkModulus, issModLen);
	if (failure == verifyStaticAppData(PKISSMOD, issModLen))
	{
		repo.setTagFlag(0x95, SDAFAILED);
		return success;
	}

	return success;
}

int EmvL2OfflineDataAuth::verifyStaticAppData(emvl2PkMode type, uint8_t modLen)
{
	int len;
	int ret = success;

	Tlv* tag93 = repo.getTag(0x93);
	len = tag93->len;
	if ((uint8_t)len != modLen)
	{
		ret = failure;
	}
	else if (failure == recoverStaticAppData(type, modLen))
	{
		ret = failure;
	}

	return ret;
}

int EmvL2OfflineDataAuth::recoverStaticAppData(emvl2PkMode type, uint8_t modLen)
{
	int hashIdx = 0, sdataLen;
	uint8_t digest[20];
	uint8_t* hashData;
	uint16_t lenHashData = 0;

	memset(repo.recoveredData, 0, sizeof(repo.recoveredData));

	Tlv* tag9F32 = repo.getTag(0x9F32);
	Tlv* tag93 = repo.getTag(0x93);

	secUtil.rsaEncrypt(type, modLen, tag9F32->val.data(), tag9F32->len, tag93->val.data(), tag93->len);

	if (repo.recoveredData[0] != 0x6A)
	{
		return failure;
	}

	if (repo.recoveredData[1] != 0x03)
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

	lenHashData = 4 + (modLen - 26) + (uint16_t)repo.staticAppData.size();
	hashData = (uint8_t*)malloc(lenHashData);
	if (NULL == hashData)
	{
		return failure;
	}

	repo.setTag(0x9F45, &repo.recoveredData[3], 2);

	memcpy(hashData + hashIdx, repo.recoveredData + 1, 4 + (modLen - 26));
	hashIdx += 4 + (modLen - 26);
	memcpy(hashData + hashIdx, repo.staticAppData.data(), repo.staticAppData.size());
	hashIdx += repo.staticAppData.size();
	
	Tlv* tag9F4A = repo.getTag(0x9F4A);
	if (tag9F4A)
	{
		if ((tag9F4A->val.data()[0] != 0x82) || (tag9F4A->len != 0x01))
		{
			return failure;
		}

		secUtil.prepStaticTagListData(&sdataLen);
		if (sdataLen == 0)
		{
			return failure;
		}
		hashData = (uint8_t*)realloc(hashData, lenHashData + sdataLen);
		if (NULL == hashData)
		{
			return failure;
		}

		memcpy(hashData + hashIdx, repo.sdaTermData, sdataLen);
		hashIdx += sdataLen;
	}

	device.sha1(hashData, hashIdx, digest);
	free(hashData);
	if (memcmp(digest, repo.recoveredData + modLen - 21, sizeof(digest)) != 0)
	{
		return failure;
	}

	return success;
}

