#include "emvl2GenAC1.h"
#include "emvl2Command.h"

EmvL2GenAC1::EmvL2GenAC1(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()), 
command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()), secUtil(EmvL2SecUtil::getInstance()) {
}

EmvL2GenAC1::~EmvL2GenAC1() {

}

uint8_t EmvL2GenAC1::perform(uint8_t termDecision, uint8_t* cardDecision) {
	int rv;
	uint8_t cdol[256], cdolData[DOLBUFFERLEN], cdolLen;

	repo.adviceReversal = 0;

	Tlv* tag8C = repo.getTag(0x8C);
	if (!tag8C)
		return failure;

	int len = tag8C->len;
	memcpy(cdol, tag8C->val.data(), len);

	util.collectDolData(cdol, len, cdolData, &cdolLen);
	util.collectDolData(cdol, len, cdolData, &cdolLen);

	repo.transactionHashData.insert(repo.transactionHashData.end(), cdolData, cdolData + cdolLen);

	if (((termDecision == TC) || (termDecision == ARQC)) && (repo.typeOfAuth == ACDA) && ((repo.getTag(0x95)->val.data()[0] & CDAFAILED) != CDAFAILED))
	{
		if ((rv = genAC1WithCDAProccessing(&termDecision, cdolData, cdolLen)) != success)
		{
			if (rv == genSecACWarning)
			{
				*cardDecision = AAC;
				return success;
			}
			else
			{
				return rv;
			}
		}
	}
	else
	{
		if ((rv = genAC1WithoutCDAProccessing(&termDecision, cdolData, cdolLen)) != success)
		{
			return rv;
		}
	}

	return genAC1DecisionProccessing(termDecision, cardDecision);
}

int EmvL2GenAC1::genAC1DecisionProccessing(uint8_t termDecision, uint8_t* cardDecision)
{
	Tlv* tag9F27 = repo.getTag(0x9F27);

	*cardDecision = tag9F27->val.data()[0];
	if (((*cardDecision) & ADVICE) == ADVICE)
	{
		repo.adviceReversal = repo.adviceReversal | 0x01;
	}

	if ((tag9F27->val.data()[0] & 0x03) == SERVICE_NOT_ALLOWED)
	{
		return emvServiceNotAllowed;
	}

	if (termDecision == AAC)
	{
		if (((*cardDecision & 0xC0) == ARQC) || ((*cardDecision & 0xC0) == TC))
		{
			return emvCryptogramTypeError;
		}
	}

	if (termDecision == ARQC)
	{
		if ((*cardDecision & 0xC0) == TC)
		{
			return emvCryptogramTypeError;
		}
	}

	if ((*cardDecision & TC) == TC)
	{
		repo.setTag(0x8A, (uint8_t*)"Y1", 2);
	}
	else
	{
		repo.setTag(0x8A, (uint8_t*)"\x00\x00", 2);
	}

	return success;
}

int EmvL2GenAC1::genAC1WithoutCDAProccessing(uint8_t* termDecision, uint8_t* cdolData, uint8_t cdolLen)
{
	uint8_t sw1, sw2;
	uint8_t lenLen;
	int rv;
	int dataElIndex, dataElIndexPrev, msgIndex = 1;

	rv = command.generateAC(cdolData, cdolLen, *termDecision);
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

	if ((repo.apdu.rdata[0] != 0x80) && (repo.apdu.rdata[0] != 0x77))
	{
		return emvDataFormatError;
	}

	Tlv* tag9F27 = repo.getTag(0x9F27);
	if (!tag9F27) {
		repo.setTag(0x9F27, termDecision, 1);
		tag9F27 = repo.getTag(0x9F27);
	}

	if (repo.apdu.rdata[0] == 0x80)
	{
		if ((rv = secUtil.genACNOCDATemplate80Processing()) != success)
		{
			return rv;
		}

		if ((tag9F27->val.data()[0] & AAR) == AAR)
		{
			return emvCryptogramTypeError;
		}
	}
	else if (repo.apdu.rdata[0] == 0x77)
	{
		repo.parseLen(&repo.apdu.rdata[msgIndex], &lenLen);
		dataElIndex = 1 + lenLen;

		while (dataElIndex < repo.apdu.rlen - 2)
		{
			dataElIndexPrev = dataElIndex;
			repo.nextTag(repo.apdu.rdata, &dataElIndex);

			if ((repo.apdu.rdata[dataElIndexPrev] != 0x9F) || (repo.apdu.rdata[dataElIndexPrev + 1] != 0x4B))
			{
				repo.transactionHashData.insert(repo.transactionHashData.end(), &repo.apdu.rdata[dataElIndexPrev], &repo.apdu.rdata[dataElIndexPrev] + (dataElIndex - dataElIndexPrev));
			}
		}

		if ((rv = secUtil.genACNOCDATemplate77Processing()) != success)
		{
			return rv;
		}

		if ((tag9F27->val.data()[0] & AAR) == AAR)
		{
			return  emvCryptogramTypeError;
		}
	}

	return success;
}

int EmvL2GenAC1::genAC1WithCDAProccessing(uint8_t* termDecision, uint8_t* cdolData, uint8_t cdolLen)
{
	uint8_t sw1, sw2;
	int rv;
	uint8_t cid;
	int  genACTCHashIndex = 0;

	repo.verifyDDAACFail = failure;
	*termDecision = *termDecision + 0x10;

	rv = command.generateAC(cdolData, cdolLen, *termDecision);
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

	if ((repo.apdu.rdata[0] != 0x80) && (repo.apdu.rdata[0] != 0x77))
	{
		return emvDataFormatError;
	}

	if (repo.apdu.rdata[0] == 0x80)
	{
		if ((rv = secUtil.genACCDATemplate80Processing()) != success)
		{
			return rv;
		}

		Tlv* tag9F27 = repo.getTag(0x9F27);
		if ((tag9F27->val.data()[0] & AAR) == AAR)
		{
			return emvCryptogramTypeError;
		}

		if (((tag9F27->val.data()[0] & 0xC0) != AAC) && ((tag9F27->val.data()[0] & AAR) != AAR))
		{
			if ((tag9F27->val.data()[0] & 0xC0) == ARQC)
			{
				repo.performImeediateSecondGenAc = success;
			}
			else
			{
				repo.performImeediateSecondGenAc = failure;
			}

			return genSecACWarning;
		}
	}
	else if (repo.apdu.rdata[0] == 0x77)
	{
		genACTCHashIndex = repo.transactionHashData.size();
		if ((rv = secUtil.genACCDATemplate77Processing(true)) != success)
		{
			return rv;
		}

		Tlv* tag9F27 = repo.getTag(0x9F27);
		if ((tag9F27->val.data()[0] & AAR) == AAR)
		{
			return emvCryptogramTypeError;
		}

		rv = secUtil.verifyDynamicSignAC(PKICCMOD, repo.cdaIccPkModLen, &cid);
		repo.transactionHashData.resize(genACTCHashIndex);

		if (rv == failure)
		{
			repo.setTagFlag(0x95, CDAFAILED);

			if (((cid & 0xC0) != TC) && ((cid & AAR) != AAR) && ((cid & AAR) != 0x00))
			{
				repo.performImeediateSecondGenAc = success;
			}

			repo.verifyDDAACFail = success;
			return genSecACWarning;
		}
	}

	return success;
}