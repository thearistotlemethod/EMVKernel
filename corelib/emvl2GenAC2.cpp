#include "emvl2GenAC2.h"

EmvL2GenAC2::EmvL2GenAC2(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()), 
command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()), secUtil(EmvL2SecUtil::getInstance()) {
}

EmvL2GenAC2::~EmvL2GenAC2() {

}

uint8_t EmvL2GenAC2::perform(bool isHostReject, uint8_t* decision, uint8_t* adviceReversal) {
	return completion(isHostReject, decision, adviceReversal);
}

int EmvL2GenAC2::completion(bool isHostReject, uint8_t* cardDecision, uint8_t* adviceReversal)
{
	uint8_t cdolData[DOLBUFFERLEN];
	uint8_t* authRespCode = NULL;
	uint8_t cdolLen;
	uint8_t cid = 0;
	uint8_t termDecision = AAC, cdol[256];
	int rv;
	uint8_t i = 0;

	Tlv* tag9B = repo.getTag(0x9B);
	Tlv* tag8A = repo.getTag(0x8A);
	Tlv* tag9F27 = repo.getTag(0x9F27);
	Tlv* tag8D = repo.getTag(0x8D);
	if (!tag8D || !tag9F27 || !tag8A || !tag9B)
		return failure;

	authRespCode = tag8A->val.data();
	cid = tag9F27->val.data()[0];

	memcpy(cdol, tag8D->val.data(), tag8D->len);

	repo.setTagFlag(0x9B, CARDRISKMNGPERFORMED);

	if (repo.performImeediateSecondGenAc == failure)
	{
		*adviceReversal = repo.adviceReversal;

		if ((cid & 0xC0) == TC)
		{
			return success;
		}

		if ((cid & 0xC0) == AAC)
		{
			return success;
		}

		if (*cardDecision == AAC)
		{
			return success;
		}

		if (*cardDecision == TC)
		{
			return success;
		}

		if ((cid & 0xC0) == AAR)
		{
			repo.setTag(0x8A, (uint8_t*)"Z2", 2);
		}
		else if (memcmp(authRespCode, "01", 2) == 0)
		{

		}

		if ((cid & 0x03) == SERVICE_NOT_ALLOWED)
		{
			return emvServiceNotAllowed;
		}


		if ((memcmp(authRespCode, "00", 2) == 0) || (memcmp(authRespCode, "08", 2) == 0))
		{
			termDecision = TC;
		}
		else if (memcmp(authRespCode, "01", 2) != 0)
		{
			termDecision = AAC;
		}

		if (isHostReject && ((cid & 0xC0) != AAR))
		{
			termActionAnalysisDefault(&termDecision);
		}
	}
	else
	{
		*adviceReversal = 0;
		termDecision = *cardDecision;
	}

	if (!isHostReject)
	{
		issuerAuthentication();
	}

	if (!isHostReject)
	{
		rv = issuerScriptProcessing71();
		if (rv != success)
		{
			return rv;
		}
	}

	util.collectDolData(tag8D->val.data(), tag8D->len, cdolData, &cdolLen);
	if ((termDecision == TC) && (repo.typeOfAuth == ACDA) && (repo.verifyDDAACFail == failure))
	{
		if ((rv = genAC2WithCDAProccessing(&termDecision, cardDecision, cdolData, cdolLen)) != success)
		{
			return rv;
		}
	}
	else
	{
		if ((rv = genAC2WithoutCDAProccessing(&termDecision, cardDecision, cdolData, cdolLen)) != success)
		{
			return rv;
		}
	}

	if ((tag9F27->val.data()[0] & 0x03) == SERVICE_NOT_ALLOWED)
	{
		return emvServiceNotAllowed;
	}

	rv = issuerScriptProcessing72();
	if (rv != success)
	{
		return rv;
	}

	genAC2DecisionProccessing(isHostReject, &termDecision, cardDecision, adviceReversal);
	return success;
}

void EmvL2GenAC2::termActionAnalysisDefault(uint8_t* termDecision)
{
	uint8_t* tvr = repo.getTag(0x95)->val.data();
	uint8_t tacDefault[5];
	uint8_t iacDefault[5];
	uint8_t ucCheckBit = 0x80;
	int endLoop = failure;
	int i;

	Tlv* tag9F0D = repo.getTag(0x9F0D);
	if (!tag9F0D)
	{
		memset(iacDefault, 0xFF, sizeof(iacDefault));
	}
	else
	{
		memcpy(iacDefault, tag9F0D->val.data(), sizeof(iacDefault));
	}

	Tlv* tagDF8120 = repo.getTag(0xDF8120);
	if (!tagDF8120)
	{
		memset(tacDefault, 0, sizeof(tacDefault));
		tacDefault[0] = 0xCC;
	}
	else
	{
		memcpy(tacDefault, tagDF8120->val.data(), sizeof(tacDefault));
	}

	for (i = 0; (i < 5) && (failure == endLoop); i++)
	{
		ucCheckBit = 0x80;

		do
		{
			if ((tvr[i] & ucCheckBit) == ucCheckBit)
			{
				if (((tacDefault[i] & ucCheckBit) == ucCheckBit) || ((iacDefault[i] & ucCheckBit) == ucCheckBit))
				{
					endLoop = success;
					break;
				}
			}
			ucCheckBit >>= 1;
		} while (ucCheckBit != 0);
	}

	if (ucCheckBit != 0)
	{
		repo.setTag(0x8A, (uint8_t*)"Z3", 2);
		*termDecision = AAC;
	}
	else
	{
		repo.setTag(0x8A, (uint8_t*)"Y3", 2);
		*termDecision = TC;
	}
}

void EmvL2GenAC2::issuerAuthentication()
{
	int rv;
	uint8_t sw1, sw2;

	if ((repo.isTagFlag(0x82, IAUTHSupported)))
	{
		Tlv* tag91 = repo.getTag(0x91);
		if (tag91)
		{
			rv = command.externalAuthenticate();
			if (rv == success)
			{
				sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
				sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];
				repo.setTagFlag(0x9B, ISSUERAUTHPERFORMED);

				if ((sw1 != 0x90) || (sw2 != 0x00))
				{
					repo.setTagFlag(0x95, ISSUERAUTHFAILED);
				}
			}
		}
	}
}

int EmvL2GenAC2::issuerScriptProcessing71()
{
	uint8_t* issScriptId;
	uint8_t* issScriptCmd;
	uint8_t issScriptCmdLen, lenLen, lenLen9F18, lenLen86;
	uint8_t scriptId[4];
	int formatError;
	uint8_t  replyData[APDUBUFFERLEN];
	uint8_t sw1, sw2, cmdIndex;
	int outLen = APDUBUFFERLEN;
	uint8_t cmdLen;
	int cmdOffset, issScriptIndex = 0, lenIssScript = 0, len = 0, index = 0;
	int i9F18len, rv;
	int iCmdLen = 0;
	int ret;

	g_iTotalScriptMsgLen = 0;

	if (repo.script71.size() == 0)
	{
		return success;
	}

	uint8_t* scriptBuffer = repo.script71.data();
	if (scriptBuffer[0] != 0x71)
	{
		return success;
	}

	Tlv* tagDF8134 = repo.getTag(0xDF8134);
	if (!tagDF8134) {
		tagDF8134 = repo.setTag(0xDF8134, NULL, 128);
	}

	while (scriptBuffer[issScriptIndex] == 0x71)
	{
		memset(scriptId, 0, sizeof(scriptId));
		g_ucCmdSeqNo = 1;
		formatError = failure;
		g_ucScriptIndex++;
		tagDF8134->len = 5 * g_ucScriptIndex;
		cmdOffset = 0;

		if ((scriptBuffer[issScriptIndex + 1] & 0x80) == 0x80)
		{
			lenLen = scriptBuffer[issScriptIndex + 1] & 0x7F;
			lenIssScript = util.bin2Int(&scriptBuffer[issScriptIndex + 2], lenLen);
			lenLen += 1;
		}
		else
		{
			lenLen = 1;
			lenIssScript = scriptBuffer[issScriptIndex + 1];
		}

		g_iTotalScriptMsgLen += (lenIssScript + (lenLen + 1));

		if (g_iTotalScriptMsgLen > 256)
		{
			repo.setTagFlag(0x95, ISSUERSCRIPTFAILED1);
			return success;
		}

		index = issScriptIndex + (lenLen + 1);

		if ((scriptBuffer[index] == 0x9F) && (scriptBuffer[index + 1] == 0x18))
		{
			i9F18len = repo.parseLen(&scriptBuffer[index + 2], &lenLen9F18);
			memcpy(scriptId, &scriptBuffer[index + lenLen + 2], i9F18len);
			repo.nextTag(scriptBuffer, &index);
		}

		while (index < 256)
		{
			if ((index - 2) == (lenIssScript + issScriptIndex))
			{
				break;
			}

			if ((index - 2) == (lenIssScript + issScriptIndex - 6 - lenLen9F18))
			{
				break;
			}

			if ((index - 2) > (lenIssScript + issScriptIndex))
			{
				formatError = success;
				break;
			}

			if (scriptBuffer[index] == 0x86)
			{
				if (scriptBuffer[index + 1] == 0x81) {
					lenLen86 = 2;
				}
				else {
					lenLen86 = 1;
				}
				repo.nextTag(scriptBuffer, &index);
			}
			else
			{
				formatError = success;
				break;
			}
		}

		if (formatError != failure)
		{
			repo.setTagFlag(0x95, ISSUERSCRIPTFAILED1);
			repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);

			issScriptIndex += lenIssScript + 1 + lenLen;
			tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x00;
			memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);
			continue;
		}

		if (((index - (lenLen86 + 1)) != (lenIssScript + issScriptIndex)) && ((index - (lenLen86 + 1)) != (lenIssScript + issScriptIndex - 6 - lenLen9F18)))
		{
			issScriptIndex += lenIssScript + 1 + lenLen;
			continue;
		}

		rv = repo.parseTags(&scriptBuffer[issScriptIndex], lenIssScript + 1 + lenLen);
		issScriptIndex += lenIssScript + 1 + lenLen;

		if (rv != success)
		{
			continue;
		}

		issScriptId = repo.getTag(0x71)->val.data();
		if (issScriptId[0] == 0)
		{
			continue;
		}

		if (issScriptId[0] == 0x9F)
		{
			if (issScriptId[1] != 0x18)
			{
				continue;
			}

			i9F18len = repo.parseLen(&issScriptId[2]);
			if ((i9F18len != 0x04) && (i9F18len != 0x00))
			{
				continue;
			}

			cmdOffset += 3 + i9F18len;
			memcpy(scriptId, issScriptId + 2 + lenLen, i9F18len);
		}

		Tlv* tag71 = repo.getTag(0x71);
		issScriptCmd = &tag71->val.data()[cmdOffset];
		issScriptCmdLen = len - cmdOffset - lenLen;

		cmdIndex = 0;

		do
		{
			if (issScriptCmd[cmdIndex++] != 0x86)
			{
				repo.setTagFlag(0x95, ISSUERSCRIPTFAILED1);
				repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
				break;
			}
			else
			{
				if (issScriptCmd[cmdIndex] == 0x81) {
					cmdLen = issScriptCmd[cmdIndex + 1];
					cmdIndex += 2;
				}
				else {
					cmdLen = issScriptCmd[cmdIndex];
					cmdIndex += 1;
				}
			}

			if ((cmdLen + cmdIndex) > lenIssScript)
			{
				continue;
			}

			iCmdLen = cmdLen;
			ret = device.cardSendReceive((uint8_t*)&issScriptCmd[cmdIndex], (uint32_t)iCmdLen, (uint8_t*)replyData, (uint32_t*)&outLen);

			cmdIndex += cmdLen;

			if (ret != success)
			{
				return cardCommError;
			}
			else
			{
				outLen = 2;
				memcpy(repo.apdu.rdata, replyData, outLen);
				repo.apdu.rlen = outLen;
			}

			if ((cmdLen > 3) && (ret != success))
			{
				return cardCommError;
			}

			sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
			sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

			if ((sw1 != 0x90) && (sw1 != 0x62) && (sw1 != 0x63))
			{
				tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x10;

				if (g_ucCmdSeqNo <= 14)
				{
					tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] |= g_ucCmdSeqNo;
				}
				else
				{
					tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] |= 0x0F;
				}

				memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);
				repo.setTagFlag(0x95, ISSUERSCRIPTFAILED1);
				repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
				break;
			}
			else if ((sw1 == 0x90) && (sw2 == 0x00))
			{
				tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x20;
				memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);
			}
			else
			{
				tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x10;
				memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);
				repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
			}

			g_ucCmdSeqNo++;
		} while (cmdIndex < issScriptCmdLen);

		repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
	}

	return success;
}

int EmvL2GenAC2::issuerScriptProcessing72()
{
	uint8_t* issScriptId;
	uint8_t* issScriptCmd;
	uint8_t issScriptCmdLen, lenLen, lenLen9F18, lenLen86;
	uint8_t scriptId[4];
	int formatError;
	uint8_t  replyData[APDUBUFFERLEN];
	uint8_t sw1, sw2, cmdIndex;
	int outLen = APDUBUFFERLEN;
	uint8_t cmdLen;
	int cmdOffset, issScriptIndex = 0, lenIssScript = 0, len = 0, index = 0;
	int i9F18len, rv;
	int iCmdLen = 0;
	int ret;

	g_iTotalScriptMsgLen = 0;

	if (repo.script72.size() == 0)
	{
		return success;
	}

	uint8_t* scriptBuffer = repo.script72.data();
	if (scriptBuffer[0] != 0x72)
	{
		return success;
	}

	Tlv* tagDF8134 = repo.getTag(0xDF8134);
	if (!tagDF8134) {
		tagDF8134 = repo.setTag(0xDF8134, NULL, 128);
	}

	while (scriptBuffer[issScriptIndex] == 0x72)
	{
		memset(scriptId, 0, sizeof(scriptId));
		g_ucCmdSeqNo = 1;
		formatError = failure;
		g_ucScriptIndex++;

		tagDF8134->len = 5 * g_ucScriptIndex;
		cmdOffset = 0;

		if ((scriptBuffer[issScriptIndex + 1] & 0x80) == 0x80)
		{
			lenLen = scriptBuffer[issScriptIndex + 1] & 0x7F;
			lenIssScript = util.bin2Int(&scriptBuffer[issScriptIndex + 2], lenLen);
			lenLen += 1;
		}
		else
		{
			lenLen = 1;
			lenIssScript = scriptBuffer[issScriptIndex + 1];
		}

		g_iTotalScriptMsgLen += (lenIssScript + (lenLen + 1));

		if (g_iTotalScriptMsgLen > 256)
		{
			repo.setTagFlag(0x95, ISSUERSCRIPTFAILED2);

			return success;
		}

		index = issScriptIndex + (lenLen + 1);

		if ((scriptBuffer[index] == 0x9F) && (scriptBuffer[index + 1] == 0x18))
		{
			i9F18len = repo.parseLen(&scriptBuffer[index + 2], &lenLen9F18);
			memcpy(scriptId, &scriptBuffer[index + lenLen + 2], i9F18len);
			repo.nextTag(scriptBuffer, &index);
		}

		while (index < 256)
		{
			if ((index - 2) == (lenIssScript + issScriptIndex))
			{
				break;
			}

			if ((index - 2) == (lenIssScript + issScriptIndex - 6 - lenLen9F18))
			{
				break;
			}

			if ((index - 2) > (lenIssScript + issScriptIndex))
			{
				formatError = success;
				break;
			}

			if (scriptBuffer[index] == 0x86)
			{
				if (scriptBuffer[index + 1] == 0x81) {
					lenLen86 = 2;
				}
				else {
					lenLen86 = 1;
				}
				repo.nextTag(scriptBuffer, &index);
			}
			else
			{
				formatError = success;
				break;
			}
		}

		if (formatError != failure)
		{
			repo.setTagFlag(0x95, ISSUERSCRIPTFAILED2);
			repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);

			issScriptIndex += lenIssScript + 1 + lenLen;
			tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x00;
			memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);
			continue;
		}

		if (((index - (lenLen86 + 1)) != (lenIssScript + issScriptIndex)) && ((index - (lenLen86 + 1)) != (lenIssScript + issScriptIndex - 6 - lenLen9F18)))
		{
			issScriptIndex += lenIssScript + 1 + lenLen;
			continue;
		}

		rv = repo.parseTags(&scriptBuffer[issScriptIndex], lenIssScript + 1 + lenLen);
		issScriptIndex += lenIssScript + 1 + lenLen;

		if (rv != success)
		{
			continue;
		}

		issScriptId = repo.getTag(0x72)->val.data();
		if (issScriptId[0] == 0)
		{
			continue;
		}

		if (issScriptId[0] == 0x9F)
		{
			if (issScriptId[1] != 0x18)
			{
				continue;
			}

			i9F18len = repo.parseLen(&issScriptId[2], &lenLen);
			if ((i9F18len != 0x04) && (i9F18len != 0x00))
			{
				continue;
			}

			cmdOffset += 3 + i9F18len;
			memcpy(scriptId, issScriptId + 2 + lenLen, i9F18len);
		}

		Tlv* tag72 = repo.getTag(0x72);
		issScriptCmd = &tag72->val.data()[cmdOffset];
		issScriptCmdLen = len - cmdOffset - lenLen;

		cmdIndex = 0;
		do
		{
			if (issScriptCmd[cmdIndex++] != 0x86)
			{
				repo.setTagFlag(0x95, ISSUERSCRIPTFAILED2);
				repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
				break;
			}
			else
			{
				if (issScriptCmd[cmdIndex] == 0x81) {
					cmdLen = issScriptCmd[cmdIndex + 1];
					cmdIndex += 2;
				}
				else {
					cmdLen = issScriptCmd[cmdIndex];
					cmdIndex += 1;
				}
			}

			if ((cmdLen + cmdIndex) > lenIssScript)
			{
				continue;
			}

			iCmdLen = cmdLen;
			ret = device.cardSendReceive((uint8_t*)&issScriptCmd[cmdIndex], (uint32_t)iCmdLen, (uint8_t*)replyData, (uint32_t*)&outLen);

			cmdIndex += cmdLen;

			if (ret != success)
			{
				return cardCommError;
			}
			else
			{
				outLen = 2;
				memcpy(repo.apdu.rdata, replyData, outLen);
				repo.apdu.rlen = outLen;
			}

			if ((cmdLen > 3) && (ret != success))
			{
				return cardCommError;
			}

			sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
			sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

			if ((sw1 != 0x90) && (sw1 != 0x62) && (sw1 != 0x63))
			{
				tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x10;

				if (g_ucCmdSeqNo <= 14)
				{
					tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] |= g_ucCmdSeqNo;
				}
				else
				{
					tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] |= 0x0F;
				}

				memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);

				repo.setTagFlag(0x95, ISSUERSCRIPTFAILED2);
				repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
				break;
			}
			else if ((sw1 == 0x90) && (sw2 == 0x00))
			{
				tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x20;
				memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);
			}
			else
			{
				tagDF8134->val.data()[1 + (g_ucScriptIndex - 1) * 5] = 0x10;
				memcpy(&tagDF8134->val.data()[2 + (g_ucScriptIndex - 1) * 5], scriptId, 4);
				repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
			}

			g_ucCmdSeqNo++;
		} while (cmdIndex < issScriptCmdLen);

		repo.setTagFlag(0x9B, ISSUERSCRIPTPERFORMED);
	}

	return success;
}

int EmvL2GenAC2::genAC2WithCDAProccessing(uint8_t* termDecision, uint8_t* cardDecision, uint8_t* cdolData, uint8_t cdolLen)
{	
	uint8_t sw1, sw2;
	bool cdaRequested = false;
	int rv;
	uint8_t cid;

	Tlv* tag9F27 = repo.getTag(0x9F27);
	Tlv* tag95 = repo.getTag(0x95);
	if (!tag95 || !tag9F27)
		return failure;

	uint8_t* tvr = tag95->val.data();

	if ((tvr[0] & CDAFAILED) != CDAFAILED)
	{
		cdaRequested = true;
		*termDecision = *termDecision + 0x10;
	}

	repo.transactionHashData.insert(repo.transactionHashData.end(), cdolData, cdolData + cdolLen);

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

		if (((tag9F27->val.data()[0] & 0xC0) != AAC) && ((tag9F27->val.data()[0] & AAR) != AAR))
		{
			*cardDecision = AAC;
			return success;
		}

	}

	else if (repo.apdu.rdata[0] == 0x77)
	{
		if ((rv = secUtil.genACCDATemplate77Processing(cdaRequested)) != success)
		{
			return rv;
		}

		if ((tag9F27->val.data()[0] & 0xC0) == AAC)
		{
			*cardDecision = tag9F27->val.data()[0];
			return success;
		}
		else if ((tag9F27->val.data()[0] & AAR) == AAR)
		{
			if (repo.isTagExist(0x9F4C))
			{
				repo.setTagFlag(0x95, CDAFAILED);
				return success;
			}
		}

		if (NULL == repo.cdaIccPkModLen)
		{
			return success;
		}
		rv = secUtil.verifyDynamicSignAC(PKICCMOD, repo.cdaIccPkModLen, &cid);
		if (rv == failure)
		{
			repo.setTagFlag(0x95, CDAFAILED);

			if ((tag9F27->val.data()[0] & 0xC0) == TC)
			{
				*cardDecision = AAC;
			}

			repo.verifyDDAACFail = success;
			return success;
		}

		if (tag9F27->val.data()[0] != cid)
		{
			repo.setTagFlag(0x95, CDAFAILED);

			*cardDecision = AAC;
			repo.verifyDDAACFail = success;
			return success;
		}
	}

	return success;
}

int EmvL2GenAC2::genAC2WithoutCDAProccessing(uint8_t* termDecision, uint8_t* cardDecision, uint8_t* cdolData, uint8_t cdolLen)
{
	uint8_t sw1, sw2;
	int rv;

	if ((repo.typeOfAuth == ACDA) && ((repo.getTag(0x95)->val.data()[0] & CDAFAILED) != CDAFAILED)) 
	{
		*termDecision = AAC;
	}

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
		if ((rv = secUtil.genACNOCDATemplate80Processing()) != success)
		{
			return rv;
		}
	}
	else if (repo.apdu.rdata[0] == 0x77)
	{

		if ((rv = secUtil.genACNOCDATemplate77Processing()) != success)
		{
			return rv;
		}
	}

	return success;
}

void EmvL2GenAC2::genAC2DecisionProccessing(bool isHostReject, uint8_t* termDecision, uint8_t* cardDecision, uint8_t* adviceReversal)
{
	Tlv* tag9B = repo.getTag(0x9B);

	if (repo.verifyDDAACFail == failure)
	{
		*cardDecision = repo.getTag(0x9F27)->val.data()[0];
	}

	if (isHostReject)
	{
		*adviceReversal = *adviceReversal | 0x02;
	}

	if (((*termDecision == TC) && ((*cardDecision) & 0xC0) == AAC))
	{
		*adviceReversal = *adviceReversal | 0x02;
	}

	if (((*cardDecision) & ADVICE) == ADVICE)
	{
		*adviceReversal = *adviceReversal | 0x01;
	}
	else
	{
		*adviceReversal = *adviceReversal & 0xFE;
	}

	if (*termDecision == AAC)
	{
		if ((*cardDecision & 0xC0) != AAC)
		{
			*cardDecision = AAC;
		}
	}
	else if (*termDecision == TC)
	{
		if (((*cardDecision & 0xC0) != TC) && ((*cardDecision & 0xC0) != AAC))
		{
			* cardDecision = AAC;
		}
	}

	if ((((*cardDecision) & 0xC0) == AAC) && ((repo.getTag(0x9B)->val.data()[0] & 0x04) == 0x04))
	{
		* adviceReversal = *adviceReversal | 0x01;
	}
}
