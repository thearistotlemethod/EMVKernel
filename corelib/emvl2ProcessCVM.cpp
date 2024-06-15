#include "emvl2ProcessCVM.h"
#include "emvl2Command.h"

#define SUCCESS					0x02
#define FAIL					0x01
#define UNKNOWN					0x00
#define NOTSUPPORTED			0xFF

#define CONTINUECVM				1
#define ENDCVM					2

#define CVMFAIL					0x00
#define CVMOFFPLAINPIN			0x01
#define CVMONLPIN				0x02
#define CVMOFFPLAINPINSIGN		0x03
#define CVMOFFENCPIN			0x04
#define CVMOFFENCPINSIGN		0x05
#define CVMSIGN					0x1E
#define CVMNO					0x1F
#define CVMUNRECOG				0xFF

#define ALWAYS					0x00
#define IFUNATCASH				0x01
#define NOTCASHORCB				0x02
#define IFTERMTYPESUPPORTSCVM   0x03
#define IFMANUELCASH            0x04
#define IFPURCCB				0x05
#define IFTRANCURRENCYUNDERX    0x06
#define IFTRANCURRENCYOVERX     0x07
#define FTRANCURRENCYUNDERY     0x08
#define IFTRANCURRENCYOVERY     0x09

EmvL2ProcessCVM::EmvL2ProcessCVM(IDevice& device) : device(device), 
repo(EmvL2Repo::getInstance()), 
command(EmvL2Command::getInstance()), 
util(EmvL2Util::getInstance()),
secUtil(EmvL2SecUtil::getInstance()) {
}

EmvL2ProcessCVM::~EmvL2ProcessCVM() {

}

uint8_t EmvL2ProcessCVM::perform() {
	int idx = 8;
	uint8_t condCode = 0, type = 0, code = 0;
	uint8_t rv = 0;
	int isSuccess = 0;

	repo.pinBypassed = false;
	repo.signatureRequired = false;

	rv = init();
	if (rv != success)
	{
		if ((rv == cvmAipNotSupported) || (rv == cvmTag8EMissing) || (rv == cvmTag8ERuleMissing))
		{
			return success;
		}
		else
		{
			return rv;
		}
	}

	do
	{
		condCode = repo.getTag(0x8E)->val.data()[idx + 1];
		nextCVMCode(idx, &code, &type);

		rv = checkConditionCode(condCode, code);
		if (rv == success)
		{
			rv = isCVMCodeSupported(code, &isSuccess);
			if (rv == success)
			{
				rv = doMethod(type, &isSuccess);
				if (rv != success)
				{
					return rv;
				}
			}

			rv = processResult(isSuccess, condCode, code);
			if (rv != CONTINUECVM)
			{
				break;
			}
		}

		idx += 2;
		rv = (idx < (int)repo.getTag(0x8E)->len) ? CONTINUECVM : ENDCVM;
		if (rv != CONTINUECVM)
		{
			break;
		}
	} while (idx < 256);

	finalize(idx);
	return success;
}

int EmvL2ProcessCVM::processResult(uint8_t result, uint8_t condCode, uint8_t code)
{
	int rv;

	Tlv* tag9F34 = repo.getTag(0x9F34);

	if (result == NOTSUPPORTED)
	{
		if (((code & 0x40) != 0x40))
		{
			repo.setTagFlag(0x95, CVMNOTSUCCESS);
			repo.setTagFlag(0x9B, CVMPERFORMED);

			rv = ENDCVM;
		}
		else
		{
			rv = CONTINUECVM;
		}
	}
	else if (result == FAIL)
	{
		tag9F34->val.data()[0] = code;
		tag9F34->val.data()[1] = condCode;
		tag9F34->val.data()[2] = 0x01;

		if (((code & 0x40) != 0x40) || (code == 0) || (code == 0x40))
		{			
			repo.setTagFlag(0x95, CVMNOTSUCCESS);
			repo.setTagFlag(0x9B, CVMPERFORMED);

			rv = ENDCVM;
		}
		else
		{
			rv = CONTINUECVM;
		}
	}
	else if (result == SUCCESS)
	{
		tag9F34->val.data()[0] = code;
		tag9F34->val.data()[1] = condCode;
		tag9F34->val.data()[2] = 0x02;

		repo.setTagFlag(0x9B, CVMPERFORMED);

		rv = ENDCVM;
	}
	else
	{
		tag9F34->val.data()[0] = code;
		tag9F34->val.data()[1] = condCode;
		tag9F34->val.data()[2] = 0x00;

		repo.setTagFlag(0x9B, CVMPERFORMED);

		rv = ENDCVM;
	}

	return rv;
}

uint8_t EmvL2ProcessCVM::init()
{
	Tlv* tag8E = repo.getTag(0x8E);
	int iLenCVMList = tag8E->len;

	repo.setTag(0x9F34, (uint8_t *)"\x3F\x00\x00", 3);

	if (!repo.isTagFlag(0x82, CVMSupported))
	{
		return cvmAipNotSupported;
	}

	if (iLenCVMList == 0)
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);

		return cvmTag8EMissing;
	}

	if (iLenCVMList == 8)
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);

		return cvmTag8ERuleMissing;
	}
	else if ((iLenCVMList < 8) || (((iLenCVMList - 8) % 2) == 1))
	{
		return cvmTag8EFormatError;
	}

	return success;
}

void EmvL2ProcessCVM::finalize(int idx)
{
	Tlv* tag8E = repo.getTag(0x8E);
	int CVMListLen = tag8E->len;

	if (0 == memcmp(repo.getTag(0x9F34)->val.data(), "\x3F\x00\x00", 3))
	{
		memcpy(repo.getTag(0x9F34)->val.data(), "\x3F\x00\x01", 3);
	}

	if (idx >= CVMListLen)
	{
		repo.setTagFlag(0x95, CVMNOTSUCCESS);
		repo.setTagFlag(0x9B, CVMPERFORMED);
	}

	return;
}

void EmvL2ProcessCVM::nextCVMCode(int idx, uint8_t* code, uint8_t* type)
{
	*code = repo.getTag(0x8E)->val.data()[idx];
	switch (0x3F & *code)
	{
	case 0x00:
		*type = 0;
		break;
	case 0x01:
		*type = CVMOFFPLAINPIN;
		break;
	case 0x02:
		*type = CVMONLPIN;
		break;
	case 0x03:
		*type = CVMOFFPLAINPINSIGN;
		break;
	case 0x04:
		*type = CVMOFFENCPIN;
		break;
	case 0x05:
		*type = CVMOFFENCPINSIGN;
		break;
	case 0x1E:
		*type = CVMSIGN;
		break;
	case 0x1F:
		*type = CVMNO;
		break;
	default:
		*type = CVMUNRECOG;
		break;
	}

	return;
}

uint8_t EmvL2ProcessCVM::checkConditionCode(uint8_t condCode, uint8_t code)
{
	uint32_t amt, trnAmt;
	uint8_t amountX[12], amountY[12];

	Tlv* tag8E = repo.getTag(0x8E);
	Tlv* tag5F2A = repo.getTag(0x5F2A);
	Tlv* tag9F42 = repo.getTag(0x9F42);

	memcpy(amountX, tag8E->val.data(), 4);
	memcpy(amountY, tag8E->val.data() + 4, 4);
	condCode = 0x3F & condCode;

	uint8_t* trnCurCode = NULL;
	if(tag5F2A)
		trnCurCode = tag5F2A->val.data();

	uint8_t* appCurCode = NULL;
	if (tag9F42)
		appCurCode = tag9F42->val.data();

	Tlv* tag9C = repo.getTag(0x9C);
	Tlv* tag9F35 = repo.getTag(0x9F35);
	Tlv* tag9F02 = repo.getTag(0x9F02);

	switch (condCode)
	{
	case ALWAYS:
		return success;

	case IFUNATCASH:
		if (tag9C && (tag9C->val.data()[0] == TRNCASH) && tag9F35 && (isUnattendedTerminal(tag9F35->val.data()[0]) == success))
			return success;
		return cvmCondCodeNotSupported;
	case NOTCASHORCB:
		if (tag9C && (tag9C->val.data()[0] == TRNCASH) || tag9F35 && (tag9F35->val.data()[0] == TRNCASHBACK))
			return cvmCondCodeNotSupported;
		return success;

	case IFTERMTYPESUPPORTSCVM:
		return cvmIsSupported(code);

	case IFMANUELCASH:
		if (tag9C && (tag9C->val.data()[0] == TRNCASH) && tag9F35 && (isUnattendedTerminal(tag9F35->val.data()[0]) == failure))
		{
			return success;
		}
		else
		{
			return cvmCondCodeNotSupported;
		}

	case IFPURCCB:
		if (tag9C && (tag9C->val.data()[0] == TRNCASHBACK))
		{
			return success;
		}
		else
		{
			return cvmCondCodeNotSupported;
		}

	case IFTRANCURRENCYUNDERX:		
		if (!tag9F02)
		{
			return cvmCondCodeNotSupported;
		}

		trnAmt = util.bcd2Int(tag9F02->val.data(), tag9F02->len);
		amt = util.bin2Int(amountX, 4);

		if (trnCurCode && appCurCode && memcmp(trnCurCode, appCurCode, 2) == 0)
		{
			if (trnAmt < amt)
			{
				return success;
			}
		}

		return cvmCondCodeNotSupported;

	case IFTRANCURRENCYOVERX:
		if (!tag9F02)
		{
			return cvmCondCodeNotSupported;
		}

		trnAmt = util.bcd2Int(tag9F02->val.data(), tag9F02->len);
		amt = util.bin2Int(amountX, 4);

		if ((trnCurCode[0] == 0) || (appCurCode[0] == 0))
		{
			return cvmCondCodeNotSupported;
		}

		if (memcmp(trnCurCode, appCurCode, 2) == 0)
		{
			if (trnAmt > amt)
			{
				return success;
			}
		}

		return cvmCondCodeNotSupported;

	case FTRANCURRENCYUNDERY: 
		if (!tag9F02)
		{
			return cvmCondCodeNotSupported;
		}

		trnAmt = util.bcd2Int(tag9F02->val.data(), tag9F02->len);
		amt = util.bin2Int(amountY, 4);

		if ((trnCurCode[0] == 0) || (appCurCode[0] == 0))
		{
			return cvmCondCodeNotSupported;
		}

		if (memcmp(trnCurCode, appCurCode, 2) == 0)
		{
			if (trnAmt < amt)
			{
				return success;
			}
		}

		return cvmCondCodeNotSupported;

	case IFTRANCURRENCYOVERY:
		if (!tag9F02)
		{
			return cvmCondCodeNotSupported;
		}

		trnAmt = util.bcd2Int(tag9F02->val.data(), tag9F02->len);
		amt = util.bin2Int(amountY, 4);

		if ((trnCurCode[0] == 0) || (appCurCode[0] == 0))
		{
			return cvmCondCodeNotSupported;
		}

		if (memcmp(trnCurCode, appCurCode, 2) == 0)
		{
			if (trnAmt > amt)
			{
				return success;
			}
		}

		return cvmCondCodeNotSupported;

	default:
		return cvmCondCodeNotSupported;
	}
}

uint8_t EmvL2ProcessCVM::isUnattendedTerminal(uint8_t ttype)
{
	if (ttype == 0x14 || ttype == 0x15 || ttype == 0x16)
	{
		return success;
	}

	return failure;
}

uint8_t EmvL2ProcessCVM::cvmIsSupported(uint8_t code)
{
	uint8_t maskedCode = 0x3F & code;

	if (maskedCode == CVMNO)
	{
		if (!repo.isTagFlag(0x9F33, NOCVMSUPPORTED))
		{
			return cvmCondCodeNotSupported;
		}
	}
	else if (maskedCode == CVMOFFPLAINPIN)
	{
		if (!repo.isTagFlag(0x9F33, OFFLINEPLAINPIN))
		{
			return cvmCondCodeNotSupported;
		}
	}
	else if (maskedCode == CVMOFFENCPIN)
	{
		if (!repo.isTagFlag(0x9F33, OFFLINEENCHIPEREDPIN))
		{
			return cvmCondCodeNotSupported;
		}
	}
	else if (maskedCode == CVMONLPIN)
	{
		if (!repo.isTagFlag(0x9F33, ONLINEENCHIPEREDPIN))
		{
			return cvmCondCodeNotSupported;
		}
	}
	else if (maskedCode == CVMSIGN)
	{
		if (!repo.isTagFlag(0x9F33, SIGNATURESUPPORTED))
		{
			return cvmCondCodeNotSupported;
		}
	}
	else if (maskedCode == CVMOFFPLAINPINSIGN)
	{
		if (!repo.isTagFlag(0x9F33, OFFLINEPLAINPIN))
		{
			return cvmCondCodeNotSupported;
		}

		if (!repo.isTagFlag(0x9F33, SIGNATURESUPPORTED))
		{
			return cvmCondCodeNotSupported;
		}
	}
	else if (maskedCode == CVMOFFENCPINSIGN)
	{
		if (!repo.isTagFlag(0x9F33, OFFLINEENCHIPEREDPIN))
		{
			return cvmCondCodeNotSupported;
		}

		if (!repo.isTagFlag(0x9F33, SIGNATURESUPPORTED))
		{
			return cvmCondCodeNotSupported;
		}
	}
	else
	{
		return cvmCondCodeNotSupported;
	}


	return success;
}

uint8_t EmvL2ProcessCVM::isCVMCodeSupported(uint8_t code, int* isSuccess)
{
	switch (0x3F & code)
	{
	case CVMOFFPLAINPIN:
		if (!repo.isTagFlag(0x9F33, OFFLINEPLAINPIN))
		{
			repo.setTagFlag(0x95, PINPADNOTPRESENT);
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}

		break;

	case CVMONLPIN:
		if (!repo.isTagFlag(0x9F33, ONLINEENCHIPEREDPIN))
		{
			repo.setTagFlag(0x95, PINPADNOTPRESENT);
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}

		break;

	case CVMOFFPLAINPINSIGN:
		if (!repo.isTagFlag(0x9F33, OFFLINEPLAINPIN))
		{
			repo.setTagFlag(0x95, PINPADNOTPRESENT);
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}
		else if (!repo.isTagFlag(0x9F33, SIGNATURESUPPORTED))
		{
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}
		break;

	case CVMOFFENCPIN:
		if (!repo.isTagFlag(0x9F33, OFFLINEENCHIPEREDPIN))
		{
			repo.setTagFlag(0x95, PINPADNOTPRESENT);
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}

		break;

	case CVMOFFENCPINSIGN:
		if (!repo.isTagFlag(0x9F33, OFFLINEENCHIPEREDPIN))
		{
			repo.setTagFlag(0x95, PINPADNOTPRESENT);
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}
		else if (!repo.isTagFlag(0x9F33, SIGNATURESUPPORTED))
		{
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}

		break;

	case CVMSIGN:
		if (!repo.isTagFlag(0x9F33, SIGNATURESUPPORTED))
		{
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}

		break;

	case CVMNO:
		if (!repo.isTagFlag(0x9F33, NOCVMSUPPORTED))
		{
			*isSuccess = NOTSUPPORTED;
			return cvmIsNotSupported;
		}

		break;

	case 0:
		break;

	default:
		repo.setTagFlag(0x95, UNRECOGNISEDCVM);
		*isSuccess = NOTSUPPORTED;
		return CVMUNRECOG;
		break;
	}

	return success;
}

uint8_t EmvL2ProcessCVM::doMethod(uint8_t type, int* isSuccess)
{
	uint8_t rv = success;
	uint8_t pan[32], panLength = 0;
	uint8_t PANStr[64];

	switch (type)
	{
	case 0:
	{
		*isSuccess = FAIL;
	}
	break;

	case CVMOFFPLAINPIN:
	{
		if (repo.pinBypassed == true) {
			break;
		}
		rv = offlinePlainPIN(isSuccess);
	}
	break;

	case CVMONLPIN:
	{
		if (repo.pinBypassed == true) {
			break;
		}

		Tlv* tag5A = repo.getTag(0x5A);

		memcpy(pan, tag5A->val.data(), tag5A->len);
		util.bcd2Str(pan, panLength, PANStr);

		int ret = device.pinOnline(PANStr, panLength * 2);
		if (success != ret)
		{
			repo.setTagFlag(0x95, PINNOTENTERED);
			*isSuccess = FAIL;

			if (ret == pinCancel || ret == pinTimeout) {
				repo.pinBypassed = true;
			}
		}
		else {
			repo.setTagFlag(0x95, ONLINEPINENTERED);
			*isSuccess = UNKNOWN;
		}
	}
	break;

	case CVMOFFPLAINPINSIGN:
	{
		if (repo.pinBypassed == true) {
			break;
		}
		rv = offlinePlainPIN(isSuccess);
		if (((*isSuccess) == SUCCESS) && rv != 0)
		{
			*isSuccess = UNKNOWN;
			repo.signatureRequired = true;
		}
	}
	break;

	case CVMOFFENCPIN:
	{
		if (repo.pinBypassed == true) {
			break;
		}
		rv = offlineEncryptedPIN(isSuccess);
	}
	break;

	case CVMOFFENCPINSIGN:
	{
		if (repo.pinBypassed == true) {
			break;
		}
		rv = offlineEncryptedPIN(isSuccess);
		if (((*isSuccess) == SUCCESS) && rv != 0)
		{
			*isSuccess = UNKNOWN;
			repo.signatureRequired = true;
		}
	}
	break;

	case CVMSIGN:
	{
		*isSuccess = UNKNOWN;
		repo.signatureRequired = true;
	}
	break;

	case CVMNO:
	{
		*isSuccess = SUCCESS;
	}
	break;

	case CVMUNRECOG:
	{
		repo.setTagFlag(0x95, UNRECOGNISEDCVM);
		*isSuccess = FAIL;
	}
	break;
	}

	return rv;
}

int EmvL2ProcessCVM::offlinePlainPIN(int* isSuccess)
{
	int rv;
	uint8_t sw1, sw2;	

	if (!repo.isTagFlag(0x9F33, OFFLINEPLAINPIN))
	{
		repo.setTagFlag(0x95, PINPADNOTPRESENT);

		*isSuccess = FAIL;
		return success;
	}

	rv = command.getData(0x9F17);
	if (rv != success)
	{
		return rv;
	}

	sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

	if ((sw1 == 0x90) && (sw2 == 0x00))
	{		
		rv = repo.parseTags(&repo.apdu.rdata[0], repo.apdu.rlen - 2);

		Tlv* tag9F17 = repo.getTag(0x9F17);
		if (rv == success && tag9F17)
		{
			int iPinTryCnt = tag9F17->val.data()[0];
			if (iPinTryCnt == 0)
			{
				repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);

				*isSuccess = FAIL;
				return success;
			}
		}
	}

	int i = 0;
	while (i <= 15)
	{
		uint8_t cardSw[2] = { 0 };
		int dRv = device.pinOfflinePlain(cardSw);
		if (success != dRv)
		{
			if (dRv == pinCancel) {
				repo.pinBypassed = true;
			}
			repo.setTagFlag(0x95, PINNOTENTERED);

			*isSuccess = FAIL;
			return success;
		}

		sw1 = cardSw[0];
		sw2 = cardSw[1];

		if ((sw1 == 0x90) && (sw2 == 0x00)) 
		{
			*isSuccess = SUCCESS;
			return success;
		}
		else if ((sw1 == 0x69) && (sw2 == 0x83))
		{
			repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);

			*isSuccess = FAIL;
			return success;
		}
		else if ((sw1 == 0x69) && (sw2 == 0x84))
		{
			repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);

			*isSuccess = FAIL;
			return success;
		}
		else if ((sw1 == 0x63) && (sw2 & 0xF0) == 0xC0)
		{
			if ((sw2 & 0x0F) == 0x00)
			{
				repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);

				*isSuccess = FAIL;
				return success;
			}
		}
		else
		{
			return cardRejected;
		}
		i++;
	}

	return pintryCountError;
}

int EmvL2ProcessCVM::offlineEncryptedPIN(int* isSuccess)
{
	int rv;
	uint8_t sw1, sw2;
	uint8_t unPredictNumber[8];	
	uint8_t pinModLen = 0, iccModLen = 0;

	Tlv* tag9F2D = repo.getTag(0x9F2D);
	Tlv* tag9F2E = repo.getTag(0x9F2E);
	Tlv* tag9F46 = repo.getTag(0x9F46);
	Tlv* tag9F47 = repo.getTag(0x9F47);

	memset(repo.iccPinPkModulus, 0, sizeof(repo.iccPinPkModulus));

	if (!repo.isTagFlag(0x9F33, OFFLINEENCHIPEREDPIN))
	{
		repo.setTagFlag(0x95, PINPADNOTPRESENT);
		*isSuccess = FAIL;
		return success;
	}

	if (tag9F2D)
	{
		if (failure == getICCEncPublicKey(&pinModLen))
		{
			*isSuccess = FAIL;
			return success;
		}
	}
	else if (tag9F46)
	{
		if (failure == getICCPublicKey(&iccModLen))
		{
			*isSuccess = FAIL;
			return success;
		}
	}
	else {
		*isSuccess = FAIL;
		return success;
	}
	
	repo.setTag(0x9F17);
	rv = command.getData(0x9F17);
	if (rv != success)
	{
		return rv;
	}

	sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

	if ((sw1 == 0x90) && (sw2 == 0x00))
	{		
		rv = repo.parseTags(&repo.apdu.rdata[0], repo.apdu.rlen - 2);

		Tlv* tag9F17 = repo.getTag(0x9F17);
		if (rv == success && tag9F17)
		{
			int iPinTryCnt = tag9F17->val.data()[0];
			if (iPinTryCnt == 0)
			{
				repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);
				*isSuccess = FAIL;
				return success;
			}
		}
	}

	if (tag9F2D)
	{
		if (!tag9F2E)
		{
			*isSuccess = FAIL;
			return success;
		}
	}
	else if (tag9F46)
	{
		if (!tag9F47)
		{
			*isSuccess = FAIL;
			return success;
		}
	}

	bool repeat = false;
	do
	{
		repeat = false;
		rv = command.getChallenge();
		if (rv != success)
		{
			return rv;
		}

		sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
		sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

		if ((sw1 == 0x90) && (sw2 == 0x00))
		{
			if (repo.apdu.rlen != 10)
			{
				*isSuccess = FAIL;
				return success;
			}

			memcpy(unPredictNumber, repo.apdu.rdata, sizeof(unPredictNumber));
		}
		else
		{
			*isSuccess = FAIL;
			return success;
		}

		uint8_t cardSw[2] = { 0 };
		int ret = 0;
		if (tag9F2D)
		{
			ret = device.pinOfflineEncrypted(repo.iccPinPkModulus, pinModLen, tag9F2E->val.data(), tag9F2E->len, unPredictNumber, cardSw);
		}
		else if (tag9F46)
		{
			ret = device.pinOfflineEncrypted(repo.iccPkModulus, iccModLen, tag9F47->val.data(), tag9F47->len, unPredictNumber, cardSw);
		}

		if (success != ret)
		{
			if (pinCancel == ret || pinTimeout == ret)
			{
				repo.setTagFlag(0x95, PINNOTENTERED);
				*isSuccess = FAIL;
				repo.pinBypassed = true;
				return success;
			}
			else if (pinMalfunction == ret || pinPrmError == ret)
			{
				repo.setTagFlag(0x95, PINPADNOTPRESENT);
				*isSuccess = FAIL;
				return success;
			}
			else
			{
				repo.setTagFlag(0x95, PINPADNOTPRESENT);
				*isSuccess = FAIL;
				return success;
			}
		}

		sw1 = cardSw[0];
		sw2 = cardSw[1];

		if ((sw1 == 0x90) && (sw2 == 0x00))
		{
			*isSuccess = SUCCESS;
			return success;
		}
		else if ((sw1 == 0x69) && (sw2 == 0x83))
		{
			repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);
			*isSuccess = FAIL;
			return success;
		}
		else if ((sw1 == 0x69) && (sw2 == 0x84))
		{
			repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);
			*isSuccess = FAIL;
			return success;
		}
		else if ((sw1 == 0x63) && (sw2 & 0xF0) == 0xC0)
		{
			if ((sw2 & 0x0F) == 0x00)
			{
				repo.setTagFlag(0x95, PINTRYLIMITEXCEEDED);
				*isSuccess = FAIL;
				return success;
			}
			else if ((sw2 & 0x0F) == 0x01)
			{
				repeat = true;
			}
			else
			{
				repeat = true;
			}
		}
		else
		{
			return cardRejected;
		}
	} while (false != repeat);

	return success;
}

int EmvL2ProcessCVM::getICCPublicKey(uint8_t* modLen)
{
	int len;
	uint8_t pkModLen;
	uint8_t exponent[3], expLen;
	uint8_t issModLen;

	memset(repo.caPkModulus, 0, sizeof(repo.caPkModulus));
	memset(repo.issPkModulus, 0, sizeof(repo.issPkModulus));
	memset(repo.iccPkModulus, 0, sizeof(repo.iccPkModulus));

	if (failure == repo.searchCAKeys())
	{
		return failure;
	}

	pkModLen = repo.activeCAKey->ucPKModuloLen;

	len = 0;
	Tlv* tag90 = repo.getTag(0x90);
	if (!tag90)
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
	}
	else {
		len = tag90->len;
	}

	if (pkModLen != len)
	{
		return failure;
	}

	memcpy(repo.caPkModulus, &repo.activeCAKey->ucPKModulo, pkModLen);
	expLen = repo.activeCAKey->ucPKExpLen;
	memcpy(exponent, repo.activeCAKey->ucPKExp, expLen);

	if (failure == secUtil.recoverPubKeyCert(PKCAMOD, pkModLen,
		exponent, expLen, len, tag90->val.data(), &issModLen))
	{
		return failure;
	}

	memcpy(repo.issPkModulus, repo.recPkModulus, issModLen);

	len = 0;
	Tlv* tag9F46 = repo.getTag(0x9F46);
	if (!tag9F46)
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
	}
	else {
		len = tag9F46->len;
	}

	if (issModLen != len)
	{
		return failure;
	}

	if (failure == secUtil.recoverICCPubKeyCert(issModLen, modLen))
	{
		return failure;
	}

	return success;
}

int EmvL2ProcessCVM::getICCEncPublicKey(uint8_t* modLen)
{
	int len, expLen;
	uint8_t pkModLen, issModLen;
	uint8_t exponent[3];

	memset(repo.caPkModulus, 0, sizeof(repo.caPkModulus));
	memset(repo.issPkModulus, 0, sizeof(repo.issPkModulus));
	memset(repo.iccPinPkModulus, 0, sizeof(repo.iccPinPkModulus));

	if (failure == repo.searchCAKeys())
	{
		return failure;
	}

	pkModLen = repo.activeCAKey->ucPKModuloLen;
	memcpy(repo.caPkModulus, &repo.activeCAKey->ucPKModulo, pkModLen);
	expLen = repo.activeCAKey->ucPKExpLen;
	memcpy(exponent, repo.activeCAKey->ucPKExp, expLen);

	len = 0;
	Tlv* tag90 = repo.getTag(0x90);
	if (!tag90)
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
	}
	else {
		len = tag90->len;
	}

	if (pkModLen != len)
	{
		return failure;
	}

	if (failure == secUtil.recoverPubKeyCert(PKCAMOD, pkModLen, exponent,
		expLen, len, tag90->val.data(), &issModLen))
	{
		return failure;
	}

	memcpy(repo.issPkModulus, repo.recPkModulus, issModLen);

	len = 0;
	Tlv* tag9F2D = repo.getTag(0x9F2D);
	if (!tag9F2D)
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
	}
	else {
		len = tag9F2D->len;
	}

	if (issModLen != len)
	{
		return failure;
	}

	if (failure == secUtil.recoverICCPINEncPubKeyCert(issModLen, modLen))
	{
		return failure;
	}

	return success;
}

