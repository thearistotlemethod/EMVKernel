#include "emvl2ReadAppData.h"
#include "emvl2Command.h"
#include "emvl2TagDef.h"

EmvL2ReadAppData::EmvL2ReadAppData(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()), command(EmvL2Command::getInstance())
, util(EmvL2Util::getInstance()), secUtil(EmvL2SecUtil::getInstance()) {
}

EmvL2ReadAppData::~EmvL2ReadAppData() {

}

uint8_t EmvL2ReadAppData::perform() {
	uint8_t sw1, sw2, lenLen, authType, rv = failure;

	Tlv* tag94 = repo.getTag(0x94);
	if (!tag94 || tag94->len < 4)
	{
		return aflLenError;
	}

	int aflIdx = 0;
	while (aflIdx < (int)tag94->len)
	{
		uint8_t* aflData = &tag94->val.data()[aflIdx];
		aflIdx += 4;
		uint8_t sfiVal = aflData[0];
		sfiVal &= 0xF8;
		uint8_t realSfiVal = (sfiVal >> 3) & 0x1F;
		uint8_t firstRecNo = aflData[1];
		uint8_t lastRecNo = aflData[2];
		int offCnt = aflData[3];

		if (realSfiVal == 0 || realSfiVal > 30)
		{
			return sfiLenError;
		}

		if (firstRecNo == 0 || firstRecNo > lastRecNo || offCnt > lastRecNo - firstRecNo + 1)
		{
			return aflDataError;
		}

		for (int i = firstRecNo; i <= lastRecNo; i++)
		{
			int readLen = 0;
			int readIdx = 0;
			rv = command.readRecord(sfiVal, (uint8_t)i);
			if (rv != success)
			{
				return rv;
			}

			sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
			sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

			if ((sw1 != 0x90) || (sw2 != 0))
			{
				return cardRejected;
			}

			while ((repo.apdu.rdata[readIdx] == 0) || (repo.apdu.rdata[readIdx] == 0xFF))
			{
				readIdx++;
			}

			if ((repo.apdu.rdata[readIdx] != 0x70) && ((realSfiVal >= 1) && (realSfiVal <= 10)))
			{
				return emvDataFormatError;
			}
			else if ((repo.apdu.rdata[readIdx] != 0x70) && ((realSfiVal >= 11) && (realSfiVal <= 30)) && offCnt != 0)
			{
				secUtil.determineDataAuthType(&authType);

				lenLen = repo.apdu.rdata[++readIdx] & 0x7F;
				readLen = util.bin2Int(&repo.apdu.rdata[readIdx + 1], lenLen);
				readIdx += lenLen + 1;

				switch (authType)
				{
				case ASDA:
					repo.isTagFlag(0x95, SDAFAILED);
					break;

				case ADDA:
					repo.isTagFlag(0x95, DDAFAILED);
					break;

				case ACDA:
					repo.isTagFlag(0x95, CDAFAILED);
					break;
				default:
					break;
				}
			}
			else
			{
				if (repo.apdu.rdata[readIdx] == 0x70)
				{
					readIdx += 1;

					if ((repo.apdu.rdata[readIdx] & 0x80) == 0x80)
					{
						lenLen = repo.apdu.rdata[readIdx] & 0x7F;
						readLen = util.bin2Int(&repo.apdu.rdata[readIdx + 1], lenLen);
						readIdx += lenLen + 1;
					}
					else
					{
						readLen = repo.apdu.rdata[readIdx];
						readIdx++;
					}

					if ((readIdx + readLen) != (repo.apdu.rlen - 2))
					{
						return emvDataFormatError;
					}
				}
			}

			rv = repo.parseTags(&repo.apdu.rdata[readIdx], readLen);
			if ((rv != success) && ((rv != noTag)))
			{
				if ((rv == emvDataFormatError) && ((realSfiVal >= 11) && (realSfiVal <= 30)) && offCnt != 0)
				{
					secUtil.determineDataAuthType(&authType);

					switch (authType)
					{
					case ASDA:
						repo.isTagFlag(0x95, SDAFAILED);
						break;

					case ADDA:
						repo.isTagFlag(0x95, DDAFAILED);
						break;

					case ACDA:
						repo.isTagFlag(0x95, CDAFAILED);
						break;
					default:
						break;
					}
				}
				else
				{
					return rv;
				}
			}

			if (offCnt != 0)
			{
				offCnt--;

				if ((realSfiVal >= 1) && (realSfiVal <= 10))
				{
					repo.staticAppData.insert(repo.staticAppData.end(), &repo.apdu.rdata[readIdx], &repo.apdu.rdata[readIdx] + readLen);
				}
				else if ((realSfiVal >= 11) && (realSfiVal <= 30))
				{
					repo.staticAppData.insert(repo.staticAppData.end(), &repo.apdu.rdata[0], &repo.apdu.rdata[0] + repo.apdu.rlen - 2);
				}
			}
		}
	}

	if (!checkMandatoryTags()) {
		return emvMissingMandatoryDataError;
	}

	Tlv* tag5F24 = repo.getTag(0x5F24);
	if (!tag5F24 || (failure == isDateValid(tag5F24->val.data())))
	{
		return expDateFormatError;
	}

	Tlv* tag5F25 = repo.getTag(0x5F25);	
	if (!tag5F25 || (failure == isDateValid(tag5F25->val.data())))
	{
		return effDateFormatError;
	}

	return success;
}

uint8_t EmvL2ReadAppData::isDateValid(uint8_t* Date)
{
	if (Date[1] == 0x00 || Date[1] > 0x12 || Date[2] == 0x00 || Date[2] > 0x31)
	{
		return failure;
	}
	else
	{
		if ((util.bcd2Int(Date, 1) % 4) == 0)
		{
			if ((Date[1] == 0x02) && (Date[2] > 0x29))
			{
				return failure;
			}
		}
		else
		{
			if ((Date[1] == 0x02) && (Date[2] > 0x28))
			{
				return failure;
			}
		}
	}

	return success;
}

bool EmvL2ReadAppData::checkMandatoryTags() {
	if (!repo.isTagExist(0x5A) || !repo.isTagExist(0x82) || !repo.isTagExist(0x8C) || !repo.isTagExist(0x8D) || !repo.isTagExist(0x5F24))
		return false;

	return true;
}