#include "emvl2TerminalRiskMng.h"

EmvL2TerminalRiskMng::EmvL2TerminalRiskMng(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()), 
command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()) {
}

EmvL2TerminalRiskMng::~EmvL2TerminalRiskMng() {

}

uint8_t EmvL2TerminalRiskMng::perform() {
	int rv;

	repo.staticAppData.clear();

	rv = randomTranSelect();
	if (rv != success)
	{
		return rv;
	}

	rv = velocityCheck();
	if (rv != success)
	{
		return rv;
	}

	repo.setTagFlag(0x9B, TERMRISKMNGPERFORMED);
	return success;
}

int EmvL2TerminalRiskMng::velocityCheck()
{
	int atc = 0, lastOnlineAtc = 0, rv;
	bool lastOnlineAtcZero = false, atcReadError = false, lastOnlineAtcReadError = false;
	uint8_t sw1, sw2;

	if (!repo.isTagExist(0x9F23) || !repo.isTagExist(0x9F14))
	{
		return success;;
	}
		
	rv = command.getData(0x9F36);
	if (rv != success)
	{
		return rv;
	}

	sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];

	if ((sw1 == 0x90) && (sw2 == 0))
	{
		rv = repo.parseTags(&repo.apdu.rdata[0], repo.apdu.rlen - 2);

		if (rv == success)
		{
			atc = util.bin2Int(repo.getTag(0x9F36)->val.data(), repo.getTag(0x9F36)->len);
		}
	}

	if ((sw1 == 0x6A) && ((sw2 == 0x81) || (sw2 == 0x88)))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, LCONOFFLIMITEXCEEDED);
		repo.setTagFlag(0x95, UCONOFFLIMITEXCEEDED);
		atcReadError = true;
	}
	else if ((sw1 != 0x90) || (sw2 != 0))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, LCONOFFLIMITEXCEEDED);
		repo.setTagFlag(0x95, UCONOFFLIMITEXCEEDED);
		return success;
	}

	if (!repo.isTagExist(0x9F36))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, LCONOFFLIMITEXCEEDED);
		repo.setTagFlag(0x95, UCONOFFLIMITEXCEEDED);
		atcReadError = true;
	}

	rv = command.getData(0x9F13);
	if (rv != success)
	{
		return rv;
	}

	sw1 = repo.apdu.rdata[repo.apdu.rlen - 2];
	sw2 = repo.apdu.rdata[repo.apdu.rlen - 1];
	if ((sw1 == 0x90) && (sw2 == 0))
	{
		rv = repo.parseTags(&repo.apdu.rdata[0], repo.apdu.rlen - 2);
		if (rv == success)
		{
			Tlv* tag9F13 = repo.getTag(0x9F13);
			lastOnlineAtc = util.bin2Int(tag9F13->val.data(), tag9F13->len);

			if (tag9F13->val.data()[0] == 0 && tag9F13->val.data()[1] == 0)
			{
				lastOnlineAtcZero = true;
			}
		}
	}

	if ((sw1 == 0x6A) && ((sw2 == 0x81) || (sw2 == 0x88)))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, LCONOFFLIMITEXCEEDED);
		repo.setTagFlag(0x95, UCONOFFLIMITEXCEEDED);
		lastOnlineAtcReadError = true;
	}
	else if ((sw1 != 0x90) || (sw2 != 0) || !repo.isTagExist(0x9F13))
	{
		repo.setTagFlag(0x95, ICCDATAMISSING);
		repo.setTagFlag(0x95, LCONOFFLIMITEXCEEDED);
		repo.setTagFlag(0x95, UCONOFFLIMITEXCEEDED);
		return success;
	}

	if (lastOnlineAtc == 0 && !repo.isTagFlag(0x95, LCONOFFLIMITEXCEEDED) && !repo.isTagFlag(0x95, UCONOFFLIMITEXCEEDED))
	{
		repo.setTagFlag(0x95, NEWCARD);
	}

	if (atc == 0 && lastOnlineAtcZero && repo.isTagFlag(0x95, LCONOFFLIMITEXCEEDED) && repo.isTagFlag(0x95, UCONOFFLIMITEXCEEDED))
	{
		repo.setTagFlag(0x95, NEWCARD);
	}

	if (atcReadError && lastOnlineAtcReadError)
	{
		return success;
	}

	if (atc <= lastOnlineAtc)
	{
		repo.setTagFlag(0x95, LCONOFFLIMITEXCEEDED);
		repo.setTagFlag(0x95, UCONOFFLIMITEXCEEDED);
		return success;
	}

	uint8_t lcOffLimit = repo.getTag(0x9F14)->val.data()[0];
	if ((atc - lastOnlineAtc) > lcOffLimit)
	{
		repo.setTagFlag(0x95, LCONOFFLIMITEXCEEDED);
	}

	uint8_t ucOffLimit = repo.getTag(0x9F23)->val.data()[0];
	if ((atc - lastOnlineAtc) > ucOffLimit)
	{
		repo.setTagFlag(0x95, UCONOFFLIMITEXCEEDED);
	}

	return success;
}

int EmvL2TerminalRiskMng::randomTranSelect()
{
	uint32_t trnAmount = 0, floorLimit = 0, thrsValue, trnTargetPerc, mTargetPerc, targetPerc, randNo, factor;
	uint8_t rnd;

	Tlv* tag9F1B = repo.getTag(0x9F1B);
	if (tag9F1B)
	{
		trnAmount = util.bcd2Int(repo.getTag(0x9F02)->val.data(), repo.getTag(0x9F02)->len);

		if (!repo.isTagExist(0x9F03))
		{
			util.bcd2Int(repo.getTag(0x9F03)->val.data(), repo.getTag(0x9F03)->len);
		}

		floorLimit = util.bin2Int(tag9F1B->val.data(), tag9F1B->len);
		if (trnAmount >= floorLimit)
		{
			repo.setTagFlag(0x95, FLOORLIMITEXCEEDED);
			return success;
		}
	}

	if (!repo.isTagExist(0xDF8B11) || !repo.isTagExist(0xDF8B15) || !repo.isTagExist(0xDF8B14))
	{
		return success;
	}

	thrsValue = util.bin2Int(repo.getTag(0xDF8B11)->val.data(), repo.getTag(0xDF8B11)->len);
	targetPerc = util.bin2Int(repo.getTag(0xDF8B15)->val.data(), repo.getTag(0xDF8B15)->len);
	mTargetPerc = util.bin2Int(repo.getTag(0xDF8B14)->val.data(), repo.getTag(0xDF8B14)->len);

	if (success != device.genRand(&rnd, sizeof(rnd)))
	{
		return failure;
	}
	randNo = (rnd % 100) * 100;

	if (trnAmount < thrsValue)
	{
		if ((targetPerc * 100) >= randNo)
		{
			repo.setTagFlag(0x95, TRANRANDSELECTEDONL);
			return success;
		}
	}
	else if (trnAmount >= floorLimit)
	{
		repo.setTagFlag(0x95, FLOORLIMITEXCEEDED);
	}

	else
	{
		factor = ((100 * (trnAmount - thrsValue)) / (floorLimit - thrsValue));
		trnTargetPerc = factor * (mTargetPerc - targetPerc) + targetPerc * 100;

		if (trnTargetPerc >= randNo)
		{
			repo.setTagFlag(0x95, TRANRANDSELECTEDONL);
			return success;
		}
	}

	return success;
}

