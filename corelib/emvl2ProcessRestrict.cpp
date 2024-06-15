#include "emvl2ProcessRestrict.h"

EmvL2ProcessRestrict::EmvL2ProcessRestrict(IDevice& device) : device(device), repo(EmvL2Repo::getInstance()), command(EmvL2Command::getInstance()), util(EmvL2Util::getInstance()) {
}

EmvL2ProcessRestrict::~EmvL2ProcessRestrict() {

}

uint8_t EmvL2ProcessRestrict::perform() {		
	Tlv* tag9F09 = repo.getTag(0x9F09);
	Tlv* tag9F08 = repo.getTag(0x9F08);

	if (repo.isTagExist(0x9F09) && (memcmp(tag9F09->val.data(), tag9F08->val.data(), tag9F08->len) != 0))
	{
		repo.setTagFlag(0x95, MISSMATCHAPPVERSIONS);
	}

	if (repo.isTagExist(0x9F07))
	{
		Tlv* tag9F1A = repo.getTag(0x9F1A);
		Tlv* tag5F28 = repo.getTag(0x5F28);

		if (tag9F1A && tag5F28)
		{
			uint8_t ttype = repo.getTag(0x9C)->val.data()[0];
			if (memcmp(tag9F1A->val.data(), tag5F28->val.data(), tag5F28->len) == 0)
			{
				if (ttype == TRNCASH)
				{
					if (!repo.isTagFlag(0x9F40, ACCASH))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}

					if (!repo.isTagFlag(0x9F07, DOMESTICCASHVALID))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}
				}
				else if (ttype == TRNSALE)
				{
					if (!repo.isTagFlag(0x9F40, ACGOODS))
					{
						if (!repo.isTagFlag(0x9F40, ACSERVICES))
						{
							repo.setTagFlag(0x95, SERVICENOTALLOWED);
						}
					}

					if (!repo.isTagFlag(0x9F07, DOMESTICGOODSVALID))
					{
						if (!repo.isTagFlag(0x9F07, DOMESTICSERVICESVALID))
						{
							repo.setTagFlag(0x95, SERVICENOTALLOWED);
						}
					}
				}
				else if (ttype == TRNCASHBACK)
				{
					if (!repo.isTagFlag(0x9F40, ACCASHBACK))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}

					if (!repo.isTagFlag(0x9F07, DOMESTICCASHBACKALLOWED))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}
				}
			}
			else
			{
				if (ttype == TRNCASH)
				{
					if (!repo.isTagFlag(0x9F40, ACCASH))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}

					if (!repo.isTagFlag(0x9F07, INTERNATIONALCASHVALID))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}
				}
				else if (ttype == TRNSALE)
				{
					if (!repo.isTagFlag(0x9F40, ACGOODS))
					{
						if (!repo.isTagFlag(0x9F40, ACSERVICES))
						{
							repo.setTagFlag(0x95, SERVICENOTALLOWED);
						}
					}

					if (!repo.isTagFlag(0x9F07, INTERNATIONALGOODSVALID))
					{
						if (!repo.isTagFlag(0x9F07, INTERNATIONALSERVICESVALID))
						{
							repo.setTagFlag(0x95, SERVICENOTALLOWED);
						}
					}
				}
				else if (ttype == TRNCASHBACK)
				{
					if (!repo.isTagFlag(0x9F40, ACCASHBACK))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}

					if (!repo.isTagFlag(0x9F07, INTERCASHBACKALLOWED))
					{
						repo.setTagFlag(0x95, SERVICENOTALLOWED);
					}
				}
			}
		}

		Tlv* tag9F35 = repo.getTag(0x9F35);

		if (tag9F35->val.data()[0] == 0x15 || tag9F35->val.data()[0] == 0x14)
		{
			if (!repo.isTagFlag(0x9F07, ATMSVALID))
			{
				repo.setTagFlag(0x95, SERVICENOTALLOWED);
			}
		}
		else
		{
			if (!repo.isTagFlag(0x9F07, NONATMSVALID))
			{
				repo.setTagFlag(0x95, SERVICENOTALLOWED);
			}
		}
	}

	int intCurrentDate = 0;
	uint8_t* currentDate = repo.getTag(0x9A)->val.data();

	int  intEffDate = 0;
	uint8_t* appEffDate = repo.getTag(0x5F25)->val.data();
	if (appEffDate[0] < 0x50)
	{
		intEffDate = appEffDate[0] + 0x100;
	}
	else
	{
		intEffDate = (int)appEffDate[0];
	}

	if (currentDate[0] < 0x50)
	{
		intCurrentDate = (int)currentDate[0] + 0x100;
	}
	else
	{
		intCurrentDate = (int)currentDate[0];
	}

	if (intEffDate > intCurrentDate)
	{
		repo.setTagFlag(0x95, APPNOTYETEFFECTIVE);
	}
	else if (intEffDate == intCurrentDate)
	{
		if (appEffDate[1] > currentDate[1])
		{
			repo.setTagFlag(0x95, APPNOTYETEFFECTIVE);
		}

		if (appEffDate[1] == currentDate[1])
		{
			if (appEffDate[2] > currentDate[2])
			{
				repo.setTagFlag(0x95, APPNOTYETEFFECTIVE);
			}
		}
	}

	int  intExpDate = 0;
	uint8_t* appExpDate = repo.getTag(0x5F24)->val.data();
	if (appExpDate[0] < 0x50)
	{
		intExpDate = (int)appExpDate[0] + 0x100;
	}
	else
	{
		intExpDate = (int)appExpDate[0];
	}

	if (currentDate[0] < 0x50)
	{
		intCurrentDate = (int)currentDate[0] + 0x100;
	}
	else
	{
		intCurrentDate = (int)currentDate[0];
	}

	if (intExpDate < intCurrentDate)
	{
		repo.setTagFlag(0x95, EXPIREDAPP);
	}

	if (intExpDate == intCurrentDate)
	{
		if (appExpDate[1] < currentDate[1])
		{
			repo.setTagFlag(0x95, EXPIREDAPP);
		}

		if (appExpDate[1] == currentDate[1])
		{
			if (appExpDate[2] < currentDate[2])
			{
				repo.setTagFlag(0x95, EXPIREDAPP);
			}
		}
	}

	return success;
}