#include "emvl2Util.h"
#include "emvl2Defs.h"
#include "emvl2Repo.h"

#define ISODD(p)          ((p%2)==1)

EmvL2Util* EmvL2Util::instance = NULL;

EmvL2Util& EmvL2Util::getInstance() {
	if (!instance) {
		instance = new EmvL2Util();
	}
	return *instance;
}

EmvL2Util::EmvL2Util() : repo(EmvL2Repo::getInstance()) {
	device = NULL;
}

EmvL2Util::~EmvL2Util() {

}

emvl2Ret EmvL2Util::init(IDevice* device) {
	this->device = device;

	return success;
}

uint32_t EmvL2Util::bin2Int(uint8_t* in, uint8_t inLength)
{
	uint32_t ret;
	uint8_t i, j, buf[sizeof(uint32_t)];

	if (inLength > sizeof(uint32_t))
	{
		ret = 0;
	}
	else
	{
		for (i = 0; i < sizeof(uint32_t) - inLength; i++)
		{
			buf[i] = 0;
		}
		for (j = i; j < sizeof(uint32_t); j++)
		{
			buf[j] = in[j - i];
		}
		ret = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);
	}

	return ret;
}

uint32_t EmvL2Util::bcd2Int(uint8_t* in, uint8_t inLength)
{
	uint32_t rv = 0;

	while (inLength--)
	{
		rv = (rv * 100) + (((*in >> 4) & 0x0F) * 10) + (*in & 15);
		in++;
	}

	return rv;
}

void EmvL2Util::bcd2Str(uint8_t* in, uint16_t inLength, uint8_t* out)
{
	const uint8_t h[] = "0123456789ABCDEF";
	uint16_t i;

	for (i = 0; i < inLength; i++)
	{
		*out++ = h[(in[i] >> 4) & 0x0F];
		*out++ = h[in[i] & 0x0F];
	}
	*out = 0;
}

uint8_t EmvL2Util::adjustYear(uint16_t year)
{
	uint8_t rv;

	if (year > 2000)
	{
		rv = (uint8_t)(year - 2000);
	}
	else if (year > 1900)
	{
		rv = (uint8_t)(year - 1900);
	}
	else if (year < 100)
	{
		rv = (uint8_t)year;
	}
	else
	{
		rv = (uint8_t)year;
	}

	return rv;
}

uint8_t EmvL2Util::byte2Bcd(uint8_t b)
{
	return ((b / 10) << 4) | (b % 10);
}

void EmvL2Util::collectDolData(uint8_t* dol, int dolLen, uint8_t* dolData, uint8_t* dolDataLen)
{
	int index = 0;
	uint8_t actualLength = 0, lenInDOL = 0, tagLen = 0;
	uint8_t tcHash[20] = { 0 }, lenLen = 0;
	uint32_t valueOfTag = 0;
	int16_t indexOfTag = 0;
	*dolDataLen = 0;

	while (index < dolLen)
	{
		valueOfTag = repo.parseTag(&dol[index], &tagLen);
		index += tagLen;

		Tlv* tag = repo.getTag(valueOfTag);

		if (tag)
		{
			lenInDOL = dol[index++];

			if (valueOfTag == 0x98)
			{
				calculateTCHash(tcHash);

				if (lenInDOL == 20)
				{
					memcpy(&dolData[*dolDataLen], tcHash, lenInDOL);
					*dolDataLen += lenInDOL;
					continue;
				}
				else if (lenInDOL > 20)
				{
					memset(&dolData[*dolDataLen], 0, lenInDOL - 20);
					*dolDataLen += lenInDOL - 20;
					memcpy(&dolData[*dolDataLen], tag->val.data(), 20);
					*dolDataLen += 20;
					continue;
				}
			}

			actualLength = tag->len;
			if (actualLength == 0)
			{
				memset(&dolData[*dolDataLen], 0, lenInDOL);
				*dolDataLen += lenInDOL;
			}
			else
			{
				if (lenInDOL < actualLength)
				{
					if (repo.cardBrand() == BVISA)
					{
						if ((repo.getTagFormat(valueOfTag) == FNUM))
						{
							int align = tag->len - lenInDOL;
							memcpy(&dolData[*dolDataLen], &tag->val.data()[align], lenInDOL);
							*dolDataLen += lenInDOL;
						}
						else
						{
							memcpy(&dolData[*dolDataLen], tag->val.data(), lenInDOL);
							*dolDataLen += lenInDOL;
						}
					}
					else if ((repo.cardBrand() == BEUROPAY) || (repo.cardBrand() == BMASTER))
					{
						if (repo.getTagFormat(valueOfTag) == FNUM)
						{
							int align = tag->len - lenInDOL;
							memcpy(&dolData[*dolDataLen], &tag->val.data()[align], lenInDOL);
							*dolDataLen += lenInDOL;
						}
						else
						{
							memcpy(&dolData[*dolDataLen], tag->val.data(), lenInDOL);
							*dolDataLen += lenInDOL;
						}
					}
					else
					{
						if (repo.getTagFormat(valueOfTag) == FNUM)
						{
							int align = tag->len - lenInDOL;
							memcpy(&dolData[*dolDataLen], &tag->val.data()[align], lenInDOL);
							*dolDataLen += lenInDOL;
						}
						else
						{
							memcpy(&dolData[*dolDataLen], tag->val.data(), lenInDOL);
							*dolDataLen += lenInDOL;
						}
					}
				}
				else if (lenInDOL > actualLength)
				{
					if (repo.getTagFormat(valueOfTag) == FNUM)
					{
						memset(&dolData[*dolDataLen], 0, lenInDOL -  tag->len);
						*dolDataLen += lenInDOL - tag->len;
						memcpy(&dolData[*dolDataLen], tag->val.data(), actualLength);
						*dolDataLen += actualLength;
					}
					else if (repo.getTagFormat(valueOfTag) == FCNM)
					{
						memcpy(&dolData[*dolDataLen], tag->val.data(), actualLength);
						*dolDataLen += actualLength;
						memset(&dolData[*dolDataLen], 0xFF, lenInDOL - actualLength);
						*dolDataLen += lenInDOL - tag->len;
					}
					else
					{
						memcpy(&dolData[*dolDataLen], tag->val.data(), actualLength);
						*dolDataLen += tag->len;
						memset(&dolData[*dolDataLen], 0, lenInDOL - actualLength);
						*dolDataLen += lenInDOL - actualLength;
					}
				}
				else
				{
					memcpy(&dolData[*dolDataLen], tag->val.data(), lenInDOL);
					*dolDataLen += lenInDOL;
				}
			}
			continue;
		}
		else
		{
			if (index < dolLen)
			{
				lenInDOL = repo.parseLen(&dol[index], &lenLen);
				index += lenLen;
				memset(&dolData[*dolDataLen], 0, lenInDOL);
				*dolDataLen += lenInDOL;
			}
			else
			{
				dolData[*dolDataLen] = 0;
				*dolDataLen += 1;
			}
		}
	}
}

void EmvL2Util::calculateTCHash(uint8_t* tcHash)
{
	uint8_t tdolData[DOLBUFFERLEN];
	uint8_t* tdol;
	uint8_t tdolDataLen = 0;
	int tdolLen = 0;

	Tlv* tag97 = repo.getTag(0x97);
	if (!tag97)
	{
		Tlv* tagDF8B13 = repo.getTag(0xDF8B13);

		tdolLen = tagDF8B13->len;
		tdol = tagDF8B13->val.data();

		if (tdolLen != 0)
		{
			repo.setTagFlag(0x95, DEFAULTTDOLUSED);
		}
	}
	else {
		tdolLen = tag97->len;
		tdol = tag97->val.data();
	}

	collectTdolData(tdol,tdolLen, tdolData, &tdolDataLen);
	device->sha1(tdolData, tdolDataLen, tcHash);
}

void EmvL2Util::collectTdolData(uint8_t* dol, int dolLen, uint8_t* dolData, uint8_t* dolDataLen)
{
	int index = 0;
	uint8_t actualLength, lengthInDOL, tagLen;
	uint32_t valueOfTag = 0;
	int16_t indexOfTag = 0;
	*dolDataLen = 0;

	while (index < dolLen)
	{
		valueOfTag = repo.parseTag(&dol[index], &tagLen);
		index += tagLen;

		Tlv* tag = repo.getTag(valueOfTag);

		if (tag)
		{
			lengthInDOL = dol[index++];

			actualLength = tag->len;
			if (actualLength == 0)
			{
				memset(&dolData[*dolDataLen], 0, lengthInDOL);
				*dolDataLen += lengthInDOL;
			}
			else
			{
				if (lengthInDOL < actualLength)
				{
					if (repo.getTagFormat(valueOfTag) == FNUM)
					{
						int align = tag->len - lengthInDOL;
						memcpy(&dolData[*dolDataLen], &tag->val.data()[align], lengthInDOL);
						*dolDataLen += lengthInDOL;
					}
					else
					{
						memcpy(&dolData[*dolDataLen], tag->val.data(), lengthInDOL);
						*dolDataLen += lengthInDOL;
					}
				}
				else if (lengthInDOL > actualLength)
				{
					if ((repo.getTagFormat(valueOfTag) == FNUM))
					{
						memset(&dolData[*dolDataLen], 0, lengthInDOL - tag->len);
						*dolDataLen += (lengthInDOL - actualLength);
						memcpy(&dolData[*dolDataLen], tag->val.data(), actualLength);
						*dolDataLen += actualLength;
					}
					else if (repo.getTagFormat(valueOfTag) == FCNM)
					{
						memcpy(&dolData[*dolDataLen], tag->val.data(), actualLength);
						*dolDataLen += actualLength;
						memset(&dolData[*dolDataLen], 0xFF, lengthInDOL - actualLength);
						*dolDataLen += (lengthInDOL - actualLength);
					}
					else
					{
						memcpy(&dolData[*dolDataLen], tag->val.data(), actualLength);
						*dolDataLen += actualLength;
						memset(&dolData[*dolDataLen], 0, lengthInDOL - actualLength);
						*dolDataLen += lengthInDOL - actualLength;
					}
				}
				else
				{
					memcpy(&dolData[*dolDataLen], tag->val.data(), lengthInDOL);
					*dolDataLen += lengthInDOL;
				}
			}
			continue;
		}
		else
		{
			lengthInDOL = dol[index++];
			memset(&dolData[*dolDataLen], 0, lengthInDOL);
			*dolDataLen += lengthInDOL;
		}
	}
}

uint8_t* EmvL2Util::str2Bcd(uint8_t* str, uint16_t str_len, uint8_t* bcd, uint16_t bcdlen)
{
	uint16_t i, index;
	uint8_t lnibble = 0;
	uint8_t unibble = 0;
	uint8_t* str_buf;
	uint16_t str_buf_len;

	str_buf = (uint8_t*)malloc(str_len + str_len % 2);
	if (NULL == str_buf)
	{
		return NULL;
	}

	if (ISODD(str_len))
	{
		str_buf[0] = '0';
		memcpy(str_buf + 1, str, str_len);
		str_buf_len = str_len + 1;
	}
	else
	{
		memcpy(str_buf, str, str_len);
		str_buf_len = str_len;
	}

	memset(bcd, 0, bcdlen);
	index = bcdlen - (str_len + 1) / 2;

	for (i = 0; i < str_buf_len; i++)
	{
		if (!ISODD(i))
		{
			if ((str_buf[i] >= '0') && (str_buf[i] <= '9'))
			{
				unibble = str_buf[i] - '0';
			}
			else if ((str_buf[i] >= 'A') && (str_buf[i] <= 'F'))
			{
				unibble = str_buf[i] - 0x37;
			}
			else
			{
				free(str_buf);
				return NULL;
			}

			bcd[index + i / 2] = unibble;
		}
		else
		{
			if ((str_buf[i] >= '0') && (str_buf[i] <= '9'))
			{
				lnibble = str_buf[i] - '0';
			}
			else if ((str_buf[i] >= 'A') && (str_buf[i] <= 'F'))
			{
				lnibble = str_buf[i] - 0x37;
			}
			else
			{
				free(str_buf);
				return NULL;
			}

			bcd[index + i / 2] = (unibble << 4) | (lnibble);
		}
	}

	free(str_buf);
	return bcd;
}

uint8_t* EmvL2Util::hexStr2ByteArray(const char* hexStr)
{
	int len = strlen(hexStr);

	uint8_t* buff = (uint8_t*)malloc(len / 2);
	if (buff == NULL)
		return NULL;
	int j = 0;

	for (int i = 0; i < len; i++)
	{
		if (i % 2 == 0)
		{
			int valueHigh = (int)(*(hexStr + i));
			int valueLow = (int)(*(hexStr + i + 1));

			valueHigh = hexAsc2Dec(valueHigh);
			valueLow = hexAsc2Dec(valueLow);

			valueHigh *= 16;
			int total = valueHigh + valueLow;
			*(buff + j++) = (uint8_t)total;
		}
	}
	return buff;
}

int EmvL2Util::hexAsc2Dec(int value)
{
	if (value > 47 && value < 59)
	{
		value -= 48;
	}
	else if (value > 96 && value < 103)
	{
		value -= 97;
		value += 10;
	}
	else if (value > 64 && value < 71)
	{
		value -= 65;
		value += 10;
	}
	else
	{
		value = 0;
	}
	return value;
}

