#pragma once
#include "IDevice.h"
#include "emvl2Repo.h"
#include <vector> 

using namespace std;

class EmvL2Util {
private:
	EmvL2Util();

public:
	static EmvL2Util& getInstance();
	~EmvL2Util();
	emvl2Ret init(IDevice* device);	

	uint32_t bin2Int(uint8_t* in, uint8_t inLength);
	uint32_t bcd2Int(uint8_t* in, uint8_t inLength);
	void bcd2Str(uint8_t* in, uint16_t inLength, uint8_t* out);
	uint8_t byte2Bcd(uint8_t b);
	uint8_t* str2Bcd(uint8_t* str, uint16_t str_len, uint8_t* bcd, uint16_t bcdlen);
	uint8_t* hexStr2ByteArray(const char* hexStr);
	int hexAsc2Dec(int value);
	uint8_t adjustYear(uint16_t year);
	void collectDolData(uint8_t* dol, int dolLen, uint8_t* dolData, uint8_t* dolDataLen);
private:
	void calculateTCHash(uint8_t* tcHash);
	void collectTdolData(uint8_t* dol, int dolLen, uint8_t* dolData, uint8_t* dolDataLen);

private:
	static EmvL2Util* instance;
	IDevice* device;
	EmvL2Repo& repo;
};
