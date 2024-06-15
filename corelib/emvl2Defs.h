#pragma once
#include <stdint.h>
#include <vector>
#include "emvl2TagDef.h"

#define PUBKEYMODULUSLEN		256
#define APDUBUFFERLEN			(256 + 2)
#define DOLBUFFERLEN 			512

#define AAC						0x00
#define TC						0x40
#define ARQC					0x80
#define AAR						0xC0
#define ADVICE					0x08

typedef enum
{
	success = 0,
	failure,
	fallback,
	cardCommError,
	cardDataLenError,
	noMatchingApp,
	pseNotSupportedByCard,
	emvDataFormatError,
	emvMissingMandatoryDataError,
	emvLenError,
	noMemory,
	dublicateData,
	cardRejected,
	cardBlocked,
	aflLenError,
	sfiLenError,
	aflDataError,
	noTag,
	expDateFormatError,
	effDateFormatError,
	cvmAipNotSupported,
	cvmTag8EMissing,
	cvmTag8ERuleMissing,
	cvmTag8EFormatError,
	cvmCondCodeNotSupported,
	cvmIsNotSupported,
	pinFailed,
	pinCancel,
	pinTimeout,
	pinMalfunction,
	pinPrmError,
	cvmTypeUnknown,
	pintryCountError,
	emvCryptogramTypeError,
	genSecACWarning,
	emvServiceNotAllowed,
	emvSelectAppRetry,
	amountError,
	trnTypeError,
	aipNotFound,
	aflNotFound,
	aac,
	tc,
	arqc,
	aar
} emvl2Ret;

typedef struct
{
	uint32_t tag;
	uint32_t len;
	std::vector<uint8_t> val;
}Tlv;

typedef struct
{
	uint8_t day;
	uint8_t month;
	uint16_t year;
	uint8_t second;
	uint8_t minute;
	uint8_t hour;
} emvl2DateTime;

typedef struct
{
	uint8_t ucRid[5];
	uint8_t ucPKExp[3];
	uint8_t ucPKExpLen;
	uint8_t ucPKModulo[256];
	uint8_t ucPKModuloLen;
	uint8_t ucPKIndex;
} emvl2CAKey;

typedef struct
{
	uint8_t aidLen;
	uint8_t *aid;
	int len;
	uint8_t* data;
} emvl2AIDPrms;

typedef struct
{
	Tlv tag9F06;
	Tlv tag84;
	Tlv tag4F;
	Tlv tag50;
	Tlv tag87;
	Tlv tag9F38;
	Tlv tag5F2D;
	Tlv tag5F56;
	Tlv tag9F11;
	Tlv tag9F12;
	Tlv tagBF0C;
	Tlv tag5F55;
	Tlv tag42;
} emvl2AidInfo;

typedef struct
{
	uint8_t CLA;
	uint8_t INS;
	uint8_t P1;
	uint8_t P2;
	uint8_t Lc;
	uint8_t* sdata;
	uint8_t Le;
	uint8_t rdata[APDUBUFFERLEN];
	uint16_t rlen;
	uint8_t SW1;
	uint8_t SW2;
	bool forceData;
} emvl2Apdu;

typedef enum
{
	FNULL,
	FANS,
	FAN,
	FNUM,
	FCNM,
} emvl2TagDataFormat;

typedef enum
{
	ANULL,
	ASDA,
	ADDA,
	ACDA
} emvl2DataAuth;

typedef enum
{
	PKCAMOD = 0,
	PKICCMOD,
	PKISSMOD,
	PKPINMOD
} emvl2PkMode;

