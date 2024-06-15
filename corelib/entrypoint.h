#pragma once

#include "IDevice.h"

#ifdef WIN32
#include <windows.h>
#ifdef EMVL2EXPORT_SYMBOLS
#define EMVL2EXPORT	 extern "C"	__declspec(dllexport)
#else
#define EMVL2EXPORT	extern "C" __declspec(dllimport)
#endif
#else
#define EMVL2EXPORT        extern
#endif

typedef void(__stdcall* LogCallbackFunction)(const char* log);
typedef const char* (__stdcall* PinCallbackFunction)();

EMVL2EXPORT int emvl2Version();
EMVL2EXPORT int emvl2Init(const char *readerName, LogCallbackFunction logCb, PinCallbackFunction pinCb);

EMVL2EXPORT int emvl2CardReset();
EMVL2EXPORT int emvl2ApplicationSelection();
EMVL2EXPORT int emvl2Gpo(uint8_t tranType, uint8_t accountType, const char* amount, const char* otherAmount);
EMVL2EXPORT int emvl2ReadAppData();
EMVL2EXPORT int emvl2OfflineDataAuth();
EMVL2EXPORT int emvl2ProcessRestrict();
EMVL2EXPORT int emvl2ProcessCVM();
EMVL2EXPORT int emvl2TerminalRiskMng();
EMVL2EXPORT int emvl2TermActionAnalysis(uint8_t* terminalDecision);
EMVL2EXPORT int emvl2GenAC1(uint8_t terminalDecision, uint8_t* cardDecision);
EMVL2EXPORT int emvl2GenAC2(bool isHostReject, uint8_t* decision, uint8_t* adviceReversal);

EMVL2EXPORT int emvl2Start(uint8_t ttype, uint8_t atype, const char* amount, const char* otherAmount);
EMVL2EXPORT int emvl2Completion(bool isHostReject, uint8_t* decision, uint8_t* adviceReversal);

EMVL2EXPORT int emvl2AddCaKey(const char* rid, uint8_t keyId, const char* modules, const char* exponent);
EMVL2EXPORT int emvl2AddAidPrms(const char* aid, const char* data);

EMVL2EXPORT int emvl2GetTag(const uint32_t tag, uint8_t* data, int maxLen);