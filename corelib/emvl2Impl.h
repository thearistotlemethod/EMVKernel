#pragma once

#include "IDevice.h"
#include "emvl2Repo.h"
#include "emvl2AppSelection.h"
#include "emvl2ReadAppData.h"
#include "emvl2OfflineDataAuth.h"
#include "emvl2ProcessRestrict.h"
#include "emvl2ProcessCVM.h"
#include "emvl2TerminalRiskMng.h"
#include "emvl2TermActionAnalysis.h"
#include "emvl2GenAC1.h"
#include "emvl2GenAC2.h"
#include "emvl2Command.h"
#include "emvl2GPO.h"

#define LIBVERSION		"1.0.0"

class EmvL2Impl {
private:
	EmvL2Impl();

public:	
	static EmvL2Impl& getInstance();
	~EmvL2Impl();

	uint8_t init(IDevice* device);
	IDevice& getDevice();
	void release();
	uint8_t initTransaction(uint8_t* FallbackOccured);
	uint8_t applicationSelection();
	uint8_t selectFromCandList();
	uint8_t selectMatchingApp(uint8_t* Language, int SelectedAppIndex);
	uint8_t gpo(uint8_t TransactionType, uint8_t AccountType, const char* Amount, const char* OtherAmount);
	uint8_t readAppData();
	uint8_t offlineDataAuth();
	uint8_t processRestrict();
	uint8_t processCVM();
	uint8_t terminalRiskMng();
	uint8_t termActionAnalysis(uint8_t* TerminalDecision);
	uint8_t genAC1(uint8_t TerminalDecision, uint8_t* CardDecision);
	uint8_t genAC2(uint8_t isOnlineError, uint8_t* Decision, uint8_t* AdviceReversal);
	uint8_t addCAKey(uint8_t* rid, uint8_t keyId, uint8_t modulesLen, uint8_t* modules, uint8_t* exponent, uint8_t exponentLen);
	uint8_t addAidPrms(emvl2AIDPrms prms);
	uint8_t forceOnline(void);
	uint8_t getEMVDataEl(uint32_t Tag, uint8_t* TagValue, uint16_t* TagValueLength, uint8_t* Format);
	uint8_t setEMVDataEl(uint8_t* tlvBuffer, uint8_t tlvBufferLen);
	uint8_t resetTransLogAmount(void);
	void version(char* vKernel);
	uint8_t setTranSeqCounter(uint32_t tscValue);
	void clearLogFiles();
	uint8_t getChipFields(uint8_t* buffer, int length);
	uint8_t applyHostSystemResponse(uint8_t* buffer, int length);
	void setAccountType(uint8_t AccountType);

private:
	static EmvL2Impl* instance;
	IDevice* device = NULL;
	EmvL2AppSelection* appSelectionIns = NULL;
	EmvL2GPO* gpoIns = NULL;
	EmvL2ReadAppData* readAppDataIns = NULL;
	EmvL2OfflineDataAuth* offlineDataAuthIns = NULL;
	EmvL2ProcessRestrict* processRestrictIns = NULL;
	EmvL2ProcessCVM* processCVMIns = NULL;
	EmvL2TerminalRiskMng* terminalRiskMngIns = NULL;
	EmvL2TermActionAnalysis* termActionAnalysisIns = NULL;
	EmvL2GenAC1* genAC1Ins = NULL;
	EmvL2GenAC2* genAC2Ins = NULL;
};