#include "emvl2Impl.h"
#include "emvl2SecUtil.h"

EmvL2Impl* EmvL2Impl::instance = NULL;

EmvL2Impl& EmvL2Impl::getInstance() {
	if (!instance) {
		instance = new EmvL2Impl();
	}
	return *instance;
}

EmvL2Impl::EmvL2Impl() {
	device = NULL;
}

EmvL2Impl::~EmvL2Impl() {

}

uint8_t EmvL2Impl::init(IDevice* device) {
	if (device == NULL) {
		return failure;
	}

	this->device = device;
	EmvL2Repo::getInstance().init(device);
	EmvL2Command::getInstance().init(device);
	EmvL2Util::getInstance().init(device);
	EmvL2SecUtil::getInstance().init(device);

	EmvL2Repo::getInstance().clearCaKeys();
	EmvL2Repo::getInstance().clearAidPrms();

	this->appSelectionIns = new EmvL2AppSelection(*device);
	this->gpoIns = new EmvL2GPO(*device);
	this->readAppDataIns = new EmvL2ReadAppData(*device);
	this->offlineDataAuthIns = new EmvL2OfflineDataAuth(*device);
	this->processRestrictIns = new EmvL2ProcessRestrict(*device);
	this->processCVMIns = new EmvL2ProcessCVM(*device);
	this->termActionAnalysisIns = new EmvL2TermActionAnalysis(*device);
	this->terminalRiskMngIns = new EmvL2TerminalRiskMng(*device);
	this->genAC1Ins = new EmvL2GenAC1(*device);
	this->genAC2Ins = new EmvL2GenAC2(*device);
	return success;
}

IDevice& EmvL2Impl::getDevice() {
	return *this->device;
}

void EmvL2Impl::release() {

}

uint8_t EmvL2Impl::initTransaction(uint8_t* FallbackOccured) {
	return success;
}

uint8_t EmvL2Impl::applicationSelection() {
	return this->appSelectionIns->perform();
}

uint8_t EmvL2Impl::selectFromCandList() {
	return success;
}

uint8_t EmvL2Impl::selectMatchingApp(uint8_t* Language, int SelectedAppIndex) {
	return success;
}

uint8_t EmvL2Impl::gpo(uint8_t TransactionType, uint8_t AccountType, const char* Amount, const char* OtherAmount) {
	return this->gpoIns->perform(TransactionType, AccountType, Amount, OtherAmount);
}

uint8_t EmvL2Impl::readAppData() {
	return this->readAppDataIns->perform();
}

uint8_t EmvL2Impl::offlineDataAuth() {
	return this->offlineDataAuthIns->perform();
}

uint8_t EmvL2Impl::processRestrict() {
	return this->processRestrictIns->perform();
}

uint8_t EmvL2Impl::processCVM() {
	return this->processCVMIns->perform();
}

uint8_t EmvL2Impl::terminalRiskMng() {
	return this->terminalRiskMngIns->perform();
}

uint8_t EmvL2Impl::termActionAnalysis(uint8_t* TerminalDecision) {
	return this->termActionAnalysisIns->perform(TerminalDecision);
}

uint8_t EmvL2Impl::genAC1(uint8_t TerminalDecision, uint8_t* CardDecision) {
	return this->genAC1Ins->perform(TerminalDecision, CardDecision);
}

uint8_t EmvL2Impl::genAC2(uint8_t isOnlineError, uint8_t* Decision, uint8_t* AdviceReversal) {
	return this->genAC2Ins->perform(isOnlineError, Decision, AdviceReversal);
}

uint8_t EmvL2Impl::addCAKey(uint8_t* rid, uint8_t keyId, uint8_t modulesLen, uint8_t* modules, uint8_t* exponent, uint8_t exponentLen) {
	emvl2CAKey key;
	memcpy(key.ucRid, rid, 5);
	key.ucPKIndex = keyId;
	key.ucPKModuloLen = modulesLen;
	memcpy(key.ucPKModulo, modules, modulesLen);
	memcpy(key.ucPKExp, exponent, exponentLen);
	key.ucPKExpLen = exponentLen;

	return EmvL2Repo::getInstance().addCaKey(key);
}

uint8_t EmvL2Impl::addAidPrms(emvl2AIDPrms prms) {
	return EmvL2Repo::getInstance().addAidPrms(prms);
}

uint8_t EmvL2Impl::forceOnline(void) {
	return success;
}

uint8_t EmvL2Impl::getEMVDataEl(uint32_t Tag, uint8_t* TagValue, uint16_t* TagValueLength, uint8_t* Format) {
	return success;
}

uint8_t EmvL2Impl::setEMVDataEl(uint8_t* tlvBuffer, uint8_t tlvBufferLen) {
	return success;
}

uint8_t EmvL2Impl::resetTransLogAmount(void) {
	return success;
}

void EmvL2Impl::version(char* vKernel) {
	if (vKernel != NULL) {
		strcpy(vKernel, LIBVERSION);
	}
}

uint8_t EmvL2Impl::setTranSeqCounter(uint32_t tscValue) {
	return success;
}

void EmvL2Impl::clearLogFiles() {

}

uint8_t EmvL2Impl::getChipFields(uint8_t* buffer, int length) {
	return success;
}

uint8_t EmvL2Impl::applyHostSystemResponse(uint8_t* buffer, int length) {
	return success;
}

void EmvL2Impl::setAccountType(uint8_t AccountType) {

}



