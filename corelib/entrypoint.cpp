#include "entrypoint.h"
#include "emvl2Impl.h"
#include "l1/deviceImpl.h"
#include <iostream>
#include "emvl2Defs.h"

using namespace std;

EMVL2EXPORT int emvl2Version() {
	return 2;
}

EMVL2EXPORT int emvl2Init(const char* readerName, LogCallbackFunction logCb, PinCallbackFunction pinCb) {
	DeviceImpl* device = new DeviceImpl(readerName, logCb, pinCb);
	EmvL2Impl::getInstance().init(device);
	EmvL2Impl::getInstance().getDevice().logf("Init Done\n");
	return 0;
}

EMVL2EXPORT int emvl2AddCaKey(const char* rid, uint8_t keyId, const char* modules, const char* exponent) {		
	EmvL2Impl& emvl2Impl = EmvL2Impl::getInstance();

	int modulesLen = strlen(modules) / 2;
	int exponentLen = strlen(exponent) / 2;
	int ridLen = strlen(exponent) / 2;

	uint8_t* ridBuff =  EmvL2Util::getInstance().hexStr2ByteArray(rid);
	uint8_t* modulesBuff = EmvL2Util::getInstance().hexStr2ByteArray(modules);
	uint8_t* exponentBuff = EmvL2Util::getInstance().hexStr2ByteArray(exponent);

	int rv = emvl2Impl.addCAKey(ridBuff, keyId, modulesLen, modulesBuff, exponentBuff, exponentLen);

	free(ridBuff);
	free(modulesBuff);
	free(exponentBuff);

	return rv;
}

EMVL2EXPORT int emvl2AddAidPrms(const char* aid, const char* data) {
	EmvL2Impl& emvl2Impl = EmvL2Impl::getInstance();

	emvl2Impl.getDevice().logf("%s:%s\n", aid, data);

	emvl2AIDPrms aidPrms = {0};
	aidPrms.aidLen = (uint8_t)(strlen(aid) / 2);
	aidPrms.aid = EmvL2Util::getInstance().hexStr2ByteArray(aid);
	aidPrms.len = strlen(data) / 2;
	if (aidPrms.len > 0)
		aidPrms.data = EmvL2Util::getInstance().hexStr2ByteArray(data);

	int rv = emvl2Impl.addAidPrms(aidPrms);
	return rv;
}

EMVL2EXPORT int emvl2Start(uint8_t tranType, uint8_t accountType, const char* amount, const char* otherAmount) {
	EmvL2Impl& emvl2Impl = EmvL2Impl::getInstance();

	emvl2Impl.getDevice().logf("Starting Transaction\n");

	uint8_t termDecision = 0; 
	uint8_t cardDecision = 0;

	uint8_t rv = failure;
	rv = emvl2Impl.getDevice().cardReset();
	emvl2Impl.getDevice().logf("cardReset:%d\n", rv);
	if(rv == emvl2Ret::success)
	{
		rv = emvl2Impl.applicationSelection();
		emvl2Impl.getDevice().logf("applicationSelection:%d\n", rv);
		if (rv == emvl2Ret::success) {
			rv = emvl2Impl.gpo(tranType, accountType, amount, otherAmount);
			emvl2Impl.getDevice().logf("gpo:%d\n", rv);
			if (rv == emvl2Ret::success) {
				rv = emvl2Impl.readAppData();
				emvl2Impl.getDevice().logf("readAppData:%d\n", rv);
				if (rv == emvl2Ret::success) {
					rv = emvl2Impl.offlineDataAuth();
					emvl2Impl.getDevice().logf("offlineDataAuth:%d\n", rv);
					if (rv == success) {
						rv = emvl2Impl.processRestrict();
						emvl2Impl.getDevice().logf("processRestrict:%d\n", rv);
						if (rv == emvl2Ret::success) {
							rv = emvl2Impl.processCVM();
							emvl2Impl.getDevice().logf("processCVM:%d\n", rv);
							if (rv == emvl2Ret::success) {
								rv = emvl2Impl.terminalRiskMng();
								emvl2Impl.getDevice().logf("terminalRiskMng:%d\n", rv);
								if (rv == emvl2Ret::success) {
									rv = emvl2Impl.termActionAnalysis(&termDecision);
									emvl2Impl.getDevice().logf("termActionAnalysis:%d\n", rv);
									if (rv == emvl2Ret::success) {
										rv = emvl2Impl.genAC1(termDecision, &cardDecision);
										emvl2Impl.getDevice().logf("genAC1:%d\n", rv);
										if (rv == emvl2Ret::success) {
											emvl2Impl.getDevice().logf("AC is generated successfully\n");

											switch (cardDecision)
											{
											case AAC:
												rv = emvl2Ret::aac;
												break;
											case TC:
												rv = emvl2Ret::tc;
												break;
											case ARQC:
												rv = emvl2Ret::arqc;
												break;
											case AAR:
												rv = emvl2Ret::aar;
												break;
											default:
												break;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return rv;
}

EMVL2EXPORT int emvl2Completion(bool isHostReject, uint8_t* Decision, uint8_t* AdviceReversal) {
	EmvL2Impl& emvl2Impl = EmvL2Impl::getInstance();

	emvl2Impl.getDevice().logf("Compliting Transaction\n");

	return emvl2Impl.genAC2(isHostReject, Decision, AdviceReversal);
}

EMVL2EXPORT int emvl2CardReset() {
	EmvL2Repo& repo = EmvL2Repo::getInstance();
	return EmvL2Impl::getInstance().getDevice().cardReset();
}

EMVL2EXPORT int emvl2ApplicationSelection() {
	return EmvL2Impl::getInstance().applicationSelection();
}

EMVL2EXPORT int emvl2Gpo(uint8_t tType, uint8_t aType, const char* amount, const char* otherAmount) {
	return EmvL2Impl::getInstance().gpo(tType, aType, amount, otherAmount);
}

EMVL2EXPORT int emvl2ReadAppData() {
	return EmvL2Impl::getInstance().readAppData();
}

EMVL2EXPORT int emvl2OfflineDataAuth() {
	return EmvL2Impl::getInstance().offlineDataAuth();
}

EMVL2EXPORT int emvl2ProcessRestrict() {
	return EmvL2Impl::getInstance().processRestrict();
}

EMVL2EXPORT int emvl2ProcessCVM() {
	return EmvL2Impl::getInstance().processCVM();
}

EMVL2EXPORT int emvl2TerminalRiskMng() {
	return EmvL2Impl::getInstance().terminalRiskMng();
}

EMVL2EXPORT int emvl2TermActionAnalysis(uint8_t* terminalDecision) {
	return EmvL2Impl::getInstance().termActionAnalysis(terminalDecision);
}

EMVL2EXPORT int emvl2GenAC1(uint8_t terminalDecision, uint8_t* cardDecision) {
	int rv = EmvL2Impl::getInstance().genAC1(terminalDecision, cardDecision);
	return rv;
}

EMVL2EXPORT int emvl2GenAC2(bool isHostReject, uint8_t* decision, uint8_t* adviceReversal) {
	return EmvL2Impl::getInstance().genAC2(isHostReject, decision, adviceReversal);
}

EMVL2EXPORT int emvl2GetTag(const uint32_t tag, uint8_t* data, int maxLen) {
	int rv = 0;
	EmvL2Repo& repo = EmvL2Repo::getInstance();
	Tlv* tlv = repo.getTag(tag);

	if (tlv) {
		rv = tlv->len;
		if (data) {
			if(maxLen > rv)
				memcpy(data, tlv->val.data(), rv);
			else
				memcpy(data, tlv->val.data(), maxLen);
		}
	}

	return rv;
}

