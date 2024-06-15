#include <stdio.h>
#include <stdarg.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include "bigdigits.h"
#include "sha1.h"

#ifdef WIN32

#include <WinSCard.h>
#pragma comment(lib, "winscard.lib")

#endif

#include "DeviceImpl.h"

using namespace std;

void memreverse(uint8_t * indata, uint8_t * outdata, int inlen)
{
    int i;
    for (i = 0; i < inlen; i++)
    {
        outdata[i] = indata[inlen - i - 1];
    }
}

DeviceImpl::DeviceImpl() {

}

DeviceImpl::DeviceImpl(const char* rn, LogCallbackFunction logCb, PinCallbackFunction pinCb) {
    readerName = rn;
    logCallback = logCb;
    pinCallback = pinCb;
}

DeviceImpl::~DeviceImpl() {

}

emvl2Ret DeviceImpl::cardReset() {
    DWORD dwLength = 300;
    DWORD dwCardState = 0;
    DWORD dwActiveProtocol = 0;
    DWORD dwShareMode = SCARD_SHARE_SHARED;
    DWORD dwPreferedProtocol = SCARD_PROTOCOL_Tx;
    DWORD dwATRLength = 40;

    unsigned char* atrData = { 0 };

    emvl2Ret rv = failure;

    int ret = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &cardContext);
    if (ret == SCARD_S_SUCCESS)
    {
        ret = SCardConnectA(cardContext, readerName.c_str(), dwShareMode, dwPreferedProtocol, &card, &dwActiveProtocol);
        if (ret == SCARD_S_SUCCESS)
        {
            ret = SCardStatusA(card, (char*)readerName.c_str(), &dwLength, &dwCardState, &dwActiveProtocol, atrData, &dwATRLength);
            if (ret == SCARD_S_SUCCESS)
            {
                rv = success;

                atrData = (unsigned char*)malloc(dwATRLength);

                actIOProtocol.cbPciLength = sizeof(SCARD_IO_REQUEST);

                if (dwActiveProtocol == SCARD_PROTOCOL_T0)
                {
                    protocol = 0;
                    actIOProtocol.dwProtocol = (ULONG_PTR)SCARD_PCI_T0;
                }
                else if (dwActiveProtocol == SCARD_PROTOCOL_T1)
                {
                    protocol = 1;
                    actIOProtocol.dwProtocol = (ULONG_PTR)SCARD_PCI_T1;
                }
                else
                {
                    rv = fallback;
                }
                
            }
        }
    }

    return rv;
}

emvl2Ret DeviceImpl::cardSendReceive(uint8_t* sendData, uint32_t sendDataLength, uint8_t* replyData, uint32_t* replyDataLength) {
    emvl2Ret rv = failure;
    int nRet = -1;

    DWORD dwOutLen = 258;

    logf("APDU Send:\n");
    hexdump(sendData, sendDataLength);

    nRet = SCardTransmit(card
        , (LPSCARD_IO_REQUEST)(UINT_PTR)actIOProtocol.dwProtocol
        , sendData
        , sendDataLength
        , NULL
        , replyData
        , &dwOutLen
    );
    
    if (nRet == SCARD_S_SUCCESS)
    {
        nRet = 0;
        *replyDataLength = dwOutLen;
        rv = success;

        logf("APDU Recv:\n");
        hexdump(replyData, dwOutLen);
    }

    return rv;
}

uint8_t DeviceImpl::cardProtocol() {
    return protocol;
}

emvl2Ret DeviceImpl::pinOfflinePlain(uint8_t *cardSws) {
    if (!pinCallback)
        return success;

    const char* pin = pinCallback();
    this->logf("Offline Plain Pin Entered: %s\n", pin);

    uint8_t sendBuff[13] = { 0 };
    int sendLength = 0;

    uint8_t recvBuff[2] = { 0 };
    uint32_t recvLength = 0;

    char pinBlockData[16] = { 0 };
    int index = 0;

    memset(&pinBlockData[2], 'F', sizeof(pinBlockData) - 2);
    pinBlockData[0] = '2';
    pinBlockData[1] = 0x30 + (uint8_t)strlen(pin);
    memcpy(&pinBlockData[2], pin, strlen(pin));

    index = 0;
    sendBuff[index] = 0x00;
    index++;
    sendBuff[index] = 0x20;
    index++;
    sendBuff[index] = 0x00;
    index++;
    sendBuff[index] = 0x80;
    index++;
    sendBuff[index] = 0x08;
    index++;

    convertStrToBcd(pinBlockData, strlen(pinBlockData) / 2, &sendBuff[index], 0);

    index += sizeof(pinBlockData) / 2;

    sendLength = index;
    cardSendReceive(sendBuff, sendLength, recvBuff, &recvLength);
    memcpy(cardSws, recvBuff, 2);
    return success;
}

emvl2Ret DeviceImpl::pinOfflineEncrypted(uint8_t* publicKeyMod, uint8_t publicKeyModLength, uint8_t* publicKeyExponent, uint8_t publicKeyExponentLength, uint8_t unpredictNumber[8], uint8_t *cardSws) {
    if (!pinCallback)
        return success;

    const char* pin = pinCallback();
    this->logf("Offline Encrypted Pin Entered: %s\n", pin);

    int index = 0;
    char pinBlockData[16] = { 0 };
    uint8_t ucPINEncData[256];
    uint8_t sendBuff[256] = { 0 };
    int sendLength = 0;
    uint8_t recvBuff[2] = { 0 };
    uint32_t recvLength = 0;

    memset(&pinBlockData[2], 'F', sizeof(pinBlockData) - 2);
    pinBlockData[0] = '2';
    pinBlockData[1] = 0x30 + (uint8_t)strlen(pin);
    memcpy(&pinBlockData[2], pin, strlen(pin));

    ucPINEncData[0] = 0x7F;
    convertStrToBcd(pinBlockData, strlen(pinBlockData) / 2, ucPINEncData + 1, 0);
    memcpy(ucPINEncData + 9, unpredictNumber, 8);
    memset(&ucPINEncData[17], 0x74, publicKeyModLength - 17);

    index = 0;
    sendBuff[index] = 0x00;
    index++;
    sendBuff[index] = 0x20;
    index++;
    sendBuff[index] = 0x00;
    index++;
    sendBuff[index] = 0x88;
    index++;
    sendBuff[index] = publicKeyModLength;
    index++;

    rsaDecrypt(publicKeyMod, publicKeyModLength, publicKeyExponent, publicKeyExponentLength, ucPINEncData, publicKeyModLength, &sendBuff[index]);

    index += publicKeyModLength;
    sendLength = index;
    cardSendReceive(sendBuff, sendLength, recvBuff, &recvLength);
    memcpy(cardSws, recvBuff, 2);

    return success;
}

emvl2Ret DeviceImpl::pinOnline(uint8_t* pan, uint8_t len) {
    if (!pinCallback)
        return success;

    const char* pin = pinCallback();
    this->logf("Online Pin Entered: %s\n", pin);
    return success;
}

emvl2Ret DeviceImpl::getDateTime(emvl2DateTime* datetime) {
    time_t t = std::time(0);
    tm* now = std::localtime(&t);

    datetime->year = now->tm_year + 1900;
    datetime->month = now->tm_mon + 1;
    datetime->day = now->tm_mday;
    datetime->hour = now->tm_hour;
    datetime->minute = now->tm_min;    
    datetime->second = now->tm_sec;

    logf("DateTime: %02d/%02d/%04d %02d:%02d:%02d\n", datetime->day, datetime->month, datetime->year, datetime->hour, datetime->minute, datetime->second);    
    return success;
}

void DeviceImpl::logf(const char* format, ...) {
    char dest[1024 * 16];
    va_list argptr;
    va_start(argptr, format);
    vsprintf(dest, format, argptr);
    va_end(argptr);

	std::cout << dest;
    if (logCallback) {
        logCallback(dest);
    }

    //fstream fd;
    //fd.open("kernel.log", ios::out | ios::app);  // Open the file in append mode
    //if (!fd)
    //    cout << "No such file found" << endl;
    //else {
    //    fd << dest;
    //    fd.close();
    //}
}

emvl2Ret DeviceImpl::sha1(uint8_t* data, uint32_t length, uint8_t digest[20]) {
    compute_hash_str(data, length, digest);
    return success;
}

emvl2Ret DeviceImpl::rsaDecrypt(uint8_t* modulus, uint8_t modulusLength, uint8_t* exponent, uint8_t exponentLength, uint8_t* inputData, uint8_t inputDataLength, uint8_t* decryptedData) {
#define OCTETS_PER_DIGIT sizeof(unsigned long)

    int nret;
    const int nsize = (modulusLength + OCTETS_PER_DIGIT - 1) / OCTETS_PER_DIGIT;
    const int nadjustment = nsize * OCTETS_PER_DIGIT - modulusLength;
    uint8_t* pucExpTemp = 0, * pucDataRev = 0, * pucModuleRev = 0, * pucPlainData = 0;

    if (!modulus) {
        return failure;
    }

    pucExpTemp = (uint8_t*)malloc(nsize * OCTETS_PER_DIGIT);
    pucDataRev = (uint8_t*)malloc(nsize * OCTETS_PER_DIGIT);
    pucPlainData = (uint8_t*)malloc(nsize * OCTETS_PER_DIGIT);
    pucModuleRev = (uint8_t*)malloc(nsize * OCTETS_PER_DIGIT);

    if (!pucExpTemp || !pucDataRev || !pucPlainData || !pucModuleRev)
    {
        free(pucExpTemp);
        free(pucDataRev);
        free(pucPlainData);
        free(pucModuleRev);
        return failure;
    }

    memset(pucDataRev, 0, nsize * OCTETS_PER_DIGIT);
    memset(pucModuleRev, 0, nsize * OCTETS_PER_DIGIT);

    memreverse(modulus, pucModuleRev, nsize * OCTETS_PER_DIGIT - nadjustment);
    memreverse(inputData, pucDataRev, nsize * OCTETS_PER_DIGIT - nadjustment);
    memset(pucExpTemp, 0, nsize * OCTETS_PER_DIGIT);
    memcpy(pucExpTemp, exponent, exponentLength);

    if (0 == (nret = mpModExp((DIGIT_T*)pucPlainData, (DIGIT_T*)pucDataRev, (DIGIT_T*)pucExpTemp, (DIGIT_T*)pucModuleRev, nsize)))
    {
        memreverse(pucPlainData, decryptedData, modulusLength);
    }

    free(pucExpTemp);
    free(pucDataRev);
    free(pucPlainData);
    free(pucModuleRev);

    if (nret)
    {
        return failure;
    }

    return success;
}

emvl2Ret DeviceImpl::genRand(uint8_t* unpredictNumber, int len) {
    srand((unsigned int)time(NULL));

    for (int i = 0; i < len; i++)
    {
        unpredictNumber[i] = rand();
    }

    return success;
}

void DeviceImpl::hexdump(void* ptr, int buflen) {
    if (!ptr)
        return;

    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        logf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                logf("%02x ", buf[i + j]);
            else
                logf("   ");
        logf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                logf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        logf("\n");
    }
}

void DeviceImpl::convertStrToBcd(const char* src, int len, uint8_t* dest, int RL)
{
    int i = 0, strLen = strlen(src);
    uint8_t subVal;
    strLen = strLen > len * 2 ? len * 2 : strLen;
    memset(dest, 0, len);
    if (RL == 1)
    {
        for (i = 0; i < strLen; i++)
        {
            subVal = (*(src + (strLen - i))) >= (uint8_t)'A' ? 0x37 : 0x30;
            *(dest + (i / 2)) = i % 2 != 0 ? ((*((uint8_t*)(src + i)) - subVal) & 0x0F) | (*(dest + (i / 2))) : (((*((uint8_t*)(src + i)) - subVal) & 0x0F) << 4);
        }
    }
    else if (RL == 0)
    {
        len--;
        for (i = 1; i <= strLen; i++)
        {
            subVal = (*(src + (strLen - i))) >= (uint8_t)'A' ? 0x37 : 0x30;
            *(dest + (len)) = i % 2 != 0 ? ((*((uint8_t*)(src + (strLen - i))) - subVal) & 0x0F) : (((*((uint8_t*)(src + (strLen - i))) - subVal) & 0x0F) << 4) | (*(dest + (len)));

            if (i % 2 == 0)
            {
                len--;
            }
        }
    }
}