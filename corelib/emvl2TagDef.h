#pragma once

// Application Interchange Profile
#define SDASupported    0x40
#define DDASupported    0x20
#define CVMSupported    0x10
#define TRMNGPerformed  0x08
#define IAUTHSupported	0x04
#define CDASupported    0x01

// Terminal Verification Results
#define OFFAUTHNOTPERFORMED		    0x80		//Offline data authentication was not performed
#define SDAFAILED		            0x40		//SDA failed
#define ICCDATAMISSING		        0x20		//ICC data missing
#define CARDINHARDLIST			    0x10		//Card number appears on hotlist
#define DDAFAILED		            0x08		//DDA failed
#define CDAFAILED			        0x04		//CDA failed
#define SDASELECTED		            0x02		//SDA was selected

#define MISSMATCHAPPVERSIONS        0x180		//Card and terminal have different application versions
#define EXPIREDAPP					0x140		//Expired application
#define APPNOTYETEFFECTIVE		    0x120		//Application not yet effective
#define SERVICENOTALLOWED			0x110		//Requested service not allowed for card product
#define NEWCARD		                0x108		//New card

#define CVMNOTSUCCESS		        0x280		//Cardholder verification was not successful
#define UNRECOGNISEDCVM             0x240		//Unrecognised CVM
#define PINTRYLIMITEXCEEDED         0x220		//PIN try limit exceeded
#define PINPADNOTPRESENT	        0x210		//PIN entry required, but no PIN pad present or not working
#define PINNOTENTERED				0x208		//PIN entry required, PIN pad present, but PIN was not entered
#define ONLINEPINENTERED			0x204		//On-line PIN entered

#define FLOORLIMITEXCEEDED			0x380		//Transaction exceeds floor limit
#define LCONOFFLIMITEXCEEDED        0x340		//Lower consecutive offline limit exceeded
#define UCONOFFLIMITEXCEEDED		0x320		//Upper consecutive offline limit exceeded
#define TRANRANDSELECTEDONL			0x310		//Transaction selected randomly of on-line processing
#define MERCHFORCEDONLINE		    0x308		//Merchant forced transaction on-line

#define DEFAULTTDOLUSED				0x480		//Default TDOL Used
#define ISSUERAUTHFAILED			0x440		//Issuer authentication failed
#define ISSUERSCRIPTFAILED1			0x420		//Script processing failed before final Generate AC
#define ISSUERSCRIPTFAILED2			0x410		//Script processing failed after final Generate AC

// Transaction Status Indicator
#define OFFAUTHPERFORMED            0x80		//Offline data authentication was performed
#define CVMPERFORMED				0x40		//Cardholder verification was performed
#define CARDRISKMNGPERFORMED		0x20		//Card risk management was performed
#define ISSUERAUTHPERFORMED			0x10		//Issuer authentication was performed
#define TERMRISKMNGPERFORMED		0x08		//Terminal risk management was performed
#define ISSUERSCRIPTPERFORMED		0x04		//Script processing was performed


// Terminal Capabilities
#define OFFLINEPLAINPIN			    0x180		//Plaintext PIN for offline ICC verification
#define ONLINEENCHIPEREDPIN			0x140		//Enciphered PIN for online verification
#define SIGNATURESUPPORTED 			0x120		//Signature (paper)
#define OFFLINEENCHIPEREDPIN		0x110		//Enciphered PIN for offline verification
#define NOCVMSUPPORTED				0x108		//No CVM Required
#define SDASUPPORTED                0x280		//Static Data Authentication (SDA)
#define DDASUPPORTED                0x240		//Dynamic Data Authentication (DDA)
#define CDASUPPORTED				0x208		//Combined DDA/Application Cryptogram Generation

// Application Usage Control
#define DOMESTICCASHVALID           0x80		//Valid for domestic cash transactions
#define INTERNATIONALCASHVALID      0x40		//Valid for international cash transactions
#define DOMESTICGOODSVALID          0x20		//Valid for domestic goods
#define INTERNATIONALGOODSVALID     0x10		//Valid for international goods
#define DOMESTICSERVICESVALID       0x08		//Valid for domestic services
#define INTERNATIONALSERVICESVALID  0x04		//Valid for international services
#define ATMSVALID                   0x02		//Valid at ATMs
#define NONATMSVALID                0x01		//Valid at terminals other than ATMs
#define DOMESTICCASHBACKALLOWED     0x180		//Domestic cashback is allowed
#define INTERCASHBACKALLOWED		0x140		//International cashback is allowed

// Additional Terminal Capabilities
#define ACCASH						0x80
#define ACGOODS						0x40
#define ACSERVICES					0x20
#define ACCASHBACK					0x10

// Transaction Types
#define TRNSALE						0x00
#define TRNCASH						0x01
#define TRNCASHBACK					0x09

// Brands
#define BVISA						3
#define BEUROPAY					41
#define BMASTER						43
#define BJCB						6

#define SERVICE_NOT_ALLOWED			0x01


