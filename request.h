// Placeholder.

#pragma once

#include <stdint.h>
#include <string>
#include <vector>

using namespace std;

typedef uint8_t byte;

const vector <byte> start{ 0x7B, 0x0D, 0x0A };
const vector <byte> last{ 0x7D };
const vector <byte> nextline{ 0x0D, 0x0A };
const vector <byte> startline{ 0x20, 0x20, 0x22 };
const vector <byte> endline{ 0x22, 0x2C };
const vector <byte> endlineNoString{ 0x2C };
const vector <byte> endlineNull{ };
const vector <byte> space{ 0x22, 0x3A, 0x20, 0x22 };
const vector <byte> spaceNoString{ 0x22, 0x3A, 0x20 };

class requestBase
{
public:
	requestBase()
	{
		strings = { str_deviceIp, str_devicePort, str_id, str_commandTypeName, str_isResponse, str_isNotification };
		strSizes = { 9, 11, 3, 16, 11, 15 };
		isString_array = { true, false, true, true, false, false };
	}

	vector <byte> createRequest(vector<char*> params, vector<int> sizes);

protected:
	char str_deviceIp[9] = "DeviceIp";
	char str_devicePort[11] = "DevicePort";
	char str_id[3] = "ID";
	char str_commandTypeName[16] = "CommandTypeName";
	char str_isResponse[11] = "IsResponse";
	char str_isNotification[15] = "IsNotification";

	vector <bool> isString_array;
	vector <char*> strings;
	vector <int> strSizes;

	vector<byte> createLine(char* str, int strSize, char* value, int valueSize, bool isString, bool isLastLine);
};

class setDeviceCommunicationPortRequest : public requestBase 
{
public:
	setDeviceCommunicationPortRequest()
	{
		strings.insert(strings.begin(), str_deviceCommunicationIp);
		strings.insert(strings.begin(), str_deviceCommunicationPort);

		strSizes.insert(strSizes.begin(), 21);
		strSizes.insert(strSizes.begin(), 24);

		isString_array.insert(isString_array.begin(), true);
		isString_array.insert(isString_array.begin(), false);
	}

protected:
	char str_deviceCommunicationPort[24] = "DeviceCommunicationPort";
	char str_deviceCommunicationIp[21] = "DeviceCommuniationIp";
};

class accessRequest : public requestBase
{
public:
	accessRequest()
	{
		strings.insert(strings.begin(), str_lockerSegmentInfo);
		strings.insert(strings.begin(), str_cardNumber);

		strSizes.insert(strSizes.begin(), 18);
		strSizes.insert(strSizes.begin(), 11);

		isString_array.insert(isString_array.begin(), false);
		isString_array.insert(isString_array.begin(), true);
	}

protected:
	char str_cardNumber[11] = "CardNumber";
	char str_lockerSegmentInfo[18] = "LockerSegmentInfo";
};