// placeholder

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif 
#include "MFRC522.h"
#include "bcm2835.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>
#include <random>
#include <sstream> 
#include "request.h"
#include <iomanip>
#include <thread>
#include <stdio.h>
#include "civetweb.h"
#include <fstream>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>

using namespace std;

#define PIN RPI_GPIO_P1_08
#define DEFAULT_BUFLEN 512
#define SERVER_PORT 8150
#define SETTINGS_SIZE 10

struct mg_context* ctx;
int serverSocket;
int connectResult;
bool bSettingsChanged = false;
char* deviceIp;

static const char* html_form =
"<html><body>PS-Tec Reader"
"<form method=\"POST\" action=\"/handle_post_request\">"
"<br> <b> Authentification </b> <br>"
"Password: <input type=\"password\" name=\"input_0\" /> <br/>"
"<br> <b> Communication </b> <br>"
"CDI IP-Addresse: <input type=\"text\" name=\"input_1\" /> <br/>"
"DeviceIP: <input type=\"text\" name=\"input_2\" /> <br/>"
"DevicePort: <input type=\"text\" name=\"input_3\" /> <br/>"
"<br> <b> Card Number Modification </b> <br>"
"RemoveZeroFirst: <input type=\"text\" name=\"input_4\" /> <br/>"
"RemoveZeroInside: <input type=\"text\" name=\"input_5\" /> <br/>"
"TurnBytes: <input type=\"text\" name=\"input_6\" /> <br/>"
"TurnBits: <input type=\"text\" name=\"input_7\" /> <br/>"
"<br> <b> Relais </b> <br>"
"Relais Time: <input type=\"text\" name=\"input_8\" /> <br/>"
"Follow-Up Time: <input type=\"text\" name=\"input_9\" /> <br/> <br>"
"<input type=\"submit\" />"
"</form></body></html>";

/*void stopWebServer()
{
    delay(5000);
    mg_stop(ctx);
    //close(serverSocket);
    //sync();
    //reboot(RB_AUTOBOOT);
}*/

int writeToConfig(vector <char*> dataArray)
{
	std::ofstream config{ "config.txt" };
	if (config.is_open())
	{
		for (int i = 0; i < dataArray.size(); i++)
		{
			if (i == dataArray.size() - 1)
			{
				config << dataArray[i];
			}
			else
				config << dataArray[i] << endl;
		}

		config.close();
		return 0;
	}
	else return -1;
}

void writeToLogs(string msg)
{
	cout << msg;

	std::ofstream file("logs.txt", fstream::app);
	file << msg;
	file.close();
}

static int begin_request_handler(struct mg_connection* conn)
{
    const struct mg_request_info* ri = mg_get_request_info(conn);
    char post_data[1024], password[sizeof(post_data)], cdiIp[sizeof(post_data)], deviceIp[sizeof(post_data)], devicePort[sizeof(post_data)], removeZeroFirstSet[sizeof(post_data)],
		 removeZeroInsideSet[sizeof(post_data)], turnBytesSet[sizeof(post_data)], turnBitsSet[sizeof(post_data)], relaisTime[sizeof(post_data)], 
		 afterTime[sizeof(post_data)];
    int post_data_len;

    if (!strcmp(ri->local_uri, "/handle_post_request")) {
        // User has submitted a form, show submitted data and a variable value
        post_data_len = mg_read(conn, post_data, sizeof(post_data));

        // Parse form data. input1 and input2 are guaranteed to be NUL-terminated
		mg_get_var(post_data, post_data_len, "input_0", password, sizeof(password));
        mg_get_var(post_data, post_data_len, "input_1", cdiIp, sizeof(cdiIp));
        mg_get_var(post_data, post_data_len, "input_2", deviceIp, sizeof(deviceIp));
		mg_get_var(post_data, post_data_len, "input_3", devicePort, sizeof(devicePort));
		mg_get_var(post_data, post_data_len, "input_4", removeZeroFirstSet, sizeof(removeZeroFirstSet));
		mg_get_var(post_data, post_data_len, "input_5", removeZeroInsideSet, sizeof(removeZeroInsideSet));
		mg_get_var(post_data, post_data_len, "input_6", turnBytesSet, sizeof(turnBytesSet));
		mg_get_var(post_data, post_data_len, "input_7", turnBitsSet, sizeof(turnBitsSet));
		mg_get_var(post_data, post_data_len, "input_8", relaisTime, sizeof(relaisTime));
		mg_get_var(post_data, post_data_len, "input_9", afterTime, sizeof(afterTime));

		// Important: Due to the time limitations, i am hardcoding the password like this. Please change this line to a encrypted code and never openly write passwords in the code
		string ourPasswdStr = "Hallo123";
		vector <char> ourPasswd(ourPasswdStr.begin(), ourPasswdStr.end());
		vector <char> typedPasswd;
		for (int i = 0; i < ourPasswd.size(); i++)
			typedPasswd.push_back(password[i]);
		if (typedPasswd != ourPasswd)
			return 0;

        // Send reply to the client, showing submitted form values.
        mg_printf(conn, "HTTP/1.0 200 OK\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "Submitted data: [%.*s]\n"
            "Submitted data length: %d bytes\n"
            "input_1: [%s]\n",
            //"input_2: [%s]\n",
            post_data_len, post_data, post_data_len, cdiIp /* , deviceIp */ );

		while (1)
		{
			vector <char*> dataArray = { cdiIp, deviceIp, devicePort, removeZeroFirstSet, removeZeroInsideSet, turnBytesSet, turnBitsSet, relaisTime, afterTime };
			int writeResult = writeToConfig(dataArray);
			if (writeResult == 0) break;
		}
		bSettingsChanged = true;

        //thread stopThread(stopWebServer);
        //stopThread.detach();
    }
    else {
        // Show HTML form.
        mg_printf(conn, "HTTP/1.0 200 OK\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: text/html\r\n\r\n%s",
            (int)strlen(html_form), html_form);
    }
    return 1;  // Mark request as processed
}

void startWebServer()
{
    const char* options[] = {"listening_ports", "8080", NULL};
    struct mg_callbacks callbacks;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.begin_request = begin_request_handler;
    ctx = mg_start(&callbacks, NULL, options);
    //getchar();  // Wait until user hits "enter"
    //mg_stop(ctx);
}

string generate_uuid() /*generate_uuid_v4()*/
{
    static std::random_device              rd;
    static std::mt19937                    gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);

    std::stringstream ss;
    int i;
    ss << std::hex;
    for (i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4";
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    ss << dis2(gen);
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (i = 0; i < 12; i++) {
        ss << dis(gen);
    };
    return ss.str();
}

void delay(int ms) {
#ifdef WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

string hex2str(byte* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}

void bytes2hex(char Hex[/* 2*Sz */], unsigned char Bytes[ /* Sz */], size_t Sz)
{
    char const static d[] = "0123456789abcdef";
    for (size_t i = 0; i < Sz; i++)
        Hex[i * 2 + 0] = d[Bytes[i] / 16], Hex[i * 2 + 1] = d[Bytes[i] % 16];
}

void removeZeroFirst(string& inCardNumber)
{
	bool cond = (inCardNumber[0] == '0') && (inCardNumber[1] == '0');
	if (cond) {
		for (int i = 0; i < 2; i++)
			inCardNumber.erase(0, 1);
	}
}

void removeZeroInside(string& inCardNumber)
{
	bool bZeroFirst = false;

	if (inCardNumber.find("00") == 0) {
		removeZeroFirst(inCardNumber);
		bZeroFirst = true;
	}

	int subStrIndex = inCardNumber.find("00");
	if (inCardNumber.find("00") != string::npos)
		inCardNumber.erase(subStrIndex, 2);

	if (bZeroFirst == true)
		inCardNumber.insert(0, "00");
}

vector <string> createStrVec(string& inCardNumber, unsigned int subStrLen)
{
	vector <string> strVec;
	do {
		strVec.push_back(inCardNumber.substr(0, subStrLen));
		inCardNumber.erase(0, subStrLen);
	} while (inCardNumber.length() > 0);

	return strVec;
}

void turnBytes(string& inCardNumber)
{
	unsigned int subStrLen = 2;
	vector <string> strVec = createStrVec(inCardNumber, subStrLen);

	reverse(strVec.begin(), strVec.end());

	for (auto e : strVec)
		inCardNumber += e;
}

void turnBits(string& inCardNumber)
{
	unsigned int subStrLen = 2;
	vector <string> strVec = createStrVec(inCardNumber, subStrLen);

	for (auto e : strVec) {
		reverse(e.begin(), e.end());
		inCardNumber += e;
	}
}

/*void removeZeroInside(string& inCardNumber)
{
	bool cond1 = inCardNumber.contains("00");
	bool cond2 = !(inCardNumber[0] == '0' && inCardNumber[1] == '0');
	if (cond1 && cond2)
		inCardNumber.erase("00");
}

void turnBytes(string& inCardNumber)
{
	QByteArray cmd = QByteArray::fromHex(inCardNumber.toLatin1());
	QByteArray cmdRev(cmd.size(), 0);
	std::copy(cmd.crbegin(), cmd.crend(), cmdRev.begin());
	inCardNumber = QString((cmdRev.toHex().toUpper()));
}

void turnBits(string& inCardNumber)
{
	QByteArray cmd = QByteArray::fromHex(inCardNumber.toLatin1());
	QByteArray cmdBitRev(cmd.size(), 0);
	for (int i = 0; i < cmd.size(); i++)
		cmdBitRev[i] = swapBits(cmd[i], 4, 0, 4);
	inCardNumber = QString((cmdBitRev.toHex().toUpper()));
}*/

int main()
{
	/* This is our Web Server thread, which is going to run independently
	   and provide an User Interface for reading and writing to created config.txt,
	   which will be in the client.out file folder and contain all settings. 
	   To open this interface, please type IP:Port to a web broser. Example:
	   RPi IP Address: 192.168.2.104, Port: 8080 => 192.168.2.104:8080
	   For this Web Server, we are using Civetweb OpenSource Library.
	*/
	thread startThread(startWebServer);
	startThread.detach();

	// Clear logs
	std::ofstream file("logs.txt");
	file << " ";
	file.close();

	vector <string> settingsStr;
	while (1)
	{
		bSettingsChanged = false;
		if (bSettingsChanged) continue;

		// Step 1: Getting Settings from the config.txt
		vector <char*> settings;
		settingsStr.clear();
		ifstream config("config.txt");
		if (config.is_open())
		{
			string line;
			while (getline(config, line))
			{
				cout << line << '\n';
				settingsStr.push_back(line);
			}
			config.close();
			cout << endl;

			char* str = nullptr;
			for (int i = 0; i < settingsStr.size(); i++)
			{
				str = new char[settingsStr[i].length() + 1];
				settings.push_back(str);
				strcpy(settings[i], settingsStr[i].c_str());
			}
		}
		else
			writeToLogs("config cant be opened to read from\n");

		writeToLogs("Settings: \n");
		for (int i = 0; i < settings.size(); i++)
		{
			writeToLogs(settings[i]);
			writeToLogs("\n");
		}

		// Step 2.1: Creating a socket for server communication
		while (1)
		{
			if (bSettingsChanged) break;
			serverSocket = socket(AF_INET, SOCK_STREAM, 0);
			writeToLogs("serverSocket: " + to_string(serverSocket) + "\n");
			if (serverSocket <= 0)
			{
				delay(1000);
				continue;
			}
			else break;
		}
		if (bSettingsChanged || settings.size() != SETTINGS_SIZE - 1)
		{
			close(serverSocket);
			for (int i = 0; i < settings.size(); i++)
				delete[] settings[i];
			continue;
		}



		// Step 2.2: Connecting to the server socket
		bool bDoneOnce = false;
		struct sockaddr_in server;
		while (1)
		{
			if (bSettingsChanged) break;
			unsigned long addr;
			memset(&server, 0, sizeof(server));
			addr = inet_addr(settings[0]);
			memcpy((char*)&server.sin_addr, &addr, sizeof(addr));
			server.sin_family = AF_INET;
			server.sin_port = htons(SERVER_PORT);
			struct timeval timeout;
			timeout.tv_sec = 1;  // after 1 second connect() will timeout
			timeout.tv_usec = 0;
			setsockopt(serverSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
			connectResult = connect(serverSocket, (struct sockaddr*)&server, sizeof(server));
			delay(500);
			if (connectResult == 0)
			{
				writeToLogs("serverSocket: " + to_string(connectResult) + "\n");
				break;
			}
			// I just want -1 to show once, otherwise it would flood the screen
			else if (connectResult == -1 && !bDoneOnce)
			{
				bDoneOnce = true;
				writeToLogs("serverSocket: " + to_string(connectResult) + "\n");
			}
		}
		if (bSettingsChanged)
		{
			close(serverSocket);
			for (int i = 0; i < settings.size(); i++)
				delete[] settings[i];
			continue;
		}

		// Step 3.1: Getting the local IP Address of device
		int fd;
		struct ifreq ifr;
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		/* I want to get an IPv4 IP address */
		ifr.ifr_addr.sa_family = AF_INET;
		/* I want IP address attached to "eth0" */
		strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
		ioctl(fd, SIOCGIFADDR, &ifr);
		close(fd);
		string localIpStr = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
		char* localIpPtr = new char[localIpStr.length() + 1];
		settings.push_back(localIpPtr);
		strcpy(settings[settings.size() - 1], localIpStr.c_str());
		//writeToLogs("Local IP: " + to_string(settings[settings.size() - 1]) + "\n");

		// Step 3.2: Getting the local port for the server communication
		int local_port;
		socklen_t addrlen = sizeof(server);
		if (getsockname(serverSocket, (struct sockaddr*)&server, &addrlen) == 0 &&
			server.sin_family == AF_INET && addrlen == sizeof(server))
		{
			local_port = ntohs(server.sin_port);
		}
		writeToLogs("Local Port: " + to_string(local_port) + "\n");
		string endpointStr = std::to_string(local_port);
		const char* charPtr = endpointStr.c_str();  //use char const* as target type
		char* deviceCommunicationPort = new char[endpointStr.size() + 1];
		std::copy(endpointStr.begin(), endpointStr.end(), deviceCommunicationPort);
		deviceCommunicationPort[endpointStr.size()] = '\0'; // don't forget the terminating 0

		// Check Settings
		if (settings.size() != SETTINGS_SIZE)
		{
			close(serverSocket);
			for (int i = 0; i < settings.size(); i++)
				delete[] settings[i];
			continue;
		}

		// Step 3.3: setDeviceCommunicationportRequest
		char devicePort[2] = "1";
		string uuidStr = generate_uuid();
		char uuid[37] = { };
		for (int i = 0; i < 37; i++) 
		{
			uuid[i] = uuidStr[i];
		}
		char commandTypeName[61] = "CDI_Shared_PCL.DataObjects.SetDeviceCommunicationPortRequest";
		char isResponse[6] = "false";
		char isNotification[6] = "false";

		vector<char*> params{ deviceCommunicationPort, settings[SETTINGS_SIZE - 1], settings[1], settings[2], uuid, commandTypeName, isResponse, isNotification };
		vector<int> sizes{ (int)endpointStr.size() + 1, (int)localIpStr.length() + 1, (int)settingsStr[1].length() + 1, (int)settingsStr[2].length() + 1, 37, 61, 6, 6 };

		setDeviceCommunicationPortRequest setDeviceCommunicationPortRequest;
		vector<byte> command_vec = setDeviceCommunicationPortRequest.createRequest(params, sizes);
		byte* command = &command_vec[0];

		for (int i = 0; i < command_vec.size(); i++) 
		{
			cout << command[i];
		}
		cout << endl;

		int sendResult = send(serverSocket, command, command_vec.size() /*(int)strlen(hex)*/, 0);
		writeToLogs("sendResult: " + to_string(sendResult) + "\n");



		delete[] deviceCommunicationPort;



		/*while (1) 
		{
			if (bSettingsChanged) break;	
		}
		if (bSettingsChanged)
		{
			close(serverSocket);
			continue;
		}*/



		MFRC522 mfrc;

		mfrc.PCD_Init();

		bcm2835_init();
		bcm2835_gpio_fsel(PIN, BCM2835_GPIO_FSEL_OUTP);
		bcm2835_gpio_write(PIN, LOW);

		while (1)
		{
			if (bSettingsChanged) break;
			// Look for a card
			if (!mfrc.PICC_IsNewCardPresent())
				continue;

			if (!mfrc.PICC_ReadCardSerial())
				continue;

			//byte cardNumber[4] = {mfrc.uid.uidByte[0], mfrc.uid.uidByte[1], mfrc.uid.uidByte[2], mfrc.uid.uidByte[3]};

			string cardNumberStr = hex2str(mfrc.uid.uidByte, 4 /*sizeof(mfrc.uid.uidByte) / sizeof(mfrc.uid.uidByte[0])*/ );
			writeToLogs("read card num: " + cardNumberStr + "\n");

			// Card number modification
			if (settings[3][0] == '1')
				removeZeroFirst(cardNumberStr);
			if (settings[4][0] == '1')
				removeZeroInside(cardNumberStr);
			if (settings[5][0] == '1')
				turnBytes(cardNumberStr);
			if (settings[6][0] == '1')
				turnBits(cardNumberStr);

			writeToLogs("Modified card num: " + cardNumberStr + "\n");

			const char* charPtr = cardNumberStr.c_str();  //use char const* as target type
			char* cardNumber = new char[cardNumberStr.size() + 1];
			std::copy(cardNumberStr.begin(), cardNumberStr.end(), cardNumber);
			cardNumber[cardNumberStr.size()] = '\0'; // don't forget the terminating 0

			// toUpper
			for (int i = 0; i < cardNumberStr.length(); i++)
				cardNumber[i] = toupper(cardNumber[i]);

			//unsigned char bytes[] = { 0xaa,0xbb,0xcc,0x11,0x22 };
			//char hex[2 * sizeof(cardNumber) + 1 /*for the '\0' */];
			//hex[sizeof(hex) - 1] = '\0';
			//bytes2hex(hex, cardNumber, sizeof(cardNumber));

			// Print UID
			/*for(byte i = 0; i < mfrc.uid.size; ++i)
			{
				if(mfrc.uid.uidByte[i] < 0x10)
				{
					printf(" 0");
					printf("%X",mfrc.uid.uidByte[i]);

				}
				else
				{
					printf(" ");
					printf("%X", mfrc.uid.uidByte[i]);
				}
			}
			printf("\n");*/

			// accessRequest
			//char cardNumber[9] = cardNumberByteArray;
			char lockerSegmentInfo[5] = "null";
			//char deviceIp[14] = "192.168.2.142";
			//char devicePort[2] = "1";
			string uuidStr = generate_uuid();
			char uuid[37] = { };
			for (int i = 0; i < 37; i++)
			{
				uuid[i] = uuidStr[i];
			}
			char commandTypeName[41] = "CDI_Shared_PCL.DataObjects.AccessRequest";
			char isResponse[6] = "false";
			char isNotification[6] = "false";

			vector<char*> params{ cardNumber, lockerSegmentInfo, settings[1], settings[2], uuid, commandTypeName, isResponse, isNotification };
			vector<int> sizes{ cardNumberStr.length() + 1, 5, (int)settingsStr[1].length() + 1, (int)settingsStr[2].length() + 1, 37, 41, 6, 6 };

			accessRequest accessRequest;
			vector<byte> command_vec = accessRequest.createRequest(params, sizes);
			byte* command2 = &command_vec[0];

			for (int i = 0; i < command_vec.size(); i++)
			{
				cout << command2[i];
			}
			cout << endl;

			int sendResult = send(serverSocket, command2, command_vec.size() /*(int)strlen(hex)*/, 0);
			writeToLogs("sendResult: " + to_string(sendResult) + "\n");
			//printf("sending: %s\n", hex);


			delete[] cardNumber;


			char recvBuf[DEFAULT_BUFLEN];
			int recvBufLen = DEFAULT_BUFLEN;
			struct pollfd fd;
			int ret;
			fd.fd = serverSocket; // your socket handler 
			fd.events = POLLIN;
			ret = poll(&fd, 1, 10000); // 1 second for timeout
			switch (ret) {
			case -1:
				writeToLogs("Read Error during reading CDI answer\n");
				break;
			case 0:
				writeToLogs("Timeout, no reply from CDI\n");
				break;
			default:
				// receiveMessage
				int recvResult = recv(serverSocket, recvBuf, recvBufLen, 0);
				writeToLogs("recvResult: " + to_string(recvResult) + "\n");
				break;
			}

			/*for (int i; i < sizeof(hex) / sizeof(hex[0]); i++)
			{
				printf("first byte: %d\n", hex[i]);
			}*/

			//delay(5000);

			if (recvBuf[22] == 't')
			{
				bcm2835_gpio_write(PIN, HIGH);
				bcm2835_delay(stoi(settings[7]));
				bcm2835_gpio_write(PIN, LOW);
			}
			bcm2835_delay(stoi(settings[8]));

		}
		if (bSettingsChanged)
		{
			close(serverSocket);
			for (int i = 0; i < settings.size(); i++)
				delete[] settings[i];
			continue;
		}
	}

    return 0;
}