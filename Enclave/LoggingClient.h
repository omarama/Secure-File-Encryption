#pragma once
#include "sgx_trts.h"
#include <string>
#include "Document.h"

/*
	The logging Client class generates a logging record, whcich shuld be transfered to the central server.
	Information like the time, document title, etc should be stored. 
	The hashing and signature with the private key will be done within the TLS channel to ensure 
	CIA.
*/
class LoggingClient
{
private:
	long int time;									//Unix time
	unsigned int cpuid;								//cpu id 
	std::string filename;							//file name
	std::string version;							//file version
	int fileSize;									//file size
	Action action;									//Read or write access
public:
 	LoggingClient(Document doc);
	std::string getLoggingRecord();					//create Logging Record
};