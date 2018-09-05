#include "LoggingClient.h"
#include "Enclave_t.h"

LoggingClient::LoggingClient(Document doc)
{	
	long int t = 0;
	this->filename = doc.getFileName();
	ocall_get_timestamp(&t);
	this->time=t;
	this->fileSize = doc.getFileSize();
	this->action = doc.getAction();

}
/*Logging record structure
	1 - 20	Byte				File name
	21 - 40	Byte				Time
	41 - 60 Byte				File size
	61 - 65	Byte				Action	
*/
std::string LoggingClient::getLoggingRecord()
{
	std::string loggingRecord (65,' ');
	std::string templ;
	loggingRecord.insert(0,this->filename);
	templ = std::to_string(this->time);
	loggingRecord.insert(21, templ.c_str());
	templ = std::to_string(this->fileSize);
	loggingRecord.insert(41, templ);
	if (this->action == Action::WRITE)
	{
		loggingRecord.insert(61, "WRITE");
	}
	else if (this->action == Action::READ)
	{
		loggingRecord.insert(61, "READ");
	}
	else 
	{
		loggingRecord.insert(61, "NONE");
	}
	return loggingRecord;
}
