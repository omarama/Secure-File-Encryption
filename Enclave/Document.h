#pragma once
#include <vector>
#include <string>

/*	The action type defines if a read or write access is executed.*/
enum class Action
{
	READ,
	WRITE,
	NONE
};
/*	The document class specifies the plaintext document. It holds the text, the size of the file and the title. 
	Furtermore is will hold the version number and the action type
*/
class Document
{
private:
	std::vector <uint8_t> text;
	int fileSize;
	std::string fileName;
	std::string version;
	Action action;
public:
	Document(char *input, int lengthInput, char *fileName, int lengthFileName, bool write);
	std::vector<uint8_t> getText();
	int getFileSize();
	std::string getFileName();
	Action getAction();
};