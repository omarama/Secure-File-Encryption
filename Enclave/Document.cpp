#include "Document.h"
Document::Document(char *input, int lengthInput, char *fileName, int lengthFileName, bool write)
{
	this->text.reserve(lengthInput);
	this->text.insert(this->text.begin(), input, input + lengthInput);
	this->fileSize = lengthInput;
	this->fileName.append(fileName, lengthFileName);
	if (write) {
		this->action = Action::WRITE;
	}
	else if (!write)
	{
		this->action = Action::READ;
	}
	else
	{
		this->action = Action::NONE;
	}
}
std::vector<uint8_t> Document::getText()
{
	return this->text;
}
int Document::getFileSize()
{
	return this->fileSize;
}
std::string Document::getFileName()
{
	return this->fileName;
}
Action Document::getAction()
{
	return this->action;
}
