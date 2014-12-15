#pragma once

class Config
{
private:
	std::string fileName;
	std::string module;
	std::string logPath;
	unsigned long sslReadOffset;
	unsigned long sslWriteOffset;
public:
	Config(const std::string & aFileName);
	~Config(void);

	const std::string & GetModule();
	const std::string & GetLogPath();
	const unsigned long GetSSLReadOffset();
	const unsigned long GetSSLWriteOffset();
};
