#include "StdAfx.h"
#include "Config.h"
#include "Converter.h"

Config::Config(const std::string & aFileName):fileName(aFileName)
{
    std::ifstream config(fileName.c_str());

    //parameters
    std::set<std::string> options;
    std::map<std::string, std::string> parameters;
    options.insert("*");
    
    for (boost::program_options::detail::config_file_iterator 
		i(config, options), e ; i != e; ++i)
    {
        parameters[i->string_key] = i->value[0];
    }

	module=parameters["main.module"];
	
	sslReadOffset = Converter::HexStrToULong(parameters["main.SSL_read.offset"]);
	sslWriteOffset = Converter::HexStrToULong(parameters["main.SSL_write.offset"]);

	logPath = parameters["main.logPath"];
}

Config::~Config(void)
{
}

const std::string & 
Config::GetModule()
{
	return module;
}

const unsigned long 
Config::GetSSLReadOffset()
{
	return sslReadOffset;
}

const unsigned long 
Config::GetSSLWriteOffset()
{
	return sslWriteOffset;
}
const std::string & 
Config::GetLogPath()
{
	return logPath;
}