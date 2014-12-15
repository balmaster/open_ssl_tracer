#pragma once
class Converter
{
public:

	Converter(void)
	{
	}

	~Converter(void)
	{
	}

	static unsigned long HexStrToULong(const std::string & aValue)
	{
		unsigned int res;
		std::stringstream(aValue)>>std::hex>>res;
		return res;
	}
	
};
