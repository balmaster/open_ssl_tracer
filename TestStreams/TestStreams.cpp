// TestStreams.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"



int _tmain(int argc, _TCHAR* argv[])
{
	std::ostringstream o;
	o<<std::hex<<"d:\\logs\\"<<"\\"<<(int)argv<<"_read";
	std::ofstream f(o.str().c_str());
	f<<"sdfgsudfghukshgkhskdhgk";
	f.flush();

	return 0;
}

