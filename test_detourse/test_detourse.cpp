// test_detourse.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "Config.h"



extern "C" {

int test(int a,int b)
{
	printf("%d, %d",a,b);
	return a;
}


int (* p_test)(int a,int b) = test;

int traced_test(int a,int b)
{
	printf("before");
	int r =p_test(a,b);
	printf("after");
	return r;
}
};

const char * LETTERS = "0123456789ABCDEF";
void str2Hex(const char* aSrc, char* aDst, int len)
{
	for(int i=0;i<len;i++)
	{
		aDst[2*i] = LETTERS[aSrc[i]>>4];				
		aDst[2*i+1] = LETTERS[aSrc[i] & 0x0F];				
	}
	aDst[len*2] = 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
	// parse config
	Config config("c:\\tracessl.ini");
	
	// load library
	boost::scoped_array<const char> moduleName(config.GetModule().c_str());
	HMODULE	module = GetModuleHandle(moduleName.get());
	
	unsigned long a = config.GetSSLReadOffset();
	unsigned long b = config.GetSSLWriteOffset();

	int len = 100;
	BYTE * data = new BYTE[len];
	for(int i=0;i<len;i++)data[i]=i;
	
	char* buffer = new char[(len)*2+1];
	str2Hex((char*)data,buffer,len);

	printf("%s\n",buffer);

	test(100,1000);


	// detourse
	DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

	DetourAttach(&(PVOID&)p_test, traced_test);
	DetourTransactionCommit();
	
	test(101,1001);

	
	getchar();
	return 0;
}

