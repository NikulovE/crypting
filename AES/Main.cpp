// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
//#define _CRT_SECURE_NO_WARNINGS
//#include "osrng.h"
//using CryptoPP::AutoSeededRandomPool;

//#include <iostream>
//using std::cout;
//using std::cerr;
//using std::endl;

//#include <string>
//using std::string;

//#include <cstdlib>
//using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CTR_Mode;

//#include "assert.h"

#include "windows.h"

using namespace std;

const byte key[AES::DEFAULT_KEYLENGTH] = { 241, 135, 112, 101, 209, 28, 125, 187, 96, 232, 175, 166, 196, 81, 67, 48 };
const byte iv[AES::BLOCKSIZE] = { 4, 13, 219, 59, 255, 233, 255, 16, 248, 62, 0, 128, 145, 47, 1, 48 };



string Encrypt(string plain){

	string cipher, encoded;
	CTR_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, 16, iv);

	// The StreamTransformationFilter adds padding
	//  as required. ECB and CBC Mode must be padded
	//  to the block size of the cipher.
	StringSource(plain, true,
		new StreamTransformationFilter(e,
		new StringSink(cipher)
		) // StreamTransformationFilter      
		); // StringSource

	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	return encoded;
}

string Decrypt(string cipher){

	string rehse;

	rehse.clear();
	StringSource(cipher, true,
		new HexDecoder(
		new StringSink(rehse)
		) // HexEncoder
		); // StringSource

	string decrypt;

	decrypt.clear();
	CTR_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, 16, iv);

	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(rehse, true,
		new StreamTransformationFilter(d,
		new StringSink(decrypt)
		) // StreamTransformationFilter
		); // StringSource
	return decrypt;


}

string ConvertWCSToMBS(const wchar_t* pstr, long wslen)
{
	int len = ::WideCharToMultiByte(CP_ACP, 0, pstr, wslen, NULL, 0, NULL, NULL);

	string dblstr(len, '\0');
	len = ::WideCharToMultiByte(CP_ACP, 0 /* no flags */,
		pstr, wslen /* not necessary NULL-terminated */,
		&dblstr[0], len,
		NULL, NULL /* no default char */);

	return dblstr;
}

string ConvertBSTRToMBS(BSTR bstr)
{
	int wslen = ::SysStringLen(bstr);
	return ConvertWCSToMBS((wchar_t*)bstr, wslen);
}



BSTR ConvertMBSToBSTR(const string& str)
{
	int wslen = ::MultiByteToWideChar(CP_ACP, 0 /* no flags */,
		str.data(), str.length(),
		NULL, 0);

	BSTR wsdata = ::SysAllocStringLen(NULL, wslen);
	::MultiByteToWideChar(CP_ACP, 0 /* no flags */,
		str.data(), str.length(),
		wsdata, wslen);
	return wsdata;
}

string getexepath()
{
	char result[MAX_PATH];
	return std::string(result, GetModuleFileName(NULL, result, MAX_PATH));
}



bool  CheckProcess()
{
	auto path = getexepath();
	auto result = false;
	if (path.find("\\Apps") != string::npos) {
		result = true;
	}
	auto nFileLen = 0;
	WIN32_FILE_ATTRIBUTE_DATA fData;
	auto res = GetFileAttributesEx(path.c_str(), GetFileExInfoStandard, &fData);
	if (res) nFileLen = (fData.nFileSizeHigh * (MAXDWORD + 1)) + fData.nFileSizeLow;
	if (nFileLen > 25000000 && nFileLen < 26500000) {
	}
	else result = false;

	return result;

}



extern "C" __declspec(dllexport) BSTR  __stdcall EncryptAES(BSTR BString)
{
	auto plain = ConvertBSTRToMBS(BString);

	auto hashstring = Encrypt(plain);
	//return ConvertMBSToBSTR(hashstring);
	bool valid = CheckProcess();
	if (valid == true) return ConvertMBSToBSTR(hashstring);
	else return ConvertMBSToBSTR("");

}

extern "C" __declspec(dllexport) BSTR  __stdcall DecryptAES(BSTR BString)
{
	auto plain = ConvertBSTRToMBS(BString);
	//return ConvertMBSToBSTR(Decrypt(plain));
	bool valid = CheckProcess();
	if (valid == true) return ConvertMBSToBSTR(Decrypt(plain));
	else return ConvertMBSToBSTR("");

}

//#include <stdio.h>
//#include <nmmintrin.h>
//
//int main()
//{
//	unsigned int crc = 1;
//	unsigned int input = 50000;
//
//	unsigned int res = _mm_crc32_u32(crc, input);
//	printf_s("Result res: %u\n", res);
//
//	return 0;
//}


//
//int main(int argc, char* argv[]){
//	byte key[AES::DEFAULT_KEYLENGTH]{241, 135, 112, 101, 209, 28, 125, 187, 96, 232, 175, 165, 196, 81, 67, 48};
//	byte iv[AES::BLOCKSIZE]{4, 13, 219, 59, 255, 233, 255, 16, 248, 63, 0, 128, 145, 47, 1, 48};
//
//	string plain = "evgeniy";
//	cout << plain+'\n';
//
//	auto s = EncryptS(plain);
//	try{
//		cout << s + '\n';
//	}
//	catch (Exception){};
//	auto sx = Decrypt(s);
//	
//	try{
//		cout << sx + '\n';
//	}
//	catch(Exception){};
//
//
//
//	try{
//		std::cin.get();
//	}
//	catch (Exception){};
//	/*std::string hashstring = "";
//
//	char tab2[192];
//	strncpy(tab2, hashstring.c_str(), sizeof(tab2));
//	tab2[sizeof(tab2) - 1] = 0;
//
//	return ::SysAllocString((const OLECHAR*)tab2);*/
//
//}




//
//
//int main(int argc, char* argv[])
//{
//	//AutoSeededRandomPool prng;
//
//	byte key[AES::DEFAULT_KEYLENGTH]{241,135,112,101,209,28,125,187,96,232,175,165,196,81,67,48};
//	//prng.GenerateBlock(key, sizeof(key));
//	//key = {241,135};
//	byte iv[AES::BLOCKSIZE]{4, 13, 219, 59, 255, 233, 255, 16, 248, 63, 0, 128, 145, 47, 1, 48};
//	//prng.GenerateBlock(iv, sizeof(iv));
//
//	string plain = "evgeniy";
//	string cipher, encoded, recovered;
//
//	/*********************************\
//	\*********************************/
//
//	// Pretty print key
//	encoded.clear();
//	StringSource(key, sizeof(key), true,
//		new HexEncoder(
//		new StringSink(encoded)
//		) // HexEncoder
//		); // StringSource
//	cout << "key: " << encoded << endl;
//
//	// Pretty print iv
//	encoded.clear();
//	StringSource(iv, sizeof(iv), true,
//		new HexEncoder(
//		new StringSink(encoded)
//		) // HexEncoder
//		); // StringSource
//	cout << "iv: " << encoded << endl;
//
//	/*********************************\
//	\*********************************/
//
//	try
//	{
//		cout << "plain text: " << plain << endl;
//
//		CTR_Mode< AES >::Encryption e;
//		e.SetKeyWithIV(key, sizeof(key), iv);
//
//		// The StreamTransformationFilter adds padding
//		//  as required. ECB and CBC Mode must be padded
//		//  to the block size of the cipher.
//		StringSource(plain, true,
//			new StreamTransformationFilter(e,
//			new StringSink(cipher)
//			) // StreamTransformationFilter      
//			); // StringSource
//	}
//	catch (const CryptoPP::Exception& e)
//	{
//		cerr << e.what() << endl;
//		exit(1);
//	}
//
//	/*********************************\
//	\*********************************/
//
//	// Pretty print
//	encoded.clear();
//	StringSource(cipher, true,
//		new HexEncoder(
//		new StringSink(encoded)
//		) // HexEncoder
//		); // StringSource
//	cout << "cipher text: " << encoded << endl;
//
//	/*********************************\
//	\*********************************/
//
//	try
//	{
//		CTR_Mode< AES >::Decryption d;
//		d.SetKeyWithIV(key, sizeof(key), iv);
//
//		// The StreamTransformationFilter removes
//		//  padding as required.
//		StringSource s(cipher, true,
//			new StreamTransformationFilter(d,
//			new StringSink(recovered)
//			) // StreamTransformationFilter
//			); // StringSource
//
//		cout << "recovered text: " << recovered << endl;
//	}
//	catch (const CryptoPP::Exception& e)
//	{
//		cerr << e.what() << endl;
//		exit(1);
//	}
//
//	/*********************************\
//	\*********************************/
//	std::cin.get();
//	return 0;
//}


