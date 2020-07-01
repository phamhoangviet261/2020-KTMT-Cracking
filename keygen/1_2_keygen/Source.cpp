//#include "stdafx.h"
#include "string.h"
#include <string>
//#include "crc.h"
#include <iostream>
#pragma warning (disable:4996)
using namespace std;

const uint32_t val1[4] = { 0x10325476u, 0x98badcfeu, 0xefcdab89u, 0x67452301u };
const uint32_t val2[8] = { 0xA6, 0x16, 0xAF, 0xFD, 0xD4, 0x07, 0x10, 0xF6 };
const string source1 = "BDRQKPTVJI";
const string source2 = "0123456789";

//---------------------------------------------------------
const uint32_t i_val[4] = { 0x10325476u, 0x98badcfeu, 0xefcdab89u, 0x67452301u };
const uint32_t R1[8] = { 0xd1310ba6u, 0x98dfb5acu, 0x2ffd72dbu, 0xd01adfb7u, 0xb8e1afedu, 0x6a267e96u, 0xba7c9045u, 0xf12c7f99u };
const uint32_t R2[8] = { 0x00000000u, 0x77073096u, 0xee0e612cu, 0x990951bau, 0x076dc419u, 0x706af48fu, 0xe963a535u, 0x9e6495a3u };
uint32_t R3[256];
unsigned int hexToInt(char* s)
{
	unsigned int res = 0;
	for (int i = 0, len = strlen(s); i < len; ++i)
	{
		res *= 16;
		if (s[i] >= '0' && s[i] <= '9')
			res += (s[i] - '0');
		else if (s[i] >= 'a' && s[i] <= 'f')
			res += (s[i] - 'a') + 10;
		else if (s[i] >= 'A' && s[i] <= 'F')
			res += (s[i] - 'A') + 10;
	}
	return res;
}
//read data from hex dumd to do hash 4
void readData()
{
	char buff[105];
	char s[4][5];
	FILE* fi = fopen("memory.txt", "r");
	FILE* fo = fopen("data.txt", "w");

	while (!feof(fi))
	{
		fgets(buff, 102, fi);
		char* tok = strtok(buff, " \n");
		unsigned int address = hexToInt(tok);
		for (int t = 0; t < 2; ++t) {
			for (int i = 0; i < 4; ++i)
			{
				tok = strtok(NULL, " \n");
				memcpy(s + i, tok, sizeof(char) * 3);
			}
			fprintf(fo, "%x\t%s%s%s%s\n", address + t * 4, s[3], s[2], s[1], s[0]);
		}
	}
	fclose(fi);
	fclose(fo);

	FILE* f = fopen("data.txt", "r");
	for (int32_t i = 0; i < 256; ++i)
	{
		uint32_t x, y;
		fscanf(f, "%x %X", &x, &y);
		R3[i] = y;
	}
	fclose(f);
}

uint32_t Hash234(uint32_t eax)
{
	int8_t t[10];
	sprintf((char*)t, "%08X", eax);

	for (int32_t i = 0; i < 8; ++i)
		t[i] = (R1[i] - R2[i]) ^ uint32_t(t[i]); //val[i]
	//--end hash 2
	for (int32_t i = 0; i < 8; ++i)
	{
		int32_t temp = t[i], teax = t[i];
		t[i] = (teax << i) | temp;
	}
	//--end hash 3
	//10C0 --> 10FA
	uint32_t esi = 0xFFFFFFFF, edi;

	for (int32_t i = 0; i < 8; ++i)
	{
		eax = (unsigned char)t[i];
		edi = (unsigned char)esi;
		eax ^= edi;
		esi >>= 8;
		eax = R3[eax];
		esi ^= eax;
	}
	eax = ~esi;
	//--end hash 4
	return eax;
}
//---------------------------------------------------------
string intToHex(int32_t s)
{
	string res;
	int i, j = 0;
	string hex = "0123456789ABCDEF";
	while (s != 0)
	{
		i = s % 16;
		res[j] = hex[i];
		s = s / 16;
		j++;
	}
	return res;
}


uint32_t Hash1(uint32_t mem[]) //Hard copy, ignore it
{
	uint32_t EAX = 0x98BADCFE;
	uint32_t ECX = 0x67452301;
	uint32_t EDX, EBX = 0x98BADCFE;
	uint32_t EDI = 0xEFCDAB89, EBP_pos8, EBP_neg4, EBP_posC, EBP_neg8;
	uint32_t ESI = 0x67452301, ESI_pos4 = 0xEFCDAB89, ESI_pos8 = 0x98BADCFE, ESI_posC = 0x10325476;
	EAX = EAX + mem[0];
	ECX = ECX + EAX;	//004016AB ADD ECX,EAX
	EAX = ECX;			//004016AD MOV EAX,ECX
	EAX = EAX >> 0x1D;	//004016ÀF SHR EAX,1D
	ECX = ECX << 0x3;	//004016B2 SHL ECX,3
	EAX = EAX | ECX;	//004016B5 OR EAX,ECX
	ECX = EDI;			//004016B7 MOV ECX,EDI
	EDX = EAX;			//004016B9 MOV EDX,EAX
	ECX = ECX & EAX;	//004016BB AND ECX,EAX
	EDX = ~EDX;			//004016BD NOT EDX
	EDX = EDX & EBX;	//004016BF AND EDX,EBX
	EBP_pos8 = EAX;		//004016C1 MOV DWORD PTR [EBP+8],EAX
	EDX = EDX | ECX;	//004016C4 OR EDX,ECX
	//---------------------------------------------
	ECX = 0x10325476;
	ECX = ECX + mem[1]; //EDX = EDX + [EBP-44]; 
	ECX = ECX + EDX;
	EAX = ECX;
	EAX = EAX >> 0x19;
	ECX = ECX << 0x7;
	EAX = EAX | ECX;
	ECX = EAX;
	EDX = EAX;
	EDX = EDX & EBP_pos8;
	ECX = ~ECX;
	ECX = ECX & EDI;
	ECX = ECX | EDX;
	//---------------------------------------------
	ECX = ECX + mem[2];
	EBX = EBX + ECX;
	ECX = EBX;
	ECX = ECX >> 0x15;
	EBX = EBX << 0xB;
	ECX = ECX | EBX;
	EBX = EAX;
	EDX = ECX;
	EBX = EBX & ECX;
	EDX = ~EDX;
	EDX = EDX & EBP_pos8;
	EDX = EDX | EBX;
	EBX = ECX;
	EDX = EDX + mem[3];
	EDI = EDI + EDX;
	EDX = EDI;
	EDX = EDX << 0x13;
	EDI = EDI >> 0xD;
	EDX = EDX | EDI;
	EDI = EDX;
	EBX = EBX & EDX;
	EDI = ~EDI;
	EDI = EDI & EAX;
	EBP_neg4 = EDX;
	EDI = EDI | EBX;
	EBX = EBP_pos8;
	EDI = EDI + mem[4];
	EBX = EBX + EDI;
	EDI = EBX;
	EDI = EDI >> 0x1D;
	EBX = EBX << 0x3;
	EDI = EDI | EBX;
	EBP_pos8 = EDI;
	EBX = EDI;
	EDX = EDX & EDI;
	EBX = ~EBX;
	EBX = EBX & ECX;
	EDI = EBP_neg4;
	EBX = EBX | EDX;
	EBX = EBX + mem[5];
	EAX = EAX + EBX;
	EDX = EAX;
	EDX = EDX >> 0x19;
	EAX = EAX << 0x7;
	EDX = EDX | EAX;
	EAX = EDX;
	EBX = EDX;
	EBX = EBX & EBP_pos8;
	EAX = ~EAX;
	EAX = EAX & EDI;
	EAX = EAX | EBX;
	EBX = EDX;
	EAX = EAX + mem[6];
	ECX = ECX + EAX;
	EAX = ECX;
	EAX = EAX >> 0x15;
	ECX = ECX << 0xB;
	EAX = EAX | ECX;
	ECX = EAX;
	EBX = EBX & EAX;
	ECX = ~ECX;
	ECX = ECX & EBP_pos8;
	ECX = ECX | EBX;
	EBX = EAX;
	ECX = ECX + mem[7];
	EDI = EDI + ECX;
	ECX = EDI;
	ECX = ECX << 0x13;
	EDI = EDI >> 0xD;
	ECX = ECX | EDI;
	EDI = ECX;
	EBX = EBX & ECX;
	EDI = ~EDI;
	EDI = EDI & EDX;
	EBP_neg4 = ECX;
	EDI = EDI | EBX;
	EBX = EBP_pos8;
	EDI = EDI + mem[8];
	EBX = EBX + EDI;
	EDI = EBX;
	EDI = EDI >> 0x1D;
	EBX = EBX << 0x3;
	EDI = EDI | EBX;
	EBX = EDI;
	ECX = ECX & EDI;
	EBX = ~EBX;
	EBX = EBX & EAX;
	EBP_pos8 = EDI;
	EBX = EBX | ECX;
	EDI = EBP_neg4;
	EBX = EBX + mem[9];
	EDX = EDX + EBX;
	ECX = EDX;
	ECX = ECX >> 0x19;
	EDX = EDX << 0x7;
	ECX = ECX | EDX;
	EDX = ECX;
	EBX = ECX;
	EBX = EBX & EBP_pos8;
	EDX = ~EDX;
	EDX = EDX & EDI;
	EDX = EDX | EBX;
	EBX = ECX;
	EDX = EDX + mem[10];
	EAX = EAX + EDX;
	EDX = EAX;
	EDX = EDX >> 0x15;
	EAX = EAX << 0xB;
	EDX = EDX | EAX;
	EAX = EDX;
	EBX = EBX & EDX;
	EAX = ~EAX;
	EAX = EAX & EBP_pos8;
	EAX = EAX | EBX;
	EAX = EAX + mem[11];
	EBX = EDX;
	EDI = EDI + EAX;
	EAX = EDI;
	EAX = EAX << 0x13;
	EDI = EDI >> 0xD;
	EAX = EAX | EDI;
	EDI = EAX;
	EBX = EBX & EAX;
	EDI = ~EDI;
	EDI = EDI & ECX;
	EBP_neg4 = EAX;
	EDI = EDI | EBX;
	EBX = EBP_pos8;
	EDI = EDI + mem[12];
	EBX = EBX + EDI;
	EDI = EBX;
	EDI = EDI >> 0x1D;
	EBX = EBX << 0x3;
	EDI = EDI | EBX;
	EBX = EDI;
	EAX = EAX & EDI;
	EBX = ~EBX;
	EBX = EBX & EDX;
	EBX = EBX | EAX;
	EBX = EBX + mem[13];
	ECX = ECX + EBX;
	EBX = ECX;
	EBX = EBX >> 0x19;
	ECX = ECX << 0x7;
	EBX = EBX | ECX;
	EAX = EBX;
	ECX = EBX;
	EAX = ~EAX;
	EAX = EAX & EBP_neg4;
	ECX = ECX & EDI;
	EAX = EAX | ECX;
	EAX = EAX + mem[14];
	EDX = EDX + EAX;
	EAX = EDX;
	EAX = EAX >> 0x15;
	EDX = EDX << 0xB;
	EAX = EAX | EDX;
	EDX = EBX;
	ECX = EAX;
	EDX = EDX & EAX;
	ECX = ~ECX;
	ECX = ECX & EDI;
	ECX = ECX | EDX;
	EDX = EBP_neg4;
	ECX = ECX + mem[15];
	EDX = EDX + ECX;
	ECX = EDX;
	ECX = ECX << 0x13;
	EDX = EDX >> 0xD;
	ECX = ECX | EDX;
	EDX = EAX;
	EBP_neg4 = ECX;
	EDX = EDX | ECX;
	ECX = EAX;
	EDX = EDX & EBX;
	ECX = ECX & EBP_neg4;
	EDX = EDX | ECX;
	EDX = EDX + mem[0];
	EDI = EDI + EDX + 0x5A826999;
	ECX = EDI;
	EDX = EDI;
	EDI = EBP_neg4;
	ECX = ECX >> 0x1D;
	EDX = EDX << 0x3;
	ECX = ECX | EDX;
	EBP_posC = EDI;
	EBP_posC = EBP_posC | ECX;
	EDI = EDI & ECX;
	EDX = EBP_posC;
	EDX = EDX & EAX;
	EDX = EDX | EDI;
	EDX = EDX + mem[4];
	EDX = EBX + EDX + 0x5A826999;
	EBX = EDX;
	EBX = EBX >> 0x1B;
	EDX = EDX << 0x5;
	EBX = EBX | EDX;
	EDX = EBP_posC;
	EDX = EDX & EBX;
	EBP_neg8 = EBX;
	EDX = EDX | EDI;
	EDX = EDX + mem[8];
	EDX = EAX + EDX + 0x5A826999;
	EAX = EDX;
	EAX = EAX >> 0x17;
	EDX = EDX << 0x9;
	EAX = EAX | EDX;
	EDX = EAX;
	EDI = EAX;
	EDX = EDX | ECX;
	EDI = EDI & ECX;
	EDX = EDX & EBX;
	EDX = EDX | EDI;
	EDI = EBP_neg4;
	EDX = EDX + mem[12];
	EDI = EDI + EDX + 0x5A826999;
	EDX = EDI;
	EDX = EDX >> 0x13;
	EDI = EDI << 0xD;
	EDX = EDX | EDI;
	EDI = EAX;
	EDI = EDI | EDX;
	EBP_neg4 = EDX;
	EDI = EDI & EBX;
	EBX = EAX;
	EBX = EBX & EDX;
	EDI = EDI | EBX;
	EBX = EBP_neg8;
	EDI = EDI + mem[1];
	ECX = ECX + EDI + 0x5A826999;
	EDI = ECX;
	EDI = EDI >> 0x1D;
	ECX = ECX << 0x3;
	EDI = EDI | ECX;
	ECX = EDX;
	EBP_neg4 = EBP_neg4 & EDI;
	ECX = ECX | EDI;
	EBP_pos8 = EDI;
	EDI = ECX;
	EDI = EDI & EAX;
	EDI = EDI | EBP_neg4;
	EDI = EDI + mem[5];
	EBX = EBX + EDI + 0x5A826999;
	EDI = EBX;
	EDI = EDI >> 0x1B;
	EBX = EBX << 0x5;
	EDI = EDI | EBX;
	ECX = ECX & EDI;
	ECX = ECX | EBP_neg4;
	ECX = ECX + mem[9];
	ECX = EAX + ECX + 0x5A826999;
	EAX = ECX;
	EAX = EAX >> 0x17;
	ECX = ECX << 0x9;
	EAX = EAX | ECX;
	ECX = EAX;
	EBX = EAX;
	ECX = ECX | EBP_pos8;
	EBX = EBX & EBP_pos8;
	ECX = ECX & EDI;
	ECX = ECX | EBX;
	EBX = EAX;
	ECX = ECX + mem[13];
	EDX = EDX + ECX + 0x5A826999;
	ECX = EDX;
	ECX = ECX >> 0x13;
	EDX = EDX << 0xD;
	ECX = ECX | EDX;
	EDX = EAX;
	EDX = EDX | ECX;
	EBX = EBX & ECX;
	EDX = EDX & EDI;
	EDX = EDX | EBX;
	EBX = EBP_pos8;
	EDX = EDX + mem[2];
	EBX = EBX + EDX + 0x5A826999;
	EDX = EBX;
	EBP_posC = ECX;
	EDX = EDX >> 0x1D;
	EBX = EBX << 0x3;
	EDX = EDX | EBX;
	EBP_neg4 = ECX;
	EBP_posC = EBP_posC | EDX;
	EBP_neg4 = EBP_neg4 & EDX;
	EBP_pos8 = EDX;
	EDX = EBP_posC;
	EDX = EDX & EAX;
	EDX = EDX | EBP_neg4;
	EDX = EDX + mem[6];
	EDI = EDI + EDX + 0x5A826999;
	EDX = EBP_posC;
	EBX = EDI;
	EBX = EBX >> 0x1B;
	EDI = EDI << 0x5;
	EBX = EBX | EDI;
	EDX = EDX & EBX;
	EBP_neg8 = EBX;
	EDX = EDX | EBP_neg4;
	EDX = EDX + mem[10];
	EDX = EAX + EDX + 0x5A826999;
	EAX = EDX;
	EAX = EAX >> 0x17;
	EDX = EDX << 0x9;
	EAX = EAX | EDX;
	EDX = EAX;
	EDI = EAX;
	EDX = EDX | EBP_pos8;
	EDI = EDI & EBP_pos8;
	EDX = EDX & EBX;
	EDX = EDX | EDI;
	EDI = EAX;
	EDX = EDX + mem[14];
	ECX = ECX + EDX + 0x5A826999;
	EDX = ECX;
	EDX = EDX >> 0x13;
	ECX = ECX << 0xD;
	EDX = EDX | ECX;
	ECX = EAX;
	ECX = ECX | EDX;
	EDI = EDI & EDX;
	ECX = ECX & EBX;
	EBP_posC = EDX;
	ECX = ECX | EDI;
	EDI = EBP_pos8;
	ECX = ECX + mem[3];
	EBP_neg4 = EDX;
	EDI = EDI + ECX + 0x5A826999;
	ECX = EDI;
	ECX = ECX >> 0x1D;
	EDI = EDI << 0x3;
	ECX = ECX | EDI;
	EBP_posC = EBP_posC | ECX;
	EBP_neg4 = EBP_neg4 & ECX;
	EDI = EBP_posC;
	EDI = EDI & EAX;
	EDI = EDI | EBP_neg4;
	EDI = EDI + mem[7];
	EDI = EBX + EDI + 0x5A826999;
	EBX = EDI;
	EBX = EBX >> 0x1B;
	EDI = EDI << 0x5;
	EBX = EBX | EDI;
	EDI = EBP_posC;
	EDI = EDI & EBX;
	EBP_neg8 = EBX;
	EDI = EDI | EBP_neg4;
	EDI = EDI + mem[11];
	EAX = EAX + EDI + 0x5A826999;
	EDI = EAX;
	EDI = EDI >> 0x17;
	EAX = EAX << 0x9;
	EDI = EDI | EAX;
	EAX = EDI;
	EAX = EAX | ECX;
	EAX = EAX & EBX;
	EBX = EDI;
	EBX = EBX & ECX;
	EAX = EAX | EBX;
	EBX = EBP_neg8;
	EAX = EAX + mem[15];
	EDX = EDX + EAX + 0x5A826999;
	EAX = EDX;
	EAX = EAX >> 0x13;
	EDX = EDX << 0xD;
	EAX = EAX | EDX;
	EDX = EBX;
	EDX = EDX ^ EDI;
	EDX = EDX ^ EAX;
	EDX = EDX + mem[0];
	ECX = ECX + EDX + 0x6ED9FBA1;
	EDX = ECX;
	EDX = EDX >> 0x1D;
	ECX = ECX << 0x3;
	EDX = EDX | ECX;
	ECX = EDI;
	ECX = ECX ^ EAX;
	ECX = ECX ^ EDX;
	ECX = ECX + mem[8];
	ECX = EBX + ECX + 0x6ED9FBA1;
	EBX = ECX;
	EBX = EBX >> 0x17;
	ECX = ECX << 0x9;
	EBX = EBX | ECX;
	ECX = EBX;
	EBP_pos8 = EBX;
	ECX = ECX ^ EAX;
	ECX = ECX ^ EDX;
	ECX = ECX + mem[4];
	ECX = EDI + ECX + 0x6ED9FBA1;
	EDI = ECX;
	EDI = EDI >> 0x15;
	ECX = ECX << 0xB;
	EDI = EDI | ECX;
	EBP_pos8 = EBP_pos8 ^ EDI;
	ECX = EBP_pos8;
	ECX = ECX ^ EDX;
	ECX = ECX + mem[12];
	ECX = EAX + ECX + 0x6ED9FBA1;
	EAX = ECX;
	EAX = EAX >> 0x11;
	ECX = ECX << 0xF;
	EAX = EAX | ECX;
	ECX = EBP_pos8;
	ECX = ECX ^ EAX;
	ECX = ECX + mem[2];
	EDX = EDX + ECX + 0x6ED9FBA1;
	ECX = EDX;
	ECX = ECX >> 0x1D;
	EDX = EDX << 0x3;
	ECX = ECX | EDX;
	EDX = EDI;
	EDX = EDX ^ EAX;
	EDX = EDX ^ ECX;
	EDX = EDX + mem[10];
	EBX = EBX + EDX + 0x6ED9FBA1;
	EDX = EBX;
	EDX = EDX >> 0x17;
	EBX = EBX << 0x9;
	EDX = EDX | EBX;
	EBX = EDX;
	EBP_pos8 = EDX;
	EBX = EBX ^ EAX;
	EBX = EBX ^ ECX;
	EBX = EBX + mem[6];
	EDI = EDI + EBX + 0x6ED9FBA1;
	EBX = EDI;
	EBX = EBX >> 0x15;
	EDI = EDI << 0xB;
	EBX = EBX | EDI;
	EBP_pos8 = EBP_pos8 ^ EBX;
	EDI = EBP_pos8;
	EDI = EDI ^ ECX;
	EDI = EDI + mem[14];
	EDI = EAX + EDI + 0x6ED9FBA1;
	EAX = EDI;
	EAX = EAX >> 0x11;
	EDI = EDI << 0xF;
	EAX = EAX | EDI;
	EDI = EBP_pos8;
	EDI = EDI ^ EAX;
	EDI = EDI + mem[1];
	EDI = ECX + EDI + 0x6ED9FBA1;
	ECX = EDI;
	ECX = ECX >> 0x1D;
	EDI = EDI << 0x3;
	ECX = ECX | EDI;
	EDI = EBX;
	EDI = EDI ^ EAX;
	EDI = EDI ^ ECX;
	EDI = EDI + mem[9];
	EDX = EDX + EDI + 0x6ED9FBA1;
	EDI = EDX;
	EDI = EDI >> 0x17;
	EDX = EDX << 0x9;
	EDI = EDI | EDX;
	EDX = EDI;
	EBP_pos8 = EDI;
	EDX = EDX ^ EAX;
	EDX = EDX ^ ECX;
	EDX = EDX + mem[5];
	EBX = EBX + EDX + 0x6ED9FBA1;
	EDX = EBX;
	EDX = EDX >> 0x15;
	EBX = EBX << 0xB;
	EDX = EDX | EBX;
	EBP_pos8 = EBP_pos8 ^ EDX;
	EBX = EBP_pos8;
	EBX = EBX ^ ECX;
	EBX = EBX + mem[13];
	EBX = EAX + EBX + 0x6ED9FBA1;
	EAX = EBX;
	EAX = EAX >> 0x11;
	EBX = EBX << 0xF;
	EAX = EAX | EBX;
	EBX = EBP_pos8;
	EBX = EBX ^ EAX;
	EBX = EBX + mem[3];
	EBX = ECX + EBX + 0x6ED9FBA1;
	ECX = EBX;
	ECX = ECX >> 0x1D;
	EBX = EBX << 0x3;
	ECX = ECX | EBX;
	EBX = EDX;
	EBX = EBX ^ EAX;
	ESI = ESI + ECX;
	EBX = EBX ^ ECX;
	EBX = EBX + mem[11];
	EDI = EDI + EBX + 0x6ED9FBA1;
	EBX = EDI;
	EBX = EBX >> 0x17;
	EDI = EDI << 0x9;
	EBX = EBX | EDI;
	EDI = EBX;
	ESI_posC = ESI_posC + EBX;
	EDI = EDI ^ EAX;
	EDI = EDI ^ ECX;
	EDI = EDI + mem[7];
	EDX = EDX + EDI + 0x6ED9FBA1;
	EDI = EDX;
	EDI = EDI >> 0x15;
	EDX = EDX << 0xB;
	EDI = EDI | EDX;
	EDX = EBX;
	EDX = EDX ^ EDI;
	ESI_pos8 = ESI_pos8 + EDI;
	EDX = EDX ^ ECX;
	EDX = EDX + mem[15];
	EAX = EAX + EDX + 0x6ED9FBA1;
	ECX = EAX;
	ECX = ECX >> 0x11;
	EAX = EAX << 0xF;
	ECX = ECX | EAX;
	ESI_pos4 = ESI_pos4 + ECX;
	return ESI ^ ESI_pos4 ^ ESI_pos8 ^ ESI_posC;
}

uint32_t init(string p1)
{
	//uint32_t dkey[4];
	//memcpy(dkey, val1, sizeof(uint32_t) * 4); //sizeof(uint32_t) = 32 bit, [0 .. 4,294,967,295]
	uint8_t mem[64];
	memset(mem, 0, sizeof(uint8_t) * 64); //sizeof(uint8_t) = 8 bit
	for (int32_t i = 0; i < 5; ++i)
		mem[i] = p1[i];					//mem0->mem4 la chuoi name
	mem[5] = 0x80;						//
	mem[56] = 0x28;						//
	uint32_t* x;
	x = (uint32_t*)mem;	//64 phần tử 8 bit -> 16 phần tử 8 bit, nối như sau: mem[3]mem[2]mem[1]mem[0]
	int32_t eax = Hash1(x);
	//char hex[9];
	//sprintf_s(hex, "%08X", eax);
	return eax;
}
//----------------------------------------------------------
//----------------------------------------------------------
string initString(string part1) {
	//xu li chuoi 1
	if (part1.size() != 5) return "Chuoi 1 phai co do dai la 5.\n";
	int countCharacter = 0;
	int countNumber = 0;
	//BDRQKPTVJI
	for (int i = 0; i < 5; i++) {
		if (part1[i] == 'B' || part1[i] == 'D' || part1[i] == 'R' ||
			part1[i] == 'Q' || part1[i] == 'K' || part1[i] == 'P' ||
			part1[i] == 'T' || part1[i] == 'V' || part1[i] == 'J' || part1[i] == 'I') countCharacter++;
		if (part1[i] >= '0' && part1[i] <= '9') countNumber++;
	}
	if (countCharacter!=3 || countNumber != 2) return "Chuoi 1 phai chua 3 ki tu tu chuoi BDRQKPTVJI va 2 chu so.\n";
	//ket thuc xu li chuoi 1

	return "1";
}

//--UI
void UI() {
	system("cls");
	cout << "-------------------------------------------------------------" << endl;
	cout << "         DO AN 3 MON KIEN TRUC MAY TINH VA HOP NGU" << endl;
	cout << "-------------------------------------------------------------" << endl;
	cout << "\t1. Vuong Thi Ngoc Linh - 18120195" << endl;
	cout << "\t2. Pham Ho Ngoc Tram   - 18120247" << endl;
	cout << "\t3. Pham Hoang Viet     - 18120261" << endl;
	cout << "\t4. Le Trong Bang       - 18120284" << endl;
	cout << "\t5. Vo Van Hoang Danh   - 18120304" << endl;
	cout << "-------------------------------------------------------------" << endl;
	cout << "\tKEYGEN 1_2:" << endl;
	cout << "-------------------------------------------------------------" << endl;
}


int main() {
	
	readData();
	string p1;
	string flag = "1";
	do {
		system("cls");
		UI();
		if (flag != "1") cout << flag << endl;
		//system("cls");
		cout << "\tPhan 1 (5 ki tu) -> phai chua 3 ki tu tu chuoi BDRQKPTVJI va 2 chu so. " << endl;
		cout << "\tPhan 1: " ; cin >> p1;
		//cout << "Nhap chuoi 2: " << endl; cin >> p2;
		flag = initString(p1);
	} while (flag != "1");
	uint32_t p2 = init(p1);
	//string p3 = process2(p2);
	uint32_t result = Hash234(p2);
	printf("\tPhan 2: %08X\n", result);
	system("pause");
	//test: VTT12 - 123456789
	// --> C431410A
	// --> 6EB732D8
	return 0;
}