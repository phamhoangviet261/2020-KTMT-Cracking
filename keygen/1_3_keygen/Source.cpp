#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

bool checkName(string &name) {
	if (name.length() > 10) return false;
	else {
		for (int i = 0; i < name.length(); i++) {
			if (name[i] < 'A') return false;
			else {
				name[i] = name[i] - ('a' - 'A');
			}
		}
	}
	return true;
}

int subASCII(string name) {
	int S = 0;
	for (int i = 0; i < name.length(); i++) {
		S = S + int(name[i]);
	}
	return S;
}

string decToHexa(int n)
{
	int r;
	string res = "";
	char hex[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
	while (n > 0)
	{
		r = n % 16;
		res = hex[r] + res;
		n = n / 16;
	}
	return res;
}

// vd: abcd -> dcba
void ReverseString(string& a)
{
	unsigned int n = a.length();
	for (unsigned int i = 0; i < n / 2; i++)
		swap(a[i], a[n - i - 1]);
}

char numTochar(int a)
{
	return a + '0'; //0x30 => 48 => '0'
}

string getPassWord(int tmp)
{
	string res; // password
	while (tmp > 0)
	{
		res += numTochar(tmp % 10);
		tmp /= 10;
	}
	ReverseString(res);
	return res;
}

//--UI
void UI(){
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
	cout << "\tKEYGEN 1_3:" << endl;
	cout << "-------------------------------------------------------------" << endl;
}

int main() {	
	string s;
	do {
		UI();
		cout << "\tName: "; cin >> s;
		//checkName(s);
	} while (checkName(s) == false);
    //cout << "Name input: " << s << endl;
	//cout << "Number convert: " << decToHexa(subASCII(s)) << endl;
	int tmp = subASCII(s);
	tmp ^= 22136;		//0x5678 => 22136
	tmp ^= 4660;		//0x1234 => 4660
	cout << "\tSerial Number: " << getPassWord(tmp) << endl;
	system("pause");
	return 0;
}