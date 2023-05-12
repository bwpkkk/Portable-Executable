#include<iostream>
#include<windows.h>
#include<stdlib.h>
using namespace std;

int main ()
{
	char input;
	
	FARPROC funcAddr = GetProcAddress(GetModuleHandleA("USER32.dll"), "MessageBoxW");
	wchar_t buf[100];
	_itow_s((int)(funcAddr), buf, 16);

	/*while (1)
	{
		cout << "press g for messageBoxW" << endl;
		cin >> input;
		if (input == 'g' || input == 'G')
		{
			MessageBoxW(0, buf, L"MessageBoxW",0);
		}
		else
		{
			break;
		}
	}*/

	cout << "press g for messageBoxW" << endl;
	cin >> input;
	if (input == 'g' || input == 'G')
	{
		MessageBoxW(0, buf, L"MessageBoxW", 0);
	}
	cout << "press g for messageBoxW" << endl;
	cin >> input;
	if (input == 'g' || input == 'G')
	{
		MessageBoxW(0, buf, L"MessageBoxW", 0);
	}
	getchar();
	return 0;
}