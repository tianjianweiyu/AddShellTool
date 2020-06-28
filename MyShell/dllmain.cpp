// 用于提供壳代码，这部分的代码通常
// 会被用于解压缩(解密)，修复重定位，修复(加密)IAT
// 调用TLS函数之类的操作
#include "pch.h"
#include <wincrypt.h>
#include <string>
#include <stdlib.h>
#include "lz4.h"
using namespace std;

_declspec(thread) int g_num;

//将.data .rdata 合并到 .text 区段，并设置属性
//使得三个区段被存放在一起，减少依赖，方便拷贝
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

// 编写一个结构体，其中保存了需要进行共享的数据
typedef struct _SHAREDATA
{
	//Tls起始地址
	DWORD dwStartAddress = 0;
	//Tls索引
	DWORD TlsIndex = 0;
	//Tls结束地址
	DWORD dwEndtAddress = 0;
	//Tls回调函数地址
	DWORD dwCallBackAddress = 0;
	//是否存在TLS表
	BOOL bIs_Tls = FALSE;
	//TLS结构的RVA
	long rva_Tls = 0;
	//原始 OEP
	long OldOep = 0;
	//密码
	char PassWord[17] = { 0 };
	//原始重定位表的rva
	long rva_reloc = 0;
	//默认加载基址
	long ImageBaseOld = 0;
	//导入表的RVA
	long rva_import = 0;
	//导入表的大小
	long size_import = 0;
	//加密的rva
	long rva_enc = 0;
	//加密的大小
	DWORD size_enc = 0;
	//AES公钥
	char key[17] = { 0 };
	// 压缩前数据的位置
	long FrontCompressRva = 0;
	// 压缩前大小
	long FrontCompressSize = 0;
	// 压缩后数据的位置
	long LaterCompressRva = 0;
	// 压缩后的大小
	long LaterCompressSize = 0;
} SHAREDATA, *PSHAREDATA;

struct TypeOffset
{
	//偏移值
	WORD Offset : 12;
	//属性
	WORD Type : 4;
};

//获取加载基址
DWORD ImageBaseNew;

//打开的注册表的键的句柄
HKEY hkey;

//////////////////////////////////////////////////////////////////////
//定义需要函数的指针类型并声明变量
typedef HMODULE(WINAPI* PLoadLibraryExA)(
	_In_ LPCSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
	);
PLoadLibraryExA pLoadLibraryExA;

typedef FARPROC(WINAPI* PGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);
PGetProcAddress pGetProcAddress;

typedef HGDIOBJ(WINAPI* PGetStockObject)(_In_ int i);
PGetStockObject pGetStockObject;

typedef ATOM(WINAPI* PRegisterClassA)(
	_In_ CONST WNDCLASSA *lpWndClass);
PRegisterClassA pRegisterClassA;

typedef HWND(WINAPI* PCreateWindowExA)(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCSTR lpClassName,
	_In_opt_ LPCSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam);
PCreateWindowExA pCreateWindowExA;

typedef BOOL(WINAPI* PShowWindow)(
	_In_ HWND hWnd,
	_In_ int nCmdShow);
PShowWindow pShowWindow;

typedef BOOL(WINAPI* PUpdateWindow)(
	_In_ HWND hWnd);
PUpdateWindow pUpdateWindow;

typedef BOOL(WINAPI* PGetMessageA)(
	_Out_ LPMSG lpMsg,
	_In_opt_ HWND hWnd,
	_In_ UINT wMsgFilterMin,
	_In_ UINT wMsgFilterMax);
PGetMessageA pGetMessageA;

typedef BOOL(WINAPI* PTranslateMessage)(
	_In_ CONST MSG *lpMsg);
PTranslateMessage pTranslateMessage;

typedef LRESULT(WINAPI* PDispatchMessageA)(
	_In_ CONST MSG *lpMsg);
PDispatchMessageA pDispatchMessageA;

typedef BOOL(WINAPI* PDestroyWindow)(
	_In_ HWND hWnd);
PDestroyWindow pDestroyWindow;

typedef VOID(WINAPI* PPostQuitMessage)(
	_In_ int nExitCode);
PPostQuitMessage pPostQuitMessage;

typedef VOID(WINAPI* PExitProcess)(
	_In_ UINT uExitCode
	);
PExitProcess pExitProcess;

typedef HWND(WINAPI* PGetDlgItem)(
	_In_opt_ HWND hDlg,
	_In_ int nIDDlgItem);
PGetDlgItem pGetDlgItem;

typedef int(WINAPI* PGetWindowTextA)(
	_In_ HWND hWnd,
	_Out_writes_(nMaxCount) LPSTR lpString,
	_In_ int nMaxCount);
PGetWindowTextA pGetWindowTextA;

typedef LRESULT(WINAPI* PDefWindowProcA)(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam);
PDefWindowProcA pDefWindowProcA;


typedef int(WINAPI* PMessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);
PMessageBoxA pMessageBoxA;

typedef BOOL(WINAPI* PVirtualProtect)(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);
PVirtualProtect pVirtualProtect;

typedef BOOL(WINAPI* PCryptAcquireContextA)(
	_Out_       HCRYPTPROV  *phProv,
	_In_opt_    LPCSTR    szContainer,
	_In_opt_    LPCSTR    szProvider,
	_In_        DWORD       dwProvType,
	_In_        DWORD       dwFlags
);
PCryptAcquireContextA pCryptAcquireContextA;

typedef BOOL(WINAPI* PCryptCreateHash)(
	_In_    HCRYPTPROV  hProv,
	_In_    ALG_ID      Algid,
	_In_    HCRYPTKEY   hKey,
	_In_    DWORD       dwFlags,
	_Out_   HCRYPTHASH  *phHash
);
PCryptCreateHash pCryptCreateHash;

typedef BOOL(WINAPI* PCryptHashData)(
	_In_                    HCRYPTHASH  hHash,
	_In_reads_bytes_(dwDataLen)  CONST BYTE  *pbData,
	_In_                    DWORD   dwDataLen,
	_In_                    DWORD   dwFlags
);
PCryptHashData pCryptHashData;

typedef BOOL(WINAPI* PCryptDeriveKey)(
	_In_    HCRYPTPROV  hProv,
	_In_    ALG_ID      Algid,
	_In_    HCRYPTHASH  hBaseData,
	_In_    DWORD       dwFlags,
	_Out_   HCRYPTKEY   *phKey
);
PCryptDeriveKey pCryptDeriveKey;

typedef BOOL(WINAPI* PCryptDecrypt)(
	_In_                                            HCRYPTKEY   hKey,
	_In_                                            HCRYPTHASH  hHash,
	_In_                                            BOOL        Final,
	_In_                                            DWORD       dwFlags,
	_Inout_updates_bytes_to_(*pdwDataLen, *pdwDataLen)   BYTE        *pbData,
	_Inout_                                         DWORD       *pdwDataLen
);
PCryptDecrypt pCryptDecrypt;

typedef BOOL(WINAPI* PCryptDestroyKey)(
	_In_    HCRYPTKEY   hKey
);
PCryptDestroyKey pCryptDestroyKey;

typedef BOOL(WINAPI* PCryptDestroyHash)(
	_In_    HCRYPTHASH  hHash
);
PCryptDestroyHash pCryptDestroyHash;

typedef BOOL(WINAPI* PCryptReleaseContext)(
	_In_    HCRYPTPROV  hProv,
	_In_    DWORD       dwFlags
);
PCryptReleaseContext pCryptReleaseContext;

typedef DWORD(WINAPI* PGetLastError)(
	VOID
);
PGetLastError pGetLastError;

typedef LPVOID(WINAPI* PVirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD flAllocationType,
	_In_    DWORD flProtect
	);
PVirtualAlloc pVirtualAlloc;

typedef BOOL(WINAPI* PVirtualFree)(
	_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD dwFreeType
	);
PVirtualFree pVirtualFree;

typedef SIZE_T(WINAPI* PVirtualQuery)(
	_In_opt_ LPCVOID lpAddress,
	_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
	_In_ SIZE_T dwLength
	);
PVirtualQuery pVirtualQuery;

typedef LSTATUS(APIENTRY* PRegOpenKeyA)(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpSubKey,
	_Out_ PHKEY phkResult
	);
PRegOpenKeyA pRegOpenKeyA;


typedef LSTATUS(APIENTRY* PRegCloseKey)(
	_In_ HKEY hKey
	);
PRegCloseKey pRegCloseKey;

typedef HBRUSH(WINAPI* PCreateSolidBrush)(_In_ COLORREF color);
PCreateSolidBrush pCreateSolidBrush;

typedef HFONT(WINAPI* PCreateFontA)(_In_ int cHeight, _In_ int cWidth,
	_In_ int cEscapement, _In_ int cOrientation, _In_ int cWeight, _In_ DWORD bItalic,
	_In_ DWORD bUnderline, _In_ DWORD bStrikeOut, _In_ DWORD iCharSet,
	_In_ DWORD iOutPrecision, _In_ DWORD iClipPrecision,
	_In_ DWORD iQuality, _In_ DWORD iPitchAndFamily, _In_opt_ LPCSTR pszFaceName);
PCreateFontA pCreateFontA;

typedef LRESULT(WINAPI* PSendMessageA)(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_Pre_maybenull_ _Post_valid_ WPARAM wParam,
	_Pre_maybenull_ _Post_valid_ LPARAM lParam);
PSendMessageA pSendMessageA;

typedef int(WINAPI* PSetBkMode)(_In_ HDC hdc, _In_ int mode);
PSetBkMode pSetBkMode;

typedef HDC(WINAPI* PBeginPaint)(
	_In_ HWND hWnd,
	_Out_ LPPAINTSTRUCT lpPaint);
PBeginPaint pBeginPaint;

typedef BOOL(WINAPI* PEndPaint)(
	_In_ HWND hWnd,
	_In_ CONST PAINTSTRUCT *lpPaint);
PEndPaint pEndPaint;

typedef BOOL(WINAPI* PDeleteObject)(_In_ HGDIOBJ ho);
PDeleteObject pDeleteObject;

/////////////////////////////////////////////////////////////////////

extern "C"
{
	//导出一个变量，用于接收数据。数据应该存储在 data ,合并
	//和被保存在 text 段，text 段会被完整的拷贝到新的区段
	__declspec(dllexport) SHAREDATA ShareData;

	// 获取 kernel32.dll 的基址
	__declspec(naked) long getkernelbase()
	{
		__asm
		{
			//按照加载顺序
			mov eax, dword ptr fs : [0x30]
			mov eax, dword ptr[eax + 0x0C]
			mov eax, dword ptr[eax + 0x0C]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax + 0x18]
			ret
		}
	}

	//获取函数
	DWORD MyGetProcAddress(DWORD Module, LPCSTR FunName)
	{
		//获取 Dos 头 和 Nt 头
		auto DosHeader = (PIMAGE_DOS_HEADER)Module;
		auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);

		//获取导出表结构
		DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
		auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);

		//找到导出名称表、序号表、地址表
		auto NameTable = (DWORD*)(ExportTable->AddressOfNames + Module);
		auto FuncTable = (DWORD*)(ExportTable->AddressOfFunctions + Module);
		auto OrdinalTable = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);

		//遍历找名字
		for (DWORD i = 0; i < ExportTable->NumberOfNames; i++)
		{
			//获取名字
			char* Name = (char*)(NameTable[i] + Module);
			if (!strcmp(Name, FunName))
				return FuncTable[OrdinalTable[i]] + Module;
		}
		return -1;
	}

	//base64加密函数
	string Encode(const unsigned char* Data, int DataByte)
	{
		//编码表
		const char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		//返回值
		string strEncode;
		unsigned char Tmp[4] = { 0 };
		int LineLength = 0;

		for (int i = 0; i < (int)(DataByte / 3); i++)
		{
			Tmp[1] = *Data++;
			Tmp[2] = *Data++;
			Tmp[3] = *Data++;
			strEncode += EncodeTable[Tmp[1] >> 2];
			strEncode += EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
			strEncode += EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
			strEncode += EncodeTable[Tmp[3] & 0x3F];
			//换行，如果需要用到加密数据，需要注释掉
			//if (LineLength += 4, LineLength == 76){ strEncode += "\r\n"; LineLength = 0; }
		}

		//对剩余数据进行编码
		int Mod = DataByte % 3;
		if (Mod == 1)
		{
			Tmp[1] = *Data++;
			strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
			strEncode += EncodeTable[((Tmp[1] & 0x03) << 4)];
			strEncode += "==";
		}
		else if (Mod == 2)
		{
			Tmp[1] = *Data++;
			Tmp[2] = *Data++;
			strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
			strEncode += EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
			strEncode += EncodeTable[((Tmp[2] & 0x0F) << 2)];
			strEncode += "=";
		}

		return strEncode;
	}

	//获取壳代码需要的函数
	void GetApi()
	{
		//所有函数都在这里获取
		pLoadLibraryExA = (PLoadLibraryExA)MyGetProcAddress(getkernelbase(), "LoadLibraryExA");
		pGetProcAddress = (PGetProcAddress)MyGetProcAddress(getkernelbase(), "GetProcAddress");
		pExitProcess = (PExitProcess)MyGetProcAddress(getkernelbase(), "ExitProcess");
		pVirtualProtect = (PVirtualProtect)MyGetProcAddress(getkernelbase(), "VirtualProtect");
		pGetLastError = (PGetLastError)MyGetProcAddress(getkernelbase(), "GetLastError");
		pVirtualAlloc = (PVirtualAlloc)MyGetProcAddress(getkernelbase(), "VirtualAlloc");
		pVirtualFree = (PVirtualFree)MyGetProcAddress(getkernelbase(), "VirtualFree");
		pVirtualQuery = (PVirtualQuery)MyGetProcAddress(getkernelbase(), "VirtualQuery");

		HMODULE hModule_gdi = pLoadLibraryExA("gdi32.dll", NULL, NULL);
		pGetStockObject = (PGetStockObject)pGetProcAddress(hModule_gdi, "GetStockObject");
		pCreateSolidBrush = (PCreateSolidBrush)pGetProcAddress(hModule_gdi, "CreateSolidBrush");
		pCreateFontA = (PCreateFontA)pGetProcAddress(hModule_gdi, "CreateFontA");
		pSetBkMode = (PSetBkMode)pGetProcAddress(hModule_gdi, "SetBkMode");
		pDeleteObject = (PDeleteObject)pGetProcAddress(hModule_gdi, "DeleteObject");

		HMODULE hModule_user = pLoadLibraryExA("User32.dll", NULL, NULL);
		pRegisterClassA = (PRegisterClassA)pGetProcAddress(hModule_user, "RegisterClassA");
		pCreateWindowExA = (PCreateWindowExA)pGetProcAddress(hModule_user, "CreateWindowExA");
		pShowWindow = (PShowWindow)pGetProcAddress(hModule_user, "ShowWindow");
		pUpdateWindow = (PUpdateWindow)pGetProcAddress(hModule_user, "UpdateWindow");
		pGetMessageA = (PGetMessageA)pGetProcAddress(hModule_user, "GetMessageA");
		pTranslateMessage = (PTranslateMessage)pGetProcAddress(hModule_user, "TranslateMessage");
		pDispatchMessageA = (PDispatchMessageA)pGetProcAddress(hModule_user, "DispatchMessageA");
		pDestroyWindow = (PDestroyWindow)pGetProcAddress(hModule_user, "DestroyWindow");
		pPostQuitMessage = (PPostQuitMessage)pGetProcAddress(hModule_user, "PostQuitMessage");
		pGetDlgItem = (PGetDlgItem)pGetProcAddress(hModule_user, "GetDlgItem");
		pGetWindowTextA = (PGetWindowTextA)pGetProcAddress(hModule_user, "GetWindowTextA");
		pDefWindowProcA = (PDefWindowProcA)pGetProcAddress(hModule_user, "DefWindowProcA");
		pMessageBoxA = (PMessageBoxA)pGetProcAddress(hModule_user, "MessageBoxA");
		pSendMessageA = (PSendMessageA)pGetProcAddress(hModule_user, "SendMessageA");
		pBeginPaint = (PBeginPaint)pGetProcAddress(hModule_user, "BeginPaint");
		pEndPaint = (PEndPaint)pGetProcAddress(hModule_user, "EndPaint");

		HMODULE hModule_adv = pLoadLibraryExA("Advapi32.dll", NULL, NULL);
		pCryptAcquireContextA = (PCryptAcquireContextA)pGetProcAddress(hModule_adv, "CryptAcquireContextA");
		pCryptCreateHash = (PCryptCreateHash)pGetProcAddress(hModule_adv, "CryptCreateHash");
		pCryptHashData = (PCryptHashData)pGetProcAddress(hModule_adv, "CryptHashData");
		pCryptDeriveKey = (PCryptDeriveKey)pGetProcAddress(hModule_adv, "CryptDeriveKey");
		pCryptDecrypt = (PCryptDecrypt)pGetProcAddress(hModule_adv, "CryptDecrypt");
		pCryptDestroyKey = (PCryptDestroyKey)pGetProcAddress(hModule_adv, "CryptDestroyKey");
		pCryptDestroyHash = (PCryptDestroyHash)pGetProcAddress(hModule_adv, "CryptDestroyHash");
		pCryptReleaseContext = (PCryptReleaseContext)pGetProcAddress(hModule_adv, "CryptReleaseContext");
		pRegOpenKeyA = (PRegOpenKeyA)pGetProcAddress(hModule_adv, "RegOpenKeyA");
		pRegCloseKey = (PRegCloseKey)pGetProcAddress(hModule_adv, "RegCloseKey");
	}

	//窗口回调函数
	LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{

		static HWND Edithwnd = 0;		// 保存编辑框句柄
		static HFONT hFont;				//逻辑字体
		static HWND hStatic;			//静态文本框控件

		PAINTSTRUCT ps;
		HDC hdcWnd;
		HDC hdcStatic;

		//消息处理
		switch (uMsg)
		{
		case WM_CREATE:
		{
			//创建逻辑字体
			hFont = pCreateFontA(-0/*高*/, 0/*宽*/, 0, 0, 0 /*400表示正常字体*/,
				FALSE/*斜体?*/, FALSE/*下划线?*/, FALSE/*删除线?*/, DEFAULT_CHARSET,
				OUT_CHARACTER_PRECIS, CLIP_CHARACTER_PRECIS, DEFAULT_QUALITY,
				FF_DONTCARE, "微软雅黑"
			);
			//创建编辑框控件
			Edithwnd = pCreateWindowExA(NULL, "edit", NULL,
				WS_CHILD | WS_VISIBLE | WS_BORDER, 120, 48, 200, 30, hWnd, (HMENU)0x1000, (HINSTANCE)ImageBaseNew, 0);
			//创建提示文本
			pCreateWindowExA(NULL, "static", "密码：", WS_CHILD | WS_VISIBLE| SS_SIMPLE, 40, 50, 70, 30, hWnd, (HMENU)0x1002, (HINSTANCE)ImageBaseNew, 0);
			//创建按钮控件
			pCreateWindowExA(NULL, "button", "确定",
				WS_CHILD | WS_VISIBLE, 130, 100, 70, 30, hWnd, (HMENU)0x1001, (HINSTANCE)ImageBaseNew, 0);

			//设置控件的字体
			pSendMessageA(hStatic, WM_SETFONT, (WPARAM)hFont, NULL);
			break;
		}
		case WM_CTLCOLORSTATIC:
		{
			hdcStatic = (HDC)wParam;
			pSetBkMode(hdcStatic, TRANSPARENT); //透明背景
			return (INT_PTR)pGetStockObject(NULL_BRUSH);
			break;
		}
		case WM_PAINT:
		{
			hdcWnd = pBeginPaint(hWnd, &ps);
			pEndPaint(hWnd, &ps);
			break;
		}
		case WM_CLOSE:
		{
			pDeleteObject(hFont);
			//销毁当前的窗口
			pDestroyWindow(hWnd);
			//结束消息循环
			pPostQuitMessage(0);
			//退出程序
			pExitProcess(NULL);
			break;
		}
		case WM_COMMAND:
		{
			//按钮点击事件
			WORD wHigh = HIWORD(wParam);	//响应的消息类型
			WORD wLow = LOWORD(wParam);		//控件ID
			switch (wLow)
			{
				//点击确定按钮
			case 0x1001:
			{
				char buff[100] = {};

				//获取文本
				pGetWindowTextA(Edithwnd, buff, 100);

				string temp = Encode((const unsigned char*)buff, strlen(buff) + 1);

				memcpy(buff, temp.c_str(), 17);

				//判断解压密码是否正确
				if (!strcmp(buff, ShareData.PassWord))
				{
					//退出窗口
					pPostQuitMessage(0);
					pShowWindow(hWnd, SW_HIDE);
					break;
				}
				break;
			}

			}
			break;
		}
		}

		return pDefWindowProcA(hWnd, uMsg, wParam, lParam);
	}

	//密码框
	void PassBox()
	{
		__asm
		{
			push ebx
			; 获取当前程序的 PEB 信息
			mov ebx, dword ptr fs : [0x30]
			; PEB 中偏移为 0x08 保存的是加载基址
			mov ebx, dword ptr[ebx + 0x08]
			; 将加载基址保存
			mov ImageBaseNew, ebx
			pop ebx
		}

		//1.创建一个窗口类结构体，定义一个模块
		WNDCLASSA WndClass = { sizeof(WndClass) };
		WndClass.lpszClassName = "mywndcls";	//窗口类名
		WndClass.lpfnWndProc = WndProc;			//窗口回调函数
		WndClass.style = CS_HREDRAW | CS_VREDRAW;
		WndClass.hInstance = (HINSTANCE)ImageBaseNew;
		WndClass.hbrBackground = (HBRUSH)pGetStockObject(WHITE_BRUSH);

		//2.注册创建好的窗口类结构
		pRegisterClassA(&WndClass);

		//3.创建窗口
		HWND hWnd = pCreateWindowExA(NULL, WndClass.lpszClassName, "密码框",
			WS_OVERLAPPEDWINDOW, 400, 400, 400, 200, NULL, NULL, (HINSTANCE)ImageBaseNew, 0);

		//4.显示并更新创建的窗口
		pShowWindow(hWnd, SW_SHOWNORMAL);
		pUpdateWindow(hWnd);

		//5.消息泵
		MSG msg = { 0 };
		while (pGetMessageA(&msg, NULL, 0, 0))
		{
			//转换消息
			pTranslateMessage(&msg);
			//将消息的前 4 个传递给窗口对应窗口类中填写的回调函数
			pDispatchMessageA(&msg);
		}
	}

	//解压缩区段
	void uncompress()
	{
		//1.待解压的位置
		char* pSrc = (char*)(ShareData.LaterCompressRva + ImageBaseNew);

		//2.申请空间
		char* pBuff = (char*)pVirtualAlloc(0, ShareData.FrontCompressSize,
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//3.解压缩
		LZ4_uncompress_unknownOutputSize(
			pSrc,	//压缩后的数据
			pBuff,	//解压出来的数据
			ShareData.LaterCompressSize,	//压缩后的大小
			ShareData.FrontCompressSize		//压缩前的大小
		);

		pSrc = (char*)(ShareData.FrontCompressRva + ImageBaseNew);
		//4.修改属性
		DWORD OldProtect3;
		pVirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect3);

		//5.写入原始数据
		memcpy(pSrc, pBuff, ShareData.FrontCompressSize);

		//6.修复属性
		pVirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect3, &OldProtect3);

		//7.释放空间
		pVirtualFree(pBuff, 0, MEM_RELEASE);
	}

	/*!
	*  函 数 名： AesDecrypt
	*  日    期： 2020/06/24
	*  返回类型： BOOL
	*  参    数： BYTE * pPassword 密钥
	*  参    数： DWORD dwPasswordLength 密钥长度
	*  参    数： BYTE * pData 需要AES解密的数据
	*  参    数： DWORD & dwDataLength 需要AES解密的数据长度
	*  功    能： AES解密
	*/
	BOOL AesDecrypt(BYTE *pPassword, DWORD dwPasswordLength, BYTE *pData, DWORD &dwDataLength)
	{
		// 变量
		BOOL bRet = TRUE;
		HCRYPTPROV hCryptProv = NULL;
		HCRYPTHASH hCryptHash = NULL;
		HCRYPTKEY hCryptKey = NULL;

		do
		{
			// 获取CSP句柄
			bRet = pCryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
			if (FALSE == bRet)
			{
				pMessageBoxA(NULL, "CryptAcquireContext Error\r\n", "提示", NULL);
				break;
			}

			// 创建HASH对象
			bRet = pCryptCreateHash(hCryptProv, CALG_MD5, NULL, 0, &hCryptHash);
			if (FALSE == bRet)
			{
				pMessageBoxA(NULL, "CryptCreateHash Error\r\n", "提示", NULL);
				break;
			}

			// 对密钥进行HASH计算
			bRet = pCryptHashData(hCryptHash, pPassword, dwPasswordLength, 0);
			if (FALSE == bRet)
			{
				pMessageBoxA(NULL, "CryptHashData Error\r\n", "提示", NULL);
				break;
			}

			// 使用HASH来生成密钥
			bRet = pCryptDeriveKey(hCryptProv, CALG_AES_128, hCryptHash, CRYPT_EXPORTABLE, &hCryptKey);
			if (FALSE == bRet)
			{
				pMessageBoxA(NULL, "CryptDeriveKey Error\r\n", "提示", NULL);
				break;
			}

			// 解密数据
			bRet = pCryptDecrypt(hCryptKey, NULL, TRUE, 0, pData, &dwDataLength);
			if (FALSE == bRet)
			{
				DWORD error = pGetLastError();
				pMessageBoxA(NULL, "CryptDecrypt Error\r\n", "提示", NULL);
				break;
			}
		} while (FALSE);

		// 关闭释放 
		if (hCryptKey)
		{
			pCryptDestroyKey(hCryptKey);
		}
		if (hCryptHash)
		{
			pCryptDestroyHash(hCryptHash);
		}
		if (hCryptProv)
		{
			pCryptReleaseContext(hCryptProv, 0);
		}
		return bRet;
	}

	//解密区段
	void DecryptSection()
	{
		DWORD OldProtect;

		__asm
		{
			push ebx
			; 获取当前程序的 PEB 信息
			mov ebx, dword ptr fs : [0x30]
			; PEB 中偏移为 0x08 保存的是加载基址
			mov ebx, dword ptr[ebx + 0x08]
			; 将 需要解密的区段的 RVA 加上基址
			add ShareData.rva_enc, ebx
			pop ebx
		}

		//修改页面属性位可读可写
		pVirtualProtect((LPVOID)ShareData.rva_enc, ShareData.size_enc, PAGE_READWRITE, &OldProtect);

		//执行完了第一个汇编指令之后 ShareData.rva_enc 就是 va 了
		AesDecrypt((BYTE*)ShareData.key, 17, (BYTE*)ShareData.rva_enc, ShareData.size_enc);

		//恢复原属性
		pVirtualProtect((LPVOID)ShareData.rva_enc, ShareData.size_enc, OldProtect, &OldProtect);

	}

	//修复 iat ，加密iat
	void fixiat()
	{
		//构造跳转代码(改代码对IAT进行解密，该代码有花指令)
		BYTE shellcode[] = {
			0xE8, 0x01 ,0x00, 0x00, 0x00,		// 00360000    E8 01000000     CALL 00360006
			0xE9, 0x58 ,0xEB, 0x01, 0xE8,		//00360005 - E9 58EB01E8     JMP E837EB62
			0xB8, 0x16 ,0x74, 0xF9, 0x63,		//0036000A    B8 1674F963     MOV EAX,0x63F97416
			0xEB, 0x01 ,	   					//0036000F    EB 01           JMP SHORT 00360012
			0x15, 0x35 ,0x15, 0x15, 0x15,		//00360011    15 35151515     ADC EAX,0x15151535
			0x15, 0xEB ,0x01, 0xFF, 0x50,		//00360016    15 EB01FF50     ADC EAX,0x50FF01EB
			0xEB, 0x02 ,	   					//0036001B    EB 02           JMP SHORT 0036001F
			0xFF, 0x15 ,0xC3, 0x00, 0x00, 0x00, //0036001D    FF15 C3000000   CALL DWORD PTR DS : [0xC3]
		};

		DWORD OldProtect2;
		MEMORY_BASIC_INFORMATION pBuff = { 0 };

		//获取导入表结构
		auto ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(ShareData.rva_import + ImageBaseNew);

		//遍历导入表
		while (ImportTable->Name)
		{
			//获取IAT
			auto pIat = (PIMAGE_THUNK_DATA)(ImportTable->FirstThunk + ImageBaseNew);

			//获取 Dll 名字
			auto dllname = (char*)(ImportTable->Name + ImageBaseNew);

			//加载 Dll
			auto hModule = pLoadLibraryExA(dllname, NULL, NULL);

			//保存获取到的函数地址
			DWORD hProcAddr;

			//遍历 IAT
			while (pIat->u1.Ordinal)
			{
				//判断最高位是否为1，不为1则为名称导入
				if (!(pIat->u1.Ordinal & 0x80000000))
				{
					//获取导入的名称
					auto funName = PIMAGE_IMPORT_BY_NAME(pIat->u1.AddressOfData + ImageBaseNew)->Name;

					//获取函数地址
					hProcAddr = (DWORD)pGetProcAddress(hModule, funName);

				}
				//如果是序号导入的
				else
				{
					//获取序号
					auto funOrd = (pIat->u1.Ordinal) & 0xFFFF;

					//获取函数地址
					hProcAddr = (DWORD)pGetProcAddress(hModule, (LPCSTR)funOrd);

				}

				//获取函数地址所在处的属性
				pVirtualQuery((LPVOID)hProcAddr, &pBuff, sizeof(MEMORY_BASIC_INFORMATION));
				//如果是读写属性，没有执行属性，应该就是导入变量
				//直接将地址填充到IAT中，遍历下一个
				if (!(pBuff.Protect & 0xF0))
				{
					//修改属性
					pVirtualProtect((LPVOID)pIat, 0x1, PAGE_READWRITE, &OldProtect2);

					//直接将地址填充到IAT中
					pIat->u1.Function = hProcAddr;

					//恢复属性
					pVirtualProtect((LPVOID)pIat, 0x1, OldProtect2, &OldProtect2);

					//遍历下一个IAT
					pIat++;
					continue;
				}

				//申请一段空间存放IAT解密代码
				auto addr_alloc = (DWORD)pVirtualAlloc(NULL, 35, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				//加密函数地址并替换shellcode中的部分数据
				*(DWORD*)&shellcode[11] = hProcAddr ^ 0x15151515;

				//将解密的shellcode拷贝到申请的空间中
				memcpy((BYTE*)addr_alloc, shellcode, 35);

				//修改属性
				pVirtualProtect((LPVOID)pIat, 0x1, PAGE_READWRITE, &OldProtect2);

				//将申请的地址填充到IAT中
				pIat->u1.Function = addr_alloc;

				//恢复属性
				pVirtualProtect((LPVOID)pIat, 0x1, OldProtect2, &OldProtect2);

				//遍历下一个IAT
				pIat++;
			}

			//遍历下一个导入表
			ImportTable++;
		}

	}

	//修复重定位
	void fixreloc()
	{
		if (ImageBaseNew == ShareData.ImageBaseOld)
			return;

		DWORD OldProtect1;

		//获取重定位表
		auto RealocTable = (PIMAGE_BASE_RELOCATION)(ShareData.rva_reloc + ImageBaseNew);

		//修复需要重定位的数据
		//如果 SizeOfBlock 不为空，就说明存在重定位块
		while (RealocTable->SizeOfBlock)
		{
			//如果重定位的数据在代码段，就需要修改访问属性
			//同时修改两页属性，是防止需要重定位的数据(四个字节)所在的地址
			//占了两个页面，如其中两个字节在前一页，后两字节在后一页
			pVirtualProtect((LPVOID)(RealocTable->VirtualAddress + ImageBaseNew), 0x2000, PAGE_EXECUTE_READWRITE, &OldProtect1);

			//获取重定位项数组的首地址和重定位项的数量
			int count = (RealocTable->SizeOfBlock - 8) / 2;
			TypeOffset* to = (TypeOffset*)(RealocTable + 1);

			//遍历每一个重定位项，输出内容
			for (int i = 0; i < count; ++i)
			{
				//如果 type 的值为 3 我们才需要关注
				if (to[i].Type == 3)
				{
					//获取到需要重定位的地址所在的位置
					DWORD* addr = (DWORD*)(ImageBaseNew + RealocTable->VirtualAddress + to[i].Offset);

					//使用这个地址，计算出新的重定位后的数据
					*addr = *addr + ImageBaseNew - ShareData.ImageBaseOld;
				}
			}

			//还原原区段的保护属性
			//pVirtualProtect((LPVOID)(RealocTable->VirtualAddress + ImageBaseNew), 0x2000, OldProtect1, &OldProtect1);

			//找到下一个重定位块
			RealocTable = (PIMAGE_BASE_RELOCATION)((DWORD)RealocTable + RealocTable->SizeOfBlock);
		}

	}

	//修复TLS
	void fixtls()
	{
		//获取TLS结构
		auto TlsTable = (PIMAGE_TLS_DIRECTORY)(ShareData.rva_Tls + ImageBaseNew);

		TlsTable->AddressOfCallBacks = ShareData.dwCallBackAddress;

		//获取TLS回调函数组成的数组
		auto TlsCallBackTable = (DWORD*)TlsTable->AddressOfCallBacks;

		//回调函数数组以NULL结尾，当里面为零时证明回调函数调用完了
		//结束循环
		while (*TlsCallBackTable)
		{
			//获取回调函数地址
			auto Tls_CallBack = (PIMAGE_TLS_CALLBACK)*TlsCallBackTable;

			//调用回调函数
			Tls_CallBack((PVOID)ImageBaseNew, DLL_PROCESS_ATTACH, 0);

			//下一个tls回调函数
			TlsCallBackTable++;
		}

	}

	//反调试,如果被调试返回true,没有被调试返回false
	bool anti_debug()
	{
		//1.BeingDebugged检查，其值为1则处于被调试状态
		bool BeginDebugged = false;
		__asm
		{
			//获取PEB地址
			mov eax, dword ptr fs : [0x30]
			//获取PEB.BeginDebugged
			mov al, byte ptr ds : [eax + 0x02]
			mov BeginDebugged, al
		}

		//2.NtGlobalFlag在调试状态时值为0x70,正常下为0
		int NtGlobalFlag = 0;
		__asm
		{
			//获取PEB地址
			mov eax, dword ptr fs : [0x30]
			//获取PEB.NtGlobalFlag
			mov eax, dword ptr ds : [eax + 0x68]
			mov NtGlobalFlag, eax
		}
		NtGlobalFlag == 0x70 ? NtGlobalFlag = 1 : NtGlobalFlag = 0;

		if (BeginDebugged || NtGlobalFlag)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	//反虚拟机,查询注册表键
	bool CheckWMWare()
	{
		if (pRegOpenKeyA(HKEY_CLASSES_ROOT, "\\Applications\\VMwareHostOpen.exe", &hkey) == ERROR_SUCCESS)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	//跳转到原始的 oep
	__declspec(naked) long jmpoep()
	{
		__asm
		{
			
			; 获取当前程序的 PEB 信息
			mov eax, dword ptr fs : [0x30]
			; PEB 中偏移为 0x08 保存的是加载基址
			mov eax, dword ptr[ebx + 0x08]
			; 将加载基址和 oep 相加
			add eax, ShareData.OldOep
			; 跳转到原始 oep处
			jmp eax
		}
	}

	//提供(导出)一个函数，用于作为源程序的新 OEP
	__declspec(dllexport) __declspec(naked) void start()
	{
		//这个函数是一个裸函数，没有名称粉碎并且是导出的

		//使用Tls变量
		g_num;

		//获取所需API地址
		GetApi();

		if (anti_debug())
		{
			pMessageBoxA(NULL, "正在被调试", "提示", MB_ICONERROR);
			pExitProcess(NULL);
		}

		if (CheckWMWare())
		{
			pMessageBoxA(NULL, "无法在虚拟机运行", "提示", MB_ICONERROR);
			pRegCloseKey(hkey);
			pExitProcess(NULL);
		}
		pRegCloseKey(hkey);

		//密码框
		PassBox();

		//解压缩区段
		uncompress();

		//解密区段
		DecryptSection();

		//修复IAT加密IAT
		fixiat();

		//修复重定位
		fixreloc();

		if (ShareData.bIs_Tls)
		{
			//修复tls
			fixtls();
		}

		//跳转到原始 oep
		jmpoep();

	}
}