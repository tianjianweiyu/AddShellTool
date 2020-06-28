
// AddShellToolDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "AddShellTool.h"
#include "AddShellToolDlg.h"
#include "afxdialogex.h"
#include <windows.h>
#include <wincrypt.h>
#include <DbgHelp.h>
#include "lz4.h"
#pragma comment(lib,"DbgHelp.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CAddShellToolDlg 对话框



CAddShellToolDlg::CAddShellToolDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ADDSHELLTOOL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAddShellToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_FILEPATH, m_Edit_FilePath);
	DDX_Control(pDX, IDC_EDIT_SAVEDIR, m_Edit_SaveDir);
	DDX_Control(pDX, IDC_EDIT_PASSWORD, m_Edit_PassWord);
}

BEGIN_MESSAGE_MAP(CAddShellToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_FILEPATH, &CAddShellToolDlg::OnBnClickedButtonFilepath)
	ON_BN_CLICKED(IDC_BUTTON_SAVEDIR, &CAddShellToolDlg::OnBnClickedButtonSavedir)
	ON_BN_CLICKED(IDC_BUTTON_STARTADDSHELL, &CAddShellToolDlg::OnBnClickedButtonStartaddshell)
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


// CAddShellToolDlg 消息处理程序

BOOL CAddShellToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	m_Edit_FilePath.SetWindowText(_T("支持拖拽待加壳程序"));

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAddShellToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAddShellToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAddShellToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CAddShellToolDlg::OnBnClickedButtonFilepath()
{
	// TODO: 在此添加控件通知处理程序代码

	//文件类型过滤
	const TCHAR pszFilter[] = _T("可执行文件 (*.exe)|*.exe||");

	//第一个参数为TRUE是打开文件，为FALSE是文件另存为
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
		pszFilter, this);
	TCHAR path[255];

	//获取当前用户的桌面路径
	SHGetSpecialFolderPath(0, path, CSIDL_DESKTOPDIRECTORY, 0);

	//设置对话框默认呈现的路径
	dlg.m_ofn.lpstrInitialDir = path;

	if (dlg.DoModal() == IDOK)
	{
		//获取选中的文件的路径并显示到编辑框上
		m_Edit_FilePath.SetWindowText(dlg.GetPathName());
	}

}


void CAddShellToolDlg::OnBnClickedButtonSavedir()
{
	// TODO: 在此添加控件通知处理程序代码

	CString strtemp;
	//获取待加壳程序名
	m_Edit_FilePath.GetWindowText(strtemp);

	//文件类型过滤
	const TCHAR pszFilter[] = _T("所有文件 (*.*)|*.*||");

	//第一个参数为TRUE是打开文件，为FALSE是文件另存为
	CFileDialog dlg(TRUE, NULL, strtemp, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
		pszFilter, this);


	if (dlg.DoModal() == IDOK)
	{
		//获取选中的文件的路径
		strtemp = dlg.GetPathName();
		//给加壳后的文件加上自己的后缀
		(wcsrchr(strtemp.GetBuffer(), '.'))[0] = 0;
		TCHAR  pszSaveName[MAX_PATH] = { 0 };
		_stprintf_s(pszSaveName, _T("%s%s"), strtemp.GetBuffer(), _T("_XB.exe"));
		//并显示到编辑框上
		m_Edit_SaveDir.SetWindowText(CString(pszSaveName));
	}
}


void CAddShellToolDlg::OnBnClickedButtonStartaddshell()
{
	// TODO: 在此添加控件通知处理程序代码

	//获取保存的路径
	CString temp;
	m_Edit_SaveDir.GetWindowText(temp);
	if (temp == "")
	{
		MessageBox(_T("请输入文件保存路径！"));
		return;
	}

	//获取密码
	m_Edit_PassWord.GetWindowText(temp);
	if (temp == "" || temp.GetLength() > 8)
	{
		MessageBox(_T("密码不能为空或大于8位！"));
		return;
	}

	//获取待加壳程序的路径
	m_Edit_FilePath.GetWindowText(temp);
	if (temp == "" || temp == "支持拖拽待加壳程序")
	{
		MessageBox(_T("请输入路径！"));
		return;
	}


	//将待加壳程序加载到内存
	LoadFile(temp);

	//将壳文件按加载到内存并将密码通过AES加密后的数据作为密码写入到共享结构体中
	LoadShell("MyShell.dll");

	//使用AES算法对区段(代码段)进行加密
	EncryptSection(".text");

	//压缩代码区段
	Comperss(".text");

	//为文件添加新的区段信息
	CopySection(".pack", ".text");

	//保存待加壳程序真实TLS
	DealWithTls();

	//重新设置 OEP 为 start 函数的地址
	SetOep();

	//对壳数据进行重定位
	FixReloc();

	//隐藏导入表
	HideImport();


	//将目标区段的所有内容拷贝到 PE 文件新增的区段处
	CopySectionData(".pack", ".text");

	SetTls();

	//将修改后的文件重新进行保存
	m_Edit_SaveDir.GetWindowText(temp);
	SaveFile(temp);

	FreeShell();
}

void CAddShellToolDlg::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	//获取文件路径
	TCHAR szPath[MAX_PATH] = { 0 };
	DragQueryFile(hDropInfo, 0, szPath, MAX_PATH);
	
	//过滤后缀名是否为exe
	LPTSTR pszExtension = PathFindExtension(szPath);

	if (lstrcmp(pszExtension, L".exe") == 0)
	{
		//显示到控件上
		m_Edit_FilePath.SetWindowText(szPath);
	}
	else
	{
		MessageBox(L"请拖入有效的exe文件");
	}

	CDialogEx::OnDropFiles(hDropInfo);
}

VOID CAddShellToolDlg::LoadFile(CString FileName)
{
	//如果文件存在，就打开文件，打开的目的只是为了读取其中的数据
	HANDLE FileHandle = CreateFile(FileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	//获取文件的大小，并使用这个大小申请缓存区
	m_FileSize = GetFileSize(FileHandle, NULL);
	m_FileBase = (DWORD)calloc(m_FileSize, sizeof(BYTE));

	//将目标文件的内容读取到创建的缓冲区中
	DWORD Read = 0;
	ReadFile(FileHandle, (LPVOID)m_FileBase, m_FileSize, &Read, NULL);

	//判断是不是PE文件
	//获取PE文件的第一个标记
	WORD Flag_1 = PIMAGE_DOS_HEADER(m_FileBase)->e_magic;
	//获取PE文件的第二个标记
	DWORD Flag_2 = PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(m_FileBase)->e_lfanew + m_FileBase)->Signature;
	//如果不是PE文件
	if (Flag_1 != IMAGE_DOS_SIGNATURE || Flag_2 != IMAGE_NT_SIGNATURE)
	{
		free((PVOID)m_FileBase);
		m_FileBase = NULL;
		MessageBox(_T("这不是一个有效的PE文件！"));
	}

	//为了防止句柄泄漏应该关闭句柄
	CloseHandle(FileHandle);
}

VOID CAddShellToolDlg::LoadShell(LPCSTR FileName)
{
	//以不执行 DllMain 的方式加载模块到当前的内存中
	m_DllBase = (DWORD)LoadLibraryExA(FileName, NULL, DONT_RESOLVE_DLL_REFERENCES);

	//从 dll 中获取到 start 函数，并计算它的段内偏移(函数地址 = 加载基址 + 区段基址 + 段内偏移)
	DWORD Start = (DWORD)GetProcAddress((HMODULE)m_DllBase, "start");
	m_StartOffset = Start - m_DllBase - GetSection(m_DllBase, ".text")->VirtualAddress;

	//获取到共享信息
	m_ShareData = (PSHAREDATA)GetProcAddress((HMODULE)m_DllBase, "ShareData");

	//获取密码
	CString temp;
	m_Edit_PassWord.GetWindowText(temp);
	USES_CONVERSION;
	char* pData= T2A(temp);
	DWORD dwDataLength = lstrlenA((LPCSTR)T2A(temp)) + 1;

	//对密码进行加密
	string strtemp = Encode((const unsigned char*)pData, dwDataLength);

	//写入加密后的密码到结构体中，供壳代码使用
	memcpy(m_ShareData->PassWord, strtemp.c_str(), 17);

 }

VOID CAddShellToolDlg::DealWithTls()
{
	//判断是否存在TLS表,如果存在TLS表
	if (OptHeader(m_FileBase)->DataDirectory[9].VirtualAddress != 0)
	{

		PIMAGE_TLS_DIRECTORY32 g_lpTlsDir =
			(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(OptHeader(m_FileBase)->DataDirectory[9].VirtualAddress) + m_FileBase);

		// 获取tlsIndex的Offset(文件偏移)
		DWORD indexOffset = RvaToOffset(g_lpTlsDir->AddressOfIndex - OptHeader(m_FileBase)->ImageBase);

		// 读取设置tlsIndex的值，默认为0
		if (indexOffset != -1)
		{
			m_ShareData->TlsIndex = *(DWORD*)(indexOffset + m_FileBase);
		}

		// 设置tls表中的信息
		m_ShareData->dwStartAddress = g_lpTlsDir->StartAddressOfRawData;
		m_ShareData->dwEndtAddress = g_lpTlsDir->EndAddressOfRawData;
		m_ShareData->dwCallBackAddress = g_lpTlsDir->AddressOfCallBacks;

		//保存壳的tls表的RVA
		m_ShareData->rva_Tls = OptHeader(m_DllBase)->DataDirectory[9].VirtualAddress
			- GetSection(m_DllBase, ".text")->VirtualAddress + GetSection(m_FileBase, ".pack")->VirtualAddress;


		m_ShareData->bIs_Tls = TRUE;
	}
}

PIMAGE_SECTION_HEADER CAddShellToolDlg::GetSection(DWORD Base, LPCSTR SectionName)
{
	//1.获取到区段表的第一项
	auto SectionTable = IMAGE_FIRST_SECTION(NtHeader(Base));

	//2.获取到区段表的元素个数
	WORD SectionCount = FileHeader(Base)->NumberOfSections;

	//3.遍历区段表，比较区段的名字，返回区段信息结构体的地址
	for (WORD i = 0; i < SectionCount; ++i)
	{
		//如果找到就直接返回
		if (!memcmp(SectionName, SectionTable[i].Name, strlen(SectionName) + 1))
			return &SectionTable[i];
	}
	return nullptr;
}

PIMAGE_NT_HEADERS CAddShellToolDlg::NtHeader(DWORD Base)
{
	return (PIMAGE_NT_HEADERS)(Base + DosHeader(Base)->e_lfanew);
}

PIMAGE_DOS_HEADER CAddShellToolDlg::DosHeader(DWORD Base)
{
	return (PIMAGE_DOS_HEADER)Base;
}

PIMAGE_FILE_HEADER CAddShellToolDlg::FileHeader(DWORD Base)
{
	return &NtHeader(Base)->FileHeader;
}

PIMAGE_OPTIONAL_HEADER CAddShellToolDlg::OptHeader(DWORD Base)
{
	return &NtHeader(Base)->OptionalHeader;
}

BOOL CAddShellToolDlg::AesEncrypt(BYTE *pPassword, DWORD dwPasswordLength, BYTE *pData, DWORD &dwDataLength, DWORD dwBufferLength)
{
	BOOL bRet = TRUE;
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hCryptHash = NULL;
	HCRYPTKEY hCryptKey = NULL;
	DWORD dwLength = dwDataLength;

	do
	{
		// 获取CSP句柄
		bRet = ::CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
		if (FALSE == bRet)
		{
			MessageBox(_T("CryptAcquireContext Error\r\n"));
			break;
		}

		// 创建HASH对象
		bRet = ::CryptCreateHash(hCryptProv, CALG_MD5, NULL, 0, &hCryptHash);
		if (FALSE == bRet)
		{
			MessageBox(_T("CryptCreateHash Error\r\n"));
			break;
		}

		// 对密钥进行HASH计算 计算出密钥的MD5值
		bRet = ::CryptHashData(hCryptHash, pPassword, dwPasswordLength, 0);
		if (FALSE == bRet)
		{
			MessageBox(_T("CryptHashData Error\r\n"));
			break;
		}

		// 使用HASH来生成密钥
		bRet = ::CryptDeriveKey(hCryptProv, CALG_AES_128, hCryptHash, CRYPT_EXPORTABLE, &hCryptKey);
		if (FALSE == bRet)
		{
			MessageBox(_T("CryptDeriveKey Error\r\n"));
			break;
		}

		//获取加密后数据的大小
		bRet = ::CryptEncrypt(hCryptKey, NULL, TRUE, 0, NULL, &dwLength, dwBufferLength);
		// 加密数据
		bRet = ::CryptEncrypt(hCryptKey, NULL, TRUE, 0, pData, &dwDataLength, dwLength);
		if (FALSE == bRet)
		{
			MessageBox(_T("CryptEncrypt Error\r\n"));
			break;
		}

	} while (FALSE);

	// 关闭释放
	if (hCryptKey)
	{		
		CryptDestroyKey(hCryptKey);
	}
	if (hCryptHash)
	{
		CryptDestroyHash(hCryptHash);
	}
	if (hCryptProv)
	{
		CryptReleaseContext(hCryptProv, 0);
	}

	return bRet;
}

string CAddShellToolDlg::Encode(const unsigned char* Data, int DataByte)
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

VOID CAddShellToolDlg::CopySection(LPCSTR SectionName, LPCSTR SrcName)
{
	//1.获取到区段头表的最后一个元素的地址
	auto LastSection = &IMAGE_FIRST_SECTION(NtHeader(m_FileBase))[FileHeader(m_FileBase)->NumberOfSections - 1];

	//2.将文件头中保存的区段数量 + 1
	FileHeader(m_FileBase)->NumberOfSections += 1;

	//3.通过最后一个区段头，找到新添加的区段头的位置
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	//4.从 dll 中找到我们需要拷贝的区段头
	auto SrcSection = GetSection(m_DllBase, SrcName);

	//5.直接将源区段头的完整信息拷贝到新的区段头中
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	//6.设置新的区段头中的数据： 名称
	memcpy(NewSection->Name, SectionName, 7);

	//7.设置新的区段所在的 RVA = 上一个区段的RVA + 对齐的内存大小(SectionAlignment为内存对齐粒度)
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, OptHeader(m_FileBase)->SectionAlignment);

	//8.设置新的区段所在的FOA = 上一个区段的FOA + 对齐的文件大小(SizeOfRawData已经经过文件对齐)
	NewSection->PointerToRawData = LastSection->PointerToRawData + LastSection->SizeOfRawData;

	//9.修改 SizeOfImage 的大小 = 最后一个区段的RVA + 最后一个区段的内存大小(不需要经过对齐)
	OptHeader(m_FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

	//10.重新计算文件的大小(原先的文件大小加上新区段的文件大小)，申请新的空间保存原有的数据
	m_FileSize = NewSection->SizeOfRawData + m_FileSize;
	m_FileBase = (DWORD)realloc((VOID*)m_FileBase, m_FileSize);
}

VOID CAddShellToolDlg::CopySectionData(LPCSTR SectionName, LPCSTR SrcName)
{
	//1.获取源区段在虚拟空间(dll - > 映像)中的基址
	BYTE* SrcData = (BYTE*)(GetSection(m_DllBase, SrcName)->VirtualAddress + m_DllBase);

	//2.获取目标区段在虚拟空间(堆 - >镜像)中的基址(读取到内存中，应该用文件偏移)
	BYTE* DestData = (BYTE*)(GetSection(m_FileBase, SectionName)->PointerToRawData + m_FileBase);

	//3.直接进行内存拷贝
	memcpy(DestData, SrcData, GetSection(m_DllBase, SrcName)->SizeOfRawData);
}

DWORD CAddShellToolDlg::Alignment(DWORD n, DWORD align)
{
	return n % align == 0 ? n : (n / align + 1)*align;
}

VOID CAddShellToolDlg::FixReloc()
{
	DWORD Size = 0, OldProtect = 0, Size_Reloc = 0;

	//新增加一个区段用于修复壳代码的重定位(使加壳后的程序能支持重定位)
	CopySection(".xbpack", ".reloc");

	//获取到待加壳程序的重定位表
	auto RealocTable = (PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToData((PVOID)m_DllBase, TRUE, 5, &Size);

	//如果 SizeOfBlock 不为空，就说明存在重定位块
	while (RealocTable->SizeOfBlock)
	{
		//只修复 .text 代码段的重定位
		if (RealocTable->VirtualAddress >= GetSection(m_DllBase, ".text")->VirtualAddress &&
			RealocTable->VirtualAddress < (GetSection(m_DllBase, ".text")->VirtualAddress + GetSection(m_DllBase, ".text")->Misc.VirtualSize))
		{
			//如果重定位的数据在代码段，就需要修改访问属性
			VirtualProtect((LPVOID)(RealocTable->VirtualAddress + m_DllBase), 0x1000, PAGE_READWRITE, &OldProtect);

			//获取重定位项数组的首地址和重定位项的数量
			int count = (RealocTable->SizeOfBlock - 8) / 2;
			TypeOffset* to = (TypeOffset*)(RealocTable + 1);

			//修复需要重定位的数据
			//遍历每一个重定位项，输出内容
			for (int i = 0; i < count; ++i)
			{
				//如果 type 的值为 3 我们才需要关注
				if (to[i].Type == 3)
				{
					//获取到需要重定位的地址所在的位置
					DWORD* addr = (DWORD*)(m_DllBase + RealocTable->VirtualAddress + to[i].Offset);

					//计算出不变的段内偏移 = *addr - imagebase - .text va
					DWORD item = *addr - m_DllBase - GetSection(m_DllBase, ".text")->VirtualAddress;

					//使用这个地址，计算出新的重定位后的数据
					*addr = item + OptHeader(m_FileBase)->ImageBase + GetSection(m_FileBase, ".pack")->VirtualAddress;
				}
			}

			//还原原区段的保护属性
			VirtualProtect((LPVOID)(RealocTable->VirtualAddress + m_DllBase), 0x1000, OldProtect, &OldProtect);

			//修改访问属性
			VirtualProtect(RealocTable, 0x8, PAGE_READWRITE, &OldProtect);

			//修改重定位的偏移
			RealocTable->VirtualAddress = RealocTable->VirtualAddress - GetSection(m_DllBase, ".text")->VirtualAddress
				+ GetSection(m_FileBase, ".pack")->VirtualAddress;

			//还原原区段的保护属性
			VirtualProtect(RealocTable, 0x8, OldProtect, &OldProtect);

		}
		else
		{
			//修改访问属性
			VirtualProtect(RealocTable, 0x8, PAGE_READWRITE, &OldProtect);
			RealocTable->VirtualAddress = 0;
			RealocTable->SizeOfBlock = 0;
			//还原原区段的保护属性
			VirtualProtect(RealocTable, 0x8, OldProtect, &OldProtect);
		}

		//重新计算重定位表的大小（去掉了后面不在 .text 内的重定位数据）
		Size_Reloc += RealocTable->SizeOfBlock;
		//找到下一个重定位块
		RealocTable = (PIMAGE_BASE_RELOCATION)((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}

	//关闭程序的重定位，目前只是修复了壳代码的重定位，并不表示源程序支持重定位
	if (m_ShareData->bIs_Tls)
	{
		OptHeader(m_FileBase)->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	}

	//将目标区段的所有内容拷贝到 PE 文件新增的区段处
	CopySectionData(".xbpack", ".reloc");

	//保存源程序的重定位表与默认加载基址
	m_ShareData->rva_reloc = OptHeader(m_FileBase)->DataDirectory[5].VirtualAddress;
	m_ShareData->ImageBaseOld = OptHeader(m_FileBase)->ImageBase;

	//将源程序的重定位表指向我们新增的区段
	OptHeader(m_FileBase)->DataDirectory[5].VirtualAddress = GetSection(m_FileBase, ".xbpack")->VirtualAddress;
	OptHeader(m_FileBase)->DataDirectory[5].Size = Size_Reloc;

}

VOID CAddShellToolDlg::SetOep()
{
	//修改原始 OEP 之前，保存 OEP
	m_ShareData->OldOep = OptHeader(m_FileBase)->AddressOfEntryPoint;

	//新的 rav = start 的段内偏移 + 新区段的 rva
	OptHeader(m_FileBase)->AddressOfEntryPoint = m_StartOffset + GetSection(m_FileBase, ".pack")->VirtualAddress;
}

VOID CAddShellToolDlg::SaveFile(CString FileName)
{
	//无论文件是否存在，都要创建新的文件(文件存在，进行重写，文件不存在，创建新文件)
	HANDLE FileHandle = CreateFile(FileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	//将目标文件的内容读取到创建的缓冲区中
	DWORD Write = 0;
	WriteFile(FileHandle, (LPVOID)m_FileBase, m_FileSize, &Write, NULL);

	//为了防止句柄泄漏应该关闭句柄
	CloseHandle(FileHandle);
}

VOID CAddShellToolDlg::FreeShell()
{
	FreeLibrary((HMODULE)m_DllBase);
}

VOID CAddShellToolDlg::HideImport()
{

	//获取到需要加壳的程序的导入表结构并保存
	m_ShareData->rva_import = OptHeader(m_FileBase)->DataDirectory[1].VirtualAddress;
	m_ShareData->size_import = OptHeader(m_FileBase)->DataDirectory[1].Size;

	//将导入表,IAT表的RVA 与大小 置为0
	OptHeader(m_FileBase)->DataDirectory[1].VirtualAddress = 0;
	OptHeader(m_FileBase)->DataDirectory[1].Size = 0;
	OptHeader(m_FileBase)->DataDirectory[12].VirtualAddress = 0;
	OptHeader(m_FileBase)->DataDirectory[12].Size = 0;

}

VOID CAddShellToolDlg::EncryptSection(LPCSTR SectionName)
{
	//1.获取到需要加密的区段的信息
	auto EncSection = GetSection(m_FileBase, SectionName);

	//2.找到需要加密的字段所在内存中的位置
	BYTE* data = (BYTE*)(EncSection->PointerToRawData + m_FileBase);

	//3.填写解密时需要提供的信息
	m_ShareData->rva_enc = EncSection->VirtualAddress;
	//加密的大小是实际大小(没有经过对齐)
	//这样后面多余的数据真好放加密后多出的数据
	//不会覆盖下一个区段内容
	//如果膨胀过大就会出问题 !!!注意
	m_ShareData->size_enc = EncSection->Misc.VirtualSize;

	BYTE key[17] = { 0 };
	srand((unsigned int)time(0));

	for (int i = 0; i < 16; i++)
	{
		key[i] = rand() % 10 + 0x30;
	}
	memcpy(m_ShareData->key, key, 17);

	//加密后 EncSection->SizeOfRawData 会变大，
	//如果膨胀过了区段内存对齐后的大小会覆盖其它区段 !!!注意
	//解密后加密多余的内容没有进行还原(之后有问题要注意，先这样)
	AesEncrypt(key, 17, data, m_ShareData->size_enc, 0);

}

VOID CAddShellToolDlg::Comperss(LPCSTR SectionName)
{
	//获取要压缩的区段信息
	auto pSection = GetSection(m_FileBase, SectionName);

	//压缩前位置
	char* pRoffset = (char*)(pSection->PointerToRawData + m_FileBase);

	//区段在文件中的大小(对齐后的)
	long lSize = pSection->SizeOfRawData;

	//保存压缩前信息
	//压缩前数据的RVA
	m_ShareData->FrontCompressRva = pSection->VirtualAddress;
	//压缩前大小Size
	m_ShareData->FrontCompressSize = lSize;

	//--------------------------------------------开始压缩
	// 1.获取预估的压缩后的字节数
	int compress_size = LZ4_compressBound(lSize);
	// 2.申请内存空间，用于保存压缩后的数据
	char* pBuff = new char[compress_size];
	// 3.开始压缩文件数据（函数返回压缩后的大小）
	m_ShareData->LaterCompressSize = LZ4_compress(
		pRoffset,	//压缩前的数据
		pBuff,	//压缩后的数据
		lSize	//文件原始大小
	);

	//如果压缩后数据反而变大
	if (m_ShareData->LaterCompressSize > pSection->SizeOfRawData)
	{

		//计算数据增多了多少
		DWORD incsize = Alignment(m_ShareData->LaterCompressSize,OptHeader(m_FileBase)->FileAlignment) - pSection->SizeOfRawData;
		// 重新修改文件实际大小
		// 实际大小 = 原大小 + 压缩后变多的大小
		m_FileSize = m_FileSize + incsize;

		// 申请新的空间保存原有的数据
		m_FileBase = (DWORD)realloc((VOID*)m_FileBase, m_FileSize);

		////重新获取要压缩的区段信息
		//pSection = GetSection(m_FileBase, SectionName);

		//DWORD temp = 0;

		//从最后一个开始外下移动
		//获取最后一个区段头信息
		auto pLast = &IMAGE_FIRST_SECTION(NtHeader(m_FileBase))[FileHeader(m_FileBase)->NumberOfSections - 1];

		while (memcmp(SectionName, pLast->Name, strlen(SectionName) + 1))
		{
			char* pDest = (char*)(pLast->PointerToRawData + incsize + m_FileBase);
			char* pSrc = (char*)(pLast->PointerToRawData + m_FileBase);
			//拷贝区段
			memcpy(pDest, pSrc, pLast->SizeOfRawData);

			//修改下个区段位置(相对于文件) 不加FileBase ,因为不在内存中
			pLast->PointerToRawData = pLast->PointerToRawData + incsize;
			
			////计算数据增多后对齐粒度与之前区段对齐粒度之差
			////如果增多的大小已经过了内存对齐粒度，就需要将之后的区段的RVA都向后移
			////不然文件被映射到内存时后面区段数据会覆盖压缩后部分数据
			////这种方法不行
			//temp = Alignment(m_ShareData->LaterCompressSize, OptHeader(m_FileBase)->SectionAlignment) 
			//	- Alignment(pSection->Misc.VirtualSize, OptHeader(m_FileBase)->SectionAlignment);
			//pLast->VirtualAddress += temp;

			pLast--;
		}

		// 将压缩后的数据覆盖原始数据
		memcpy((char*)(pLast->PointerToRawData + m_FileBase), pBuff, m_ShareData->LaterCompressSize);

		//将加密的数据单独放在一个区段，避免加密后数据过大，映射时被后面区段覆盖部分数据
		AddSection(".compe", ".text", pBuff, m_ShareData->LaterCompressSize);

		m_ShareData->LaterCompressRva = GetSection(m_FileBase, ".compe")->VirtualAddress;

	}
	//如果压缩数据变小
	else
	{
		// 计算数据减少了多少
		DWORD decsize = pSection->SizeOfRawData - Alignment(m_ShareData->LaterCompressSize, OptHeader(m_FileBase)->FileAlignment);
		
		//获取压缩区段下一个区段头信息
		auto pLater = pSection + 1;

		//没有后一个区段，就不需要提升
		while (pLater->VirtualAddress)
		{
			char* pDest = (char*)(pLater->PointerToRawData - decsize + m_FileBase);
			char* pSrc = (char*)(pLater->PointerToRawData + m_FileBase);
			//拷贝区段
			memcpy(pDest, pSrc, pLater->SizeOfRawData);

			//修改下个区段位置(相对于文件) 不加FileBase ,因为不在内存中
			pLater->PointerToRawData = pLater->PointerToRawData - decsize;

			//继续提升下个区段
			pLater++;
		}

		// 将压缩后的数据覆盖原始数据
		memcpy(pRoffset, pBuff, m_ShareData->LaterCompressSize);

		// 重新修改文件实际大小
		// 实际大小 = 原大小 + 压缩后减少的大小
		m_FileSize = m_FileSize - decsize;

		// 申请新的空间保存原有的数据
		m_FileBase = (DWORD)realloc((VOID*)m_FileBase, m_FileSize);

		// 修改当前区段文件大小
		pSection->SizeOfRawData = Alignment(m_ShareData->LaterCompressSize, OptHeader(m_FileBase)->FileAlignment);

		//压缩后数据的RVA
		m_ShareData->LaterCompressRva = pSection->VirtualAddress;
	}

	// 释放空间
	delete[] pBuff;
}

VOID CAddShellToolDlg::AddSection(LPCSTR SectionName, LPCSTR SrcName,char* pBuff,DWORD dataSize)
{
	//1.获取到区段头表的最后一个元素的地址
	auto LastSection = &IMAGE_FIRST_SECTION(NtHeader(m_FileBase))[FileHeader(m_FileBase)->NumberOfSections - 1];

	//2.将文件头中保存的区段数量 + 1
	FileHeader(m_FileBase)->NumberOfSections += 1;

	//3.通过最后一个区段头，找到新添加的区段头的位置
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	//4.从 exe 中找到我们需要拷贝的区段头
	auto SrcSection = GetSection(m_FileBase, SrcName);

	//5.直接将源区段头的完整信息拷贝到新的区段头中
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	//6.设置新的区段头中的数据： 名称
	memcpy(NewSection->Name, SectionName, 7);

	//7.设置新的区段所在的 RVA = 最后一个区段的RVA + 对齐的内存大小(SectionAlignment为内存对齐粒度)
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, OptHeader(m_FileBase)->SectionAlignment);

	//8.设置新的区段所在的FOA = 最后一个区段的FOA + 对齐的文件大小(SizeOfRawData已经经过文件对齐)
	NewSection->PointerToRawData = LastSection->PointerToRawData + LastSection->SizeOfRawData;

	//	设置新区段的文件大小
	NewSection->Misc.VirtualSize = dataSize;
	NewSection->SizeOfRawData = Alignment(dataSize, OptHeader(m_FileBase)->FileAlignment);

	//9.修改 SizeOfImage 的大小 = 最后一个区段的RVA + 最后一个区段的内存大小(不需要经过对齐)
	OptHeader(m_FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

	//10.重新计算文件的大小(原先的文件大小加上新区段的文件大小)，申请新的空间保存原有的数据
	m_FileSize = NewSection->SizeOfRawData + m_FileSize;
	m_FileBase = (DWORD)realloc((VOID*)m_FileBase, m_FileSize);

	//1.获取源区段在虚拟空间(dll - > 映像)中的基址
	BYTE* SrcData = (BYTE*)pBuff;

	//2.获取目标区段在虚拟空间(堆 - >镜像)中的基址(读取到内存中，应该用文件偏移)
	BYTE* DestData = (BYTE*)(GetSection(m_FileBase, SectionName)->PointerToRawData + m_FileBase);

	//3.直接进行内存拷贝
	memcpy(DestData, SrcData, dataSize);
}

// 用于将PE文件的rva转为文件偏移
DWORD CAddShellToolDlg::RvaToOffset(DWORD Rva)
{
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(NtHeader(m_FileBase));
	for (int i = 0; i < FileHeader(m_FileBase)->NumberOfSections; i++)
	{
		if (Rva >= pSection->VirtualAddress&&
			Rva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			// 如果文件地址为0,将无法在文件中找到对应的内容
			if (pSection->PointerToRawData == 0)
			{
				return -1;
			}
			return Rva - pSection->VirtualAddress + pSection->PointerToRawData;
		}
		pSection = pSection + 1;
	}
	return -1;
}

VOID CAddShellToolDlg::SetTls()
{
	if (m_ShareData->bIs_Tls == FALSE)return;
	//将待加壳程序目录表9指向壳的tls表
	DWORD A = OptHeader(m_FileBase)->DataDirectory[9].VirtualAddress;
	DWORD b = OptHeader(m_FileBase)->DataDirectory[9].Size;
	DWORD C = OptHeader(m_DllBase)->DataDirectory[9].VirtualAddress;
	DWORD d = OptHeader(m_DllBase)->DataDirectory[9].Size;

	OptHeader(m_FileBase)->DataDirectory[9].VirtualAddress = OptHeader(m_DllBase)->DataDirectory[9].VirtualAddress
		- GetSection(m_DllBase, ".text")->VirtualAddress + GetSection(m_FileBase, ".pack")->VirtualAddress;
	OptHeader(m_FileBase)->DataDirectory[9].Size = OptHeader(m_DllBase)->DataDirectory[9].Size;

	//此时获取的实际上是壳的tls表
	PIMAGE_TLS_DIRECTORY32  pITD =
		(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(OptHeader(m_FileBase)->DataDirectory[9].VirtualAddress) + m_FileBase);

	// 获取公共结构体中tlsIndex的va
	DWORD indexRva = ((DWORD)m_ShareData - (DWORD)m_DllBase + 4) - GetSection(m_DllBase, ".text")->VirtualAddress
		+ GetSection(m_FileBase, ".pack")->VirtualAddress + OptHeader(m_FileBase)->ImageBase;
	pITD->AddressOfIndex = indexRva;
	pITD->StartAddressOfRawData = m_ShareData->dwStartAddress;
	pITD->EndAddressOfRawData = m_ShareData->dwEndtAddress;
	pITD->AddressOfCallBacks = 0;
}

