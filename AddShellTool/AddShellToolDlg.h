
// AddShellToolDlg.h: 头文件
//

#pragma once
#include <string>
using namespace std;

// CAddShellToolDlg 对话框
class CAddShellToolDlg : public CDialogEx
{
// 构造
public:
	CAddShellToolDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ADDSHELLTOOL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:

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
		char key[17] = {0};
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

	CEdit m_Edit_FilePath;
	CEdit m_Edit_SaveDir;
	CEdit m_Edit_PassWord;

	//保存文件的起始地址，DWORD 方便计算
	DWORD m_FileBase = 0;
	//保存文件的大小
	DWORD m_FileSize = 0;
	//保存 dll 的加载基址(模块句柄)
	DWORD m_DllBase = 0;
	//保存共享数据块，主要用于提供信息给壳代码
	PSHAREDATA m_ShareData = nullptr;
	//保存 start 函数的段内偏移，用于计算新的 OEP
	DWORD m_StartOffset = 0;

	afx_msg void OnBnClickedButtonFilepath();
	afx_msg void OnBnClickedButtonSavedir();
	afx_msg void OnBnClickedButtonStartaddshell();
	afx_msg void OnDropFiles(HDROP hDropInfo);


	/*!
	*  函 数 名： LoadFile
	*  日    期： 2020/06/22
	*  返回类型： VOID
	*  参    数： CString FileName 待加壳程序的路径
	*  功    能： 加载待加壳程序到内存中
	*/
	VOID LoadFile(CString FileName);

	/*!
	*  函 数 名： LoadShell
	*  日    期： 2020/06/22
	*  返回类型： VOID
	*  参    数： LPCSTR FileName 壳文件的路径
	*  功    能： 加载壳文件 到内存中，并将密码写入共享结构体中
	*/
	VOID LoadShell(LPCSTR FileName);

	/*!
	*  函 数 名： DealWithTls
	*  日    期： 2020/06/27
	*  返回类型： VOID
	*  功    能： 保存待加壳程序真实的Tls
	*/
	VOID DealWithTls();

	/*!
	*  函 数 名： GetSection
	*  日    期： 2020/06/22
	*  返回类型： PIMAGE_SECTION_HEADER
	*  参    数： DWORD Base PE文件的加载基址
	*  参    数： LPCSTR SectionName 区段名
	*  功    能： 获取指定  PE 文件中指定的区段信息 
	*/
	PIMAGE_SECTION_HEADER GetSection(DWORD Base, LPCSTR SectionName);

	/*!
	*  函 数 名： NtHeader
	*  日    期： 2020/06/22
	*  返回类型： PIMAGE_NT_HEADERS
	*  参    数： DWORD Base PE文件的加载基址
	*  功    能： 获取 IMAGE_NT_HEADERS 结构体信息
	*/
	PIMAGE_NT_HEADERS NtHeader(DWORD Base);

	/*!
	*  函 数 名： DosHeader
	*  日    期： 2020/06/22
	*  返回类型： PIMAGE_DOS_HEADER
	*  参    数： DWORD Base PE文件的加载基址
	*  功    能： 获取 IMAGE_DOS_HEADER 结构体信息
	*/
	PIMAGE_DOS_HEADER DosHeader(DWORD Base);

	/*!
	*  函 数 名： FileHeader
	*  日    期： 2020/06/22
	*  返回类型： PIMAGE_FILE_HEADER
	*  参    数： DWORD Base PE文件的加载基址
	*  功    能： 获取 IMAGE_FILE_HEADER 结构体信息
	*/
	PIMAGE_FILE_HEADER FileHeader(DWORD Base);

	/*!
	*  函 数 名： OptHeader
	*  日    期： 2020/06/23
	*  返回类型： PIMAGE_OPTIONAL_HEADER
	*  参    数： DWORD Base PE文件的加载基址
	*  功    能： 获取 IMAGE_OPTIONAL_HEADER 结构体信息
	*/
	PIMAGE_OPTIONAL_HEADER OptHeader(DWORD Base);

	/*!
	*  函 数 名： AesEncrypt
	*  日    期： 2020/06/22
	*  返回类型： BOOL
	*  参    数： BYTE * pPassword 密钥
	*  参    数： DWORD dwPasswordLength 密钥长度
	*  参    数： BYTE * pData 需要AES加密的数据
	*  参    数： DWORD & dwDataLength 需要AES加密的数据长度
	*  参    数： DWORD dwBufferLength 缓冲区长度
	*  功    能： 先对密钥进行MD5加密，将加密后的数据作为真正的密钥对数据进行AES加密
	*/
	BOOL AesEncrypt(BYTE *pPassword, DWORD dwPasswordLength, BYTE *pData, DWORD &dwDataLength, DWORD dwBufferLength);

	/*!
	*  函 数 名： Encode
	*  日    期： 2020/06/24
	*  返回类型： std::string
	*  参    数： const unsigned char * Data 待加密数据的首地址
	*  参    数： int DataByte 待加密数据的长度
	*  功    能： 对数据进行base64加密
	*/
	string Encode(const unsigned char* Data, int DataByte);

	/*!
	*  函 数 名： CopySection
	*  日    期： 2020/06/23
	*  返回类型： VOID
	*  参    数： LPCSTR SectionName 待加壳程序指定区段名
	*  参    数： LPCSTR SrcName 壳代码指定区段名
	*  功    能： 将壳代码指定区段头信息拷贝到待加壳程序指定区段头信息
	*/
	VOID CopySection(LPCSTR SectionName, LPCSTR SrcName);

	/*!
	*  函 数 名： CopySectionData
	*  日    期： 2020/06/23
	*  返回类型： VOID
	*  参    数： LPCSTR SectionName 待加壳程序指定区段名
	*  参    数： LPCSTR SrcName 壳代码指定区段名
	*  功    能： 将壳代码指定区段内容拷贝到待加壳程序指定区段
	*/
	VOID CopySectionData(LPCSTR SectionName, LPCSTR SrcName);

	/*!
	*  函 数 名： Alignment
	*  日    期： 2020/06/23
	*  返回类型： DWORD	对齐后的大小
	*  参    数： DWORD n 实际字节
	*  参    数： DWORD align 对齐大小
	*  功    能： 按照指定对齐大小对数据进行对齐
	*/
	DWORD Alignment(DWORD n, DWORD align);

	/*!
	*  函 数 名： FixReloc
	*  日    期： 2020/06/23
	*  返回类型： VOID
	*  功    能： 修复壳代码的重定位并清除被加壳程序的重定位
	*/
	VOID FixReloc();

	/*!
	*  函 数 名： SetOep
	*  日    期： 2020/06/23
	*  返回类型： VOID
	*  功    能： 重新设置待加壳程序的OEP使其指向壳代码
	*/
	VOID SetOep();

	/*!
	*  函 数 名： SaveFile
	*  日    期： 2020/06/23
	*  返回类型： VOID
	*  参    数： CString FileName 保存的路径
	*  功    能： 保存加壳后的程序
	*/
	VOID SaveFile(CString FileName);

	/*!
	*  函 数 名： FreeShell
	*  日    期： 2020/06/23
	*  返回类型： VOID
	*  功    能： 释放壳代码
	*/
	VOID FreeShell();

	/*!
	*  函 数 名： ClearImport
	*  日    期： 2020/06/23
	*  返回类型： VOID
	*  功    能： 将导入表隐藏
	*/
	VOID HideImport();

	/*!
	*  函 数 名： EncryptSection
	*  日    期： 2020/06/24
	*  返回类型： VOID
	*  参    数： LPCSTR SectionName 
	*  功    能： 使用AES加密指定区段 (此处有坑)
	*/
	VOID EncryptSection(LPCSTR SectionName);

	/*!
	*  函 数 名： Comperss
	*  日    期： 2020/06/26
	*  返回类型： VOID
	*  参    数： LPCSTR SectionName 区段名
	*  功    能： 压缩指定区段
	*/
	VOID Comperss(LPCSTR SectionName);

	/*!
	*  函 数 名： AddSection
	*  日    期： 2020/06/26
	*  返回类型： VOID
	*  参    数： LPCSTR SectionName 新添区段名
	*  参    数： LPCSTR SrcName 已存在区段名，为了方便复制区段头信息
	*  参    数： char * pBuff		区段内容拷贝源地址
	*  参    数： DWORD dataSize	区段内容拷贝大小
	*  功    能： 给待加壳重新添加区段
	*/
	VOID AddSection(LPCSTR SectionName, LPCSTR SrcName, char* pBuff, DWORD dataSize);

	/*!
	*  函 数 名： RvaToOffset
	*  日    期： 2020/06/27
	*  返回类型： DWORD
	*  参    数： DWORD Rva 
	*  功    能： 将PE文件的rva转为文件偏移
	*/
	DWORD RvaToOffset(DWORD Rva);

	/*!
	*  函 数 名： SetTls
	*  日    期： 2020/06/27
	*  返回类型： VOID
	*  功    能： 设置TLS
	*/
	VOID SetTls();
};
