/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include "HookSSDT.h"



PULONG32			ServiceTableBase = NULL;
ULONG32				SSDT_NtOpenProcessIndex = 0;
pfnNtOpenProcess	Old_NtOpenProcess = NULL;
ULONG32				Old_NtOpenProcessOffset = 0;    //针对Win7 x64
UCHAR				szOldKeBugCheckExCode[15] = { 0 };


NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject,PUNICODE_STRING  RegisterPath)
{
#ifdef _WIN64
	ULONG64 SSDTAddress = NULL;
	ULONG32 ulVariable = 0;

	CHAR szFindFunctionName[] = "ZwOpenProcess";

	if (GetSSDTAddressInWin7_X64(&SSDTAddress) == FALSE)
	{
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("Win7x64 SSDT:%p\r\n", SSDTAddress);


	DbgPrint("Win7x64 SSDTNumberOfService:%d\r\n", ((PSYSTEM_SERVICE_TABLE)SSDTAddress)->NumberOfServices);

	if (!GetSSDTFunctionIndexFromNtdllExportTableByFunctionNameInWin7_X64(szFindFunctionName, &SSDT_NtOpenProcessIndex))
	{
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("Win7x64 ssdt_NtOpneProcessIndex:%d\r\n", SSDT_NtOpenProcessIndex);

	ServiceTableBase = (PULONG32)(((PSYSTEM_SERVICE_TABLE)SSDTAddress)->ServiceTableBase);
	Old_NtOpenProcessOffset = (ULONG32)(ServiceTableBase[SSDT_NtOpenProcessIndex]);
	ulVariable = Old_NtOpenProcessOffset >> 4;
	Old_NtOpenProcess = (ULONG64)((PSYSTEM_SERVICE_TABLE)SSDTAddress)->ServiceTableBase + ulVariable;

	DbgPrint("Win7x64 Old_NtOpenProcess:%p\r\n", ulVariable);


	HookSSDTWin7_X64(ServiceTableBase, SSDT_NtOpenProcessIndex, (ULONG64)Fake_NtOpenProcess);
#else
	ULONG32 SSDTAddress = NULL;

	//HOOK OpneProcess函数
	CHAR szFindFunctionName[] = "ZwOpenProcess";
	//得到SSDT表的基地址
	if (GetSSDTAddressInWinXP_X86(&SSDTAddress) == FALSE)
	{
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("Win_XP86 SSDT:%p\r\n", SSDTAddress);

	DbgPrint("WinXPx86 SSDTBase:%p\r\n", ((PSYSTEM_SERVICE_TABLE)SSDTAddress)->ServiceTableBase);

	DbgPrint("WinXPx86 SSDTNumberOfService:%d\r\n", ((PSYSTEM_SERVICE_TABLE)SSDTAddress)->NumberOfServices);

	if (GetSSDTFunctionIndexFromNtdllExportTableByFunctionNameInWinXP_X86(szFindFunctionName, &SSDT_NtOpenProcessIndex) == FALSE)
	{
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("WinXPx86 SSDT_NtOpenProcessIndex:%d\r\n", SSDT_NtOpenProcessIndex);

	//保存原先的地址
	ServiceTableBase = ((PSYSTEM_SERVICE_TABLE)SSDTAddress)->ServiceTableBase;
	Old_NtOpenProcess = (pfnNtOpenProcess)(ServiceTableBase[SSDT_NtOpenProcessIndex]);
	DbgPrint("WinXPx86 Old_NtOpenProcess:%p\r\n",Old_NtOpenProcess);

	HookSSDTWinXP_X86(ServiceTableBase, SSDT_NtOpenProcessIndex, (ULONG32)Fake_NtOpenProcess);
#endif
	DriverObject->DriverUnload = UnloadDriver;

	return STATUS_SUCCESS;
}

//SSDT表的基地址32位（4bytes）64位（8bytes）
//xp32位ntos模块的导出表中有  win764 ntos模块中的导出表中没有	
BOOLEAN GetSSDTAddressInWinXP_X86(ULONG* SSDTAddress)
{
	//从ntos   模块的导出表中得到全局变量  KeServiceDescriptorTable
	*SSDTAddress = NULL;
	*SSDTAddress = (ULONG32)GetExportVariableAddressFromNtosExportTableByVariableName(L"KeServiceDescriptorTable");
	if (*SSDTAddress != NULL)
	{
		return TRUE;
	}
	return FALSE;
}

//得到函数在导出表中的Ntdll中的索引
BOOLEAN GetSSDTFunctionIndexFromNtdllExportTableByFunctionNameInWinXP_X86(CHAR* szFindFunctionName, ULONG32* SSDTFunctionIndex)
{
	ULONG32 ulOffset_SSDTFunctionIndex = 1;

	ULONG i;
	BOOLEAN                 bOk = FALSE;
	WCHAR                   wzFileFullPath = L"\\SystemRoot\\System32\\ntdll.dll";
	SIZE_T                  MappingViewSize = 0;
	PVOID                   MappingBaseAddress = NULL;
	PIMAGE_NT_HEADERS       NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	ULONG32* AddressOfFunctions = NULL;
	ULONG32* AddressOfNames = NULL;
	USHORT*  AddressOfNameOrdinals = NULL;
	CHAR*    szFunctionName = NULL;
	ULONG32  ulFunctionOrdinal = 0;
	ULONG32  ulFunctionAddress = 0;

	*SSDTFunctionIndex = -1;

	bOk = MappingPEFileInRing0Space(wzFileFullPath, &MappingBaseAddress, &MappingViewSize);

	if (bOk == FALSE)
	{
		return FALSE;
	}
	else
	{
		__try
		{
			NtHeader = RtlImageNtHeader(MappingBaseAddress);

			if (NtHeader&&NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((ULONG32)MappingBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				//导出表中三个数组结构的首地址
				AddressOfFunctions = (ULONG32*)((ULONG32)MappingBaseAddress + ExportDirectory->AddressOfFunctions);
				AddressOfNames = (ULONG32*)((ULONG32)MappingBaseAddress + ExportDirectory->AddressOfNames);
				AddressOfNameOrdinals = (ULONG32*)((ULONG32)MappingBaseAddress + ExportDirectory->AddressOfNameOrdinals);

				for (i = 0; i < ExportDirectory->NumberOfNames; i++)
				{
					szFunctionName = (CHAR*)((ULONG32)MappingBaseAddress + AddressOfNames[i]);

					if (_stricmp(szFunctionName, szFindFunctionName) == 0)
					{
						ulFunctionOrdinal = AddressOfNameOrdinals[i];
						ulFunctionAddress = (ULONG32)((ULONG32)MappingBaseAddress + AddressOfFunctions[ulFunctionOrdinal]);
						*SSDTFunctionIndex = *(ULONG32*)(ulFunctionAddress + ulOffset_SSDTFunctionIndex);

						break;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			;
		}
	}
	//释放
	ZwUnmapViewOfSection(NtCurrentProcess(), MappingBaseAddress);

	if (*SSDTFunctionIndex == -1)
	{
		return FALSE;
	}

	return TRUE;
}


VOID HookSSDTWinXP_X86(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG32 ulFakeVariable)
{
	WPOFF();
	ServiceTableBase[ulSSDTFunctionIndex] = (ULONG32)ulFakeVariable;
	WPON();
}


NTSTATUS Fake_NtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	PEPROCESS EProcess = PsGetCurrentProcess();

	if (EProcess != NULL)
	{
		//获得进程名称
		char* szProcessImageName = PsGetProcessImageFileName(EProcess);

		if (strstr(szProcessImageName, "EnumProcess") != 0)
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	Old_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}



VOID WPOFF()
{
	//选择性编译，是给编译器看的
#if (defined(_M_AMD64) || defined(_M_IA64)) && !defined(_REALLY_GET_CALLERS_CALLER_)
	_disable();
	__writecr0(__readcr0() & (~(0x10000)));
#else
	__asm
	{
		CLI;
		MOV    EAX, CR0;
		AND    EAX, NOT 10000H;
		MOV    CR0, EAX;
}
#endif
}

VOID WPON()
{
#if (defined(_M_AMD64) || defined(_M_IA64)) && !defined(_REALLY_GET_CALLERS_CALLER_)
	__writecr0(__readcr0() ^ 0x10000);
	_enable();
#else
	__asm
	{
		MOV    EAX, CR0;
		OR     EAX, 10000H;
		MOV    CR0, EAX;
		STI;
}
#endif
}


PVOID GetExportVariableAddressFromNtosExportTableByVariableName(WCHAR* wzVariableName)
{
	UNICODE_STRING uniVariableName;
	PVOID pVariableAddress = NULL;

	if (wzVariableName&&wcslen(wzVariableName) > 0)
	{
		//动态分配一块指向第二参数的指针。第一参数的buffer直接指向第二参数，如果第一参数修改了  第二参数也会同时被修改。
		RtlInitUnicodeString(&uniVariableName, wzVariableName);
		//从NtOS的模块的导出表中得到函数地址,参数是unicode形式
		pVariableAddress = MmGetSystemRoutineAddress(&uniVariableName);
	}

	return pVariableAddress;
}



BOOLEAN GetSSDTFunctionIndexFromNtdllExportTableByFunctionNameInWin7_X64(CHAR* szFindFunctionName, ULONG32* SSDTFunctionIndex)
{
	ULONG32 ulOffsetSSDTFunctionIndex = 4;
	ULONG i;
	BOOLEAN bOk = FALSE;
	WCHAR wzFileFullPath[] = L"\\SystemRoot\\System32\\ntdll.dll";
	SIZE_T MappingViewSize = 0;
	PVOID MappingBaseAddress = NULL;
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	ULONG32* AddressOfFunctions = NULL;
	ULONG32* AddressOfNames = NULL;
	USHORT* AddressOfNameOrdinals = NULL;
	CHAR* szFunctionName = NULL;
	ULONG32 ulFunctionOrdinal = 0;
	ULONG64 ulFunctionAddress = 0;

	*SSDTFunctionIndex = -1;

	bOk = MappingPEFileInRing0Space(wzFileFullPath, &MappingBaseAddress, &MappingViewSize);
	if (bOk == FALSE)
	{
		return FALSE;
	}
	else
	{
		__try
		{
			NtHeader = RtlImageNtHeader(MappingBaseAddress);
			if (NtHeader&&NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((ULONG64)MappingBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); 


				AddressOfFunctions = (ULONG32*)((ULONG64)MappingBaseAddress + ExportDirectory->AddressOfFunctions);
				AddressOfNames = (ULONG32*)((ULONG64)MappingBaseAddress + ExportDirectory->AddressOfNames);
				AddressOfNameOrdinals = (USHORT*)((ULONG64)MappingBaseAddress + ExportDirectory->AddressOfNameOrdinals);
				for (i = 0; i < ExportDirectory->NumberOfNames; i++)
				{
					szFunctionName = (char*)((ULONG64)MappingBaseAddress + AddressOfNames[i]);   //获得函数名称
					if (_stricmp(szFunctionName, szFindFunctionName) == 0)
					{
						ulFunctionOrdinal = AddressOfNameOrdinals[i];
						ulFunctionAddress = (ULONG64)((ULONG64)MappingBaseAddress + AddressOfFunctions[ulFunctionOrdinal]);


						*SSDTFunctionIndex = *(ULONG32*)(ulFunctionAddress + ulOffsetSSDTFunctionIndex);
						break;
					}
				}
			}

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			;
		}
	}



}


VOID HookSSDTWin7_X64(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG64 ulFakeVariable)
{
	ULONG32 ulVariable = 0;
	WPOFF();

	InlineHook(KeBugCheckEx, ulFakeVariable, szOldKeBugCheckExCode, 15);
	WPON();

	ulVariable = CalcFunctionOffsetInSSDT(KeBugCheckEx, 5);
	WPOFF();
	ServiceTableBase[ulSSDTFunctionIndex] = (ULONG32)ulVariable;
	WPON();
	DbgPrint("Win7 HOOK Success\r\n");
}

ULONG32 CalcFunctionOffsetInSSDT(ULONG64 ulFunctionAdddress, ULONG32 ulParamCount)
{
	ULONG32 ulVariable = 0,i;
	CHAR v1 = 0;

	CHAR szBits[4] = { 0 };

	ulVariable = (ULONG32)(ulFunctionAdddress - (ULONG64)ServiceTableBase);
	ulVariable = ulVariable << 4;

	if (ulParamCount > 4)
	{
		ulParamCount = ulParamCount - 4;
	}
	else
	{
		ulParamCount = 0;
	}

	memcpy(&v1, &ulVariable, 1);

#define SETBIT(x,y) x|=(1<<y)
#define CLRBIT(x,y) x&=~(1<<y)
#define GETBIT(x,y) (x&(1<<y))

	for (i = 0; i < 4; i++)
	{
		szBits[i] = GETBIT(ulParamCount, i);
		if (szBits[i])
		{
			SETBIT(v1, i);
		}
		else
		{
			CLRBIT(v1, i);
		}
	}

	memcpy(&ulVariable, &v1, 1);
	return ulVariable;

}


VOID UnHookSSDTWinXP_X86(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG32 ulOldVariable)
{
	WPOFF();
	ServiceTableBase[ulSSDTFunctionIndex] = (ULONG32)ulOldVariable;
	WPON();
}


VOID UnHookSSDTWin7_X64(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG32 ulOldVariable)
{
	WPOFF();
	UnInlineHook(KeBugCheckEx, szOldKeBugCheckExCode, 15);
	WPON();

	WPOFF();
	ServiceTableBase[ulSSDTFunctionIndex] = (ULONG32)ulOldVariable;
	WPON();
}


VOID InlineHook(ULONG64 ulOldVariable, ULONG64 ulFakeVariable, UCHAR* szOldCode, ULONG32 ulOldCodeLength)
{
	ULONG64 ulVariable = 0;

	UCHAR szNewCode[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

	ulVariable = ulFakeVariable;
	memcpy(szOldCode, (PVOID)ulOldVariable, ulOldCodeLength);
	memcpy(szNewCode + 6, &ulVariable, 8);
	memset((PVOID)ulOldVariable, 0x90, ulOldCodeLength);
	memcpy((PVOID)ulOldVariable, szNewCode, 14);
}

VOID  UnInlineHook(ULONG64 ulOldVariable, UCHAR* szOldCode, ULONG32 ulOldCodeLength)
{
	memcpy((PVOID)ulOldVariable, szOldCode, ulOldCodeLength);
}



//将Ntdll.dll'模块映射到System.exe进程空间中
BOOLEAN MappingPEFileInRing0Space(WCHAR* wzFileFullPath, OUT PVOID* MappingBaseAddress, PSIZE_T MappingViewSize)
{
	UNICODE_STRING uniFileFullPath;
	OBJECT_ATTRIBUTES oa;		//文件绝对路径
	NTSTATUS Status;
	IO_STATUS_BLOCK Iosb;

	HANDLE hFile = NULL;
	HANDLE hSection = NULL;

	if (!wzFileFullPath || !MappingBaseAddress)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&uniFileFullPath, wzFileFullPath);
	InitializeObjectAttributes(&oa, &uniFileFullPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	//获得文件句柄
	Status = IoCreateFile(&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&Iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	oa.ObjectName = NULL;
	Status = ZwCreateSection(&hSection,
		SECTION_QUERY | SECTION_MAP_READ,
		&oa,
		NULL,
		PAGE_WRITECOPY,
		SEC_IMAGE,
		hFile);
	ZwClose(hFile);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	Status = ZwMapViewOfSection(
		hSection,
		NtCurrentProcess(),
		MappingBaseAddress,
		0,
		0,
		0, MappingViewSize,
		ViewUnmap,
		0,
		PAGE_WRITECOPY
	);
	ZwClose(hSection);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	return TRUE;
	
}

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

BOOLEAN GetSSDTAddressInWin7_X64(ULONG64 *SSDTAddress)
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);	//得到nt!KiSystemCall64基地址
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;   //只是一个区间
	PUCHAR i = NULL;

	UCHAR v1 = 0, v2 = 0, v3 = 0;
	INT64 iOffset = 0;
	ULONG64 VariableAddress = 0;

	*SSDTAddress = NULL;


	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		//检验地址是否合法
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			v1 = *i;
			v2 = *(i + 1);
			v3 = *(i + 2);
			if (v1 == 0x4c && v2 == 0x8d && v3 == 0x15)
			{
				memcpy(&iOffset, i + 3, 4);
				*SSDTAddress = iOffset + (ULONG64)i + 7;
				break;
			}
		}
	}

	if (*SSDTAddress == NULL)
	{
		return FALSE;
	}

	return TRUE;
}



VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
#ifdef _WIN64
	UnHookSSDTWin7_X64(ServiceTableBase, SSDT_NtOpenProcessIndex, (ULONG32)Old_NtOpenProcessOffset);
#else
	UnHookSSDTWinXP_X86(ServiceTableBase, SSDT_NtOpenProcessIndex, (ULONG32)Old_NtOpenProcess);
#endif
	
	DbgPrint("HookSSDT IS STOPPED!!!");
}
