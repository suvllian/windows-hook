/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include <ntifs.h>
#include<ntimage.h>


#ifndef CXX_HookSSDT_H
#define CXX_HookSSDT_H

#define DEVICE_NAME  L"\\Device\\HookSSDTDevice"
#define LINK_NAME    L"\\??\\HookSSDTLink"


extern
char* PsGetProcessImageFileName(PEPROCESS EProcess);

extern
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID BaseAddress);

//定义SSDT表的结构
//定义SSDT表的结构
typedef struct _SYSTEM_SERVICE_TABLE_WIN7_X64 {
	PVOID  		ServiceTableBase;		//数组基地址
	PVOID  		ServiceCounterTableBase;
	ULONG64  	NumberOfServices;                     //SSDT表中的函数个数   0x191
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE_WIN7_X64, *PSYSTEM_SERVICE_TABLE_WIN7_X64;

typedef struct _SYSTEM_SERVICE_TABLE_WINXP_X86 {
	PVOID   ServiceTableBase;
	PVOID   ServiceCounterTableBase;
	ULONG32 NumberOfServices;                         //SSDT表中的函数个数   0x11c
	PVOID   ParamTableBase;
} SYSTEM_SERVICE_TABLE_WINXP_X86, *PSYSTEM_SERVICE_TABLE_WINXP_X86;


typedef
NTSTATUS
(*pfnNtOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);


#ifdef _WIN64
#define PSYSTEM_SERVICE_TABLE PSYSTEM_SERVICE_TABLE_WIN7_X64    
#else
#define PSYSTEM_SERVICE_TABLE PSYSTEM_SERVICE_TABLE_WINXP_X86   
#endif

#define SEC_IMAGE  0x01000000

/*Win7 64位下*/
BOOLEAN GetSSDTAddressInWin7_X64(ULONG64 *SSDTAddress);

BOOLEAN GetSSDTFunctionIndexFromNtdllExportTableByFunctionNameInWin7_X64(CHAR* szFindFunctionName, ULONG32* SSDTFunctionIndex);

/*Win7 64位End*/
VOID UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp);
NTSTATUS Fake_NtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

BOOLEAN GetSSDTAddressInWinXP_X86(ULONG* SSDTAddress);


PVOID GetExportVariableAddressFromNtosExportTableByVariableName(WCHAR* wzVariableName);
BOOLEAN GetSSDTFunctionIndexFromNtdllExportTableByFunctionNameInWinXP_X86(CHAR* szFindFunctionName, ULONG32* SSDTFunctionIndex);
BOOLEAN MappingPEFileInRing0Space(WCHAR* wzFileFullPath, OUT PVOID* MappingBaseAddress, PSIZE_T MappingViewSize);

VOID WPON();
VOID WPOFF();



VOID HookSSDTWinXP_X86(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG32 ulFakeVariable);
VOID HookSSDTWin7_X64(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG64 ulFakeVariable);

ULONG32 CalcFunctionOffsetInSSDT(ULONG64 ulFunctionAdddress, ULONG32 ulParamCount);

VOID InlineHook(ULONG64 ulOldVariable, ULONG64 ulFakeVariable, UCHAR* szOldCode, ULONG32 ulOldCodeLength);
VOID  UnInlineHook(ULONG64 ulOldVariable, UCHAR* szOldCode, ULONG32 ulOldCodeLength);

VOID UnHookSSDTWinXP_X86(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG32 ulOldVariable);
VOID UnHookSSDTWin7_X64(PULONG32 ServiceTableBase, ULONG32 ulSSDTFunctionIndex, ULONG32 ulOldVariable);
#endif