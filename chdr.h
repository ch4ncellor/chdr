#pragma once

#include <Windows.h>
#include <vector>
#include <winnt.h>
#include <TlHelp32.h>
#include <fstream>
#include <comdef.h>
#include <map>
#include <Psapi.h>
#include <filesystem>
#include <winternl.h>

namespace chdr
{

#if 1
#define SHOULD_PRINT_DEBUG_LOGS // Log errors/verbose information.
#endif

#ifdef SHOULD_PRINT_DEBUG_LOGS
	// Custom debug assert/log.
#define CH_LOG(s, ...) { std::printf("[!] "); std::printf(s, __VA_ARGS__); std::printf("\n"); }
#define CH_ASSERT(x, b, s, ...) if (!(b)) {  if (s) CH_LOG(s, __VA_ARGS__) if constexpr (x) return;  }
#else
	// Custom debug assert/log.
#define CH_LOG(s, ...) (void)0
#define CH_ASSERT(x, b, s, ...) if (!(b)) { if (x) return;  }
#endif

	// Custom casting macros, because fucking C++ style casts are just TOO long.
#define CH_R_CAST reinterpret_cast
#define CH_S_CAST static_cast
#define CH_D_CAST dynamic_cast
#define CH_C_CAST const_cast

	// For ease of use.
	using ByteArray_t = std::vector<std::uint8_t>;

	// To be used internally by PEHeaderData_t.
	class Process_t;
	class Module_t;
	class Driver_t;

	class Module_t;

	// For easy and organized PE header parsing.
	class PEHeaderData_t
	{
		struct SectionData_t
		{
			std::string         m_szName = "";
			std::uint32_t		m_Address = 0u;
			std::uint32_t		m_Size = 0u;
			std::uint32_t		m_Characteristics = 0u;
			std::uint32_t		m_PointerToRawData = 0u;
			std::uint32_t		m_SizeOfRawData = 0u;
		};

		struct ExportData_t
		{
			std::uint32_t   m_nAddress = 0u;
			std::uint16_t	m_nOrdinal = 0u;
		};

		struct ImportData_t
		{
			std::string m_szModuleName = "";
			std::string m_szImportName = "";
		};

		struct DebugData_t
		{
			std::string         m_szPDBPath = "";
			std::string		    m_szGUIDSignature = "";
			std::uint32_t		m_Age = 0u;
			std::uint32_t		m_CVSignature = 0u;
		};

		// Only for PDB7.0 format!
		struct CV_INFO_PDB70 {
			DWORD	CvSignature;
			GUID	Signature;
			DWORD	Age;
			BYTE	PdbFileName[MAX_PATH];
		};

		// For caching desired data.
		std::vector<SectionData_t>          m_SectionData = { };
		std::map<std::string, ExportData_t> m_ExportData = { };
		std::vector<ImportData_t>           m_ImportData = { };
		std::vector<IMAGE_DATA_DIRECTORY>   m_DirectoryData = { };
		DebugData_t				            m_DebugData = { };

		PIMAGE_DOS_HEADER        m_pDOSHeaders = { 0 };
		PIMAGE_NT_HEADERS        m_pNTHeaders = { 0 };

		bool					 m_bIsValidInternal = false;
		std::uint32_t			 m_nMismatchedArchitecture = false;
	public:
		enum PEHEADER_PARSING_TYPE : std::int32_t
		{
			TYPE_NONE = (0 << 0),
			TYPE_ALL = (1 << 1),
			TYPE_EXPORT_DIRECTORY = (1 << 2),
			TYPE_IMPORT_DIRECTORY = (1 << 3),
			TYPE_DEBUG_DIRECTORY = (1 << 4),
			TYPE_SECTIONS = (1 << 5)
		};
	public:
		// Default ctor
		PEHeaderData_t() { }

		// Parsing data out of this image's buffer.
		PEHeaderData_t(std::uint8_t* m_ImageBuffer, std::size_t m_ImageSize, std::int32_t m_ParseType = PEHEADER_PARSING_TYPE::TYPE_NONE);

		// Parsing data out of this image's process.
		PEHeaderData_t(Process_t& m_Process, std::int32_t m_ParseType = PEHEADER_PARSING_TYPE::TYPE_ALL, std::uintptr_t m_CustomBaseAddress = NULL);

	public:
		// Ensure we found the target PE header.
		bool IsValid();

		// Helper function to get DOS header of PE image.
		PIMAGE_DOS_HEADER GetDOSHeader();

		// Helper function to get NT headers of PE image.
		PIMAGE_NT_HEADERS GetNTHeader();

		// Helper function to get specific data directory of PE image.
		IMAGE_DATA_DIRECTORY GetDataDirectory(std::size_t m_nDirIndex);

		// Helper function to get section data of PE image.
		std::vector<SectionData_t> GetSectionData();

		// Helper function to get exported functions' data of PE image.
		std::map<std::string, ExportData_t> GetExportData();

		// Helper function to get imported functions' data of PE image.
		std::vector<ImportData_t> GetImportData();

		// Helper function to get debug directories' data of PE image.
		DebugData_t GetDebugData();

		// Convert relative virtual address to file offset.
		std::uint32_t RvaToOffset(std::uint32_t m_dRva);

		// Convert file offset to relative virtual address.
		std::uint32_t OffsetToRva(std::uint32_t m_dOffset);

		// Get certain section by address in memory.
		SectionData_t GetSectionByAddress(std::uint32_t m_nAddress);

		// Get desired export address by name.
		std::uintptr_t GetRemoteProcAddress(const char* m_szExportName);
	};

	// PE Image utility helpers
	class ImageFile_t
	{
		PEHeaderData_t m_PEHeaderData = { };
	public:

		// Used for parsing PE's from file.
		ImageFile_t(const char* m_szImagePath, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL);

		// Used for parsing PE's from memory.
		ImageFile_t(std::uint8_t* m_ImageBuffer, std::size_t m_nImageSize, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL);

	public:
		ByteArray_t    m_ImageBuffer;

	public:

		// Ensure we found the target PE image.
		bool IsValid();

		// Helper function to get PE header data of PE image.
		PEHeaderData_t GetPEHeaderData();

		// Writes data in local buffer to file.
		void WriteToFile(const char* m_szFilePath);
	};

	// Driver utility helpers
	class Driver_t
	{
		std::string m_szDriverPath = "";
		HANDLE m_hTargetDriverHandle = { 0 };

	public:
		// Default ctor.
		Driver_t() { }

		// Initialize by driver path.
		Driver_t(const char* m_szDriverPath);

		// Initialize by driver information.
		Driver_t(const char* m_szDriverName, DWORD m_dDesiredAccess, DWORD m_dSharedMode, DWORD m_dCreationDisposition, DWORD m_dFlagsAndAttributes);

	public:

		// For opening an HANDLE to a currently loaded driver.
		bool SetupHandle(const char* m_szDriverName, DWORD m_dDesiredAccess, DWORD m_dSharedMode, DWORD m_dCreationDisposition, DWORD m_dFlagsAndAttributes);

		// For destroying a HANDLE to a currently loaded driver.
		bool DestroyHandle();

		// Send IOCTL request to the target driver, returning the response.
		DWORD SendIOCTL(DWORD m_dControlCode, LPVOID m_pInBuffer, DWORD m_dBufferSize, LPVOID m_pOutBuffer, DWORD m_dOutBufferSize);

		// Loads a target driver through the service manager. Obviously, these drivers must be SIGNED.
		SC_HANDLE LoadDriver(const char* m_szDriverPaths, const char* m_szDriverName);

		// Unloads a target driver that was previously loaded through the service manager.
		void UnloadDriver(const SC_HANDLE m_hLoadedStartedService);
	};

	class Module_t
	{
		std::uintptr_t m_dModuleBaseAddress = NULL;
		std::uint32_t  m_dModuleSize = NULL;

		PEHeaderData_t m_PEHeaderData = { };

	public:
		ByteArray_t m_ModuleData = { };

		// Default ctor
		Module_t() { }

		// Setup module in process by (non-case sensitive) name. 
		Module_t(chdr::Process_t& m_Process, const char* m_szModuleName, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL);

		// Setup module in process by address in process. (plz pass correct data here :D)
		Module_t(chdr::Process_t& m_Process, std::uintptr_t m_dModuleBaseAddress, std::uint32_t m_dModuleSize, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL);

		// Ease of use for building constructors.
		void SetupModule_Internal(chdr::Process_t& m_Process, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL);
	public:

		// Helper function to get PE header data of target process.
		PEHeaderData_t GetPEHeaderData();

		// Helper function to get module data of target process.
		ByteArray_t GetModuleData();

		// Ensure we found the target module in memory.
		bool IsValid();
	};

	class Thread_t
	{
		// Basic thread information.
		std::uint32_t m_dThreadID = 0;
		HANDLE m_hThreadHandle = { };

		// Acts as a lock, to only resume threads previously suspended.
		bool m_bIsThreadManuallySuspended = false;

		// Acts as a lock, to only free HANDLE's that we've internally obtained.
		bool m_bShouldFreeHandleAtDestructor = false;

	public:
		enum THREADINFOCLASS {
			ThreadBasicInformation,
			ThreadTimes,
			ThreadPriority,
			ThreadBasePriority,
			ThreadAffinityMask,
			ThreadImpersonationToken,
			ThreadDescriptorTableEntry,
			ThreadEnableAlignmentFaultFixup,
			ThreadEventPair,
			ThreadQuerySetWin32StartAddress,
			ThreadZeroTlsCell,
			ThreadPerformanceCount,
			ThreadAmILastThread,
			ThreadIdealProcessor,
			ThreadPriorityBoost,
			ThreadSetTlsArrayAddress,
			ThreadIsIoPending,
			ThreadHideFromDebugger
		};

		typedef NTSTATUS(__stdcall* NtQueryInformationThread_fn)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
	public:
		// Default ctor
		Thread_t() { }

		// Initialize with TID.
		Thread_t(std::uint32_t m_dThreadID);

		// Initialize with TID&HANDLE.
		Thread_t(HANDLE m_hThreadHandle);

		// Default dtor
		~Thread_t();

		// Terminating a target thread.
		void Terminate();

		// Suspending a target thread.
		void Suspend();

		// Resuming a target thread.
		void Resume();

		// Check which module this thread is associated with.
		std::string GetOwningModule(chdr::Process_t& m_Process, bool m_bUseCachedData = true);

		// Ensure we found a HANDLE to the target thread.
		bool IsValid();

		// Is the target thread suspended?
		bool IsSuspended();

		// Did we suspend the target thread ourselves?
		bool IsManuallySuspended();

		// Get's the start address of a target thread.
		std::uint32_t GetStartAddress();
	};

	// Process utility helpers
	class Process_t
	{
	public:
		// Default ctor
		Process_t() { }

		// Get target proces by name.
		Process_t(const wchar_t* m_wszProcessName, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL, DWORD m_dDesiredAccess = PROCESS_ALL_ACCESS);

		// Get target proces by PID.
		Process_t(std::uint32_t m_nProcessID, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL, DWORD m_dDesiredAccess = PROCESS_ALL_ACCESS);

		// Get target proces by HANDLE.
		Process_t(HANDLE m_hProcessHandle, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL);

		// Default dtor
		~Process_t();

		enum eManualMapInjectionFlags : std::int32_t
		{
			INJECTION_NONE = (0 << 0),
			INJECTION_MODE_THREADHIJACK = (1 << 1),
			INJECTION_MODE_CREATEREMOTETHREAD = (1 << 2),
			INJECTION_EXTRA_WIPEPEHEADERS = (1 << 3),
			INJECTION_EXTRA_WIPEGARBAGESECTIONS = (1 << 4),
			INJECTION_MAXIMUM = INJECTION_EXTRA_WIPEGARBAGESECTIONS + 1
		};

		enum class eProcessArchitecture : std::int32_t
		{
			ARCHITECTURE_UNKNOWN = (0 << 0),
			ARCHITECTURE_x64 = (1 << 6),
			ARCHITECTURE_x86 = (1 << 5),
			ARCHITECTURE_MAXIMUM = ARCHITECTURE_x86 + 1
		};

	private:
		PEHeaderData_t m_PEHeaderData = { };

		// Basic process information.
		HANDLE m_hTargetProcessHandle = { 0 };
		std::uint32_t  m_nTargetProcessID = 0;

		// For saving off this processes' architecture type.
		eProcessArchitecture m_eProcessArchitecture = eProcessArchitecture::ARCHITECTURE_UNKNOWN;

		// For saving off this processes' name.
		std::string m_szProcessName = "";

		// For saving off this processes' filesystem path.
		std::string m_szProcessPath = "";

		// Acts as a lock, to only resume threads previously suspended.
		bool m_bIsProcessManuallySuspended = false;

		// Acts as a lock, to only free HANDLE's that we've internally obtained.
		bool m_bShouldFreeHandleAtDestructor = false;

		enum PROCESSINFOCLASS
		{
			ProcessBasicInformation = 0x00,
			ProcessQuotaLimits = 0x01,
			ProcessIoCounters = 0x02,
			ProcessVmCounters = 0x03,
			ProcessTimes = 0x04,
			ProcessBasePriority = 0x05,
			ProcessRaisePriority = 0x06,
			ProcessDebugPort = 0x07,
			ProcessExceptionPort = 0x08,
			ProcessAccessToken = 0x09,
			ProcessLdtInformation = 0x0A,
			ProcessLdtSize = 0x0B,
			ProcessDefaultHardErrorMode = 0x0C,
			ProcessIoPortHandlers = 0x0D,
			ProcessPooledUsageAndLimits = 0x0E,
			ProcessWorkingSetWatch = 0x0F,
			ProcessUserModeIOPL = 0x10,
			ProcessEnableAlignmentFaultFixup = 0x11,
			ProcessPriorityClass = 0x12,
			ProcessWx86Information = 0x13,
			ProcessHandleCount = 0x14,
			ProcessAffinityMask = 0x15,
			ProcessPriorityBoost = 0x16,
			ProcessDeviceMap = 0x17,
			ProcessSessionInformation = 0x18,
			ProcessForegroundInformation = 0x19,
			ProcessWow64Information = 0x1A,
			ProcessImageFileName = 0x1B,
			ProcessLUIDDeviceMapsEnabled = 0x1C,
			ProcessBreakOnTermination = 0x1D,
			ProcessDebugObjectHandle = 0x1E,
			ProcessDebugFlags = 0x1F,
			ProcessHandleTracing = 0x20,
			ProcessIoPriority = 0x21,
			ProcessExecuteFlags = 0x22,
			ProcessResourceManagement = 0x23,
			ProcessCookie = 0x24,
			ProcessImageInformation = 0x25,
			ProcessCycleTime = 0x26,
			ProcessPagePriority = 0x27,
			ProcessInstrumentationCallback = 0x28,
			ProcessThreadStackAllocation = 0x29,
			ProcessWorkingSetWatchEx = 0x2A,
			ProcessImageFileNameWin32 = 0x2B,
			ProcessImageFileMapping = 0x2C,
			ProcessAffinityUpdateMode = 0x2D,
			ProcessMemoryAllocationMode = 0x2E,
			ProcessGroupInformation = 0x2F,
			ProcessTokenVirtualizationEnabled = 0x30,
			ProcessConsoleHostProcess = 0x31,
			ProcessWindowInformation = 0x32,
			ProcessHandleInformation = 0x33,
			ProcessMitigationPolicy = 0x34,
			ProcessDynamicFunctionTableInformation = 0x35,
			ProcessHandleCheckingMode = 0x36,
			ProcessKeepAliveCount = 0x37,
			ProcessRevokeFileHandles = 0x38,
			ProcessWorkingSetControl = 0x39,
			ProcessHandleTable = 0x3A,
			ProcessCheckStackExtentsMode = 0x3B,
			ProcessCommandLineInformation = 0x3C,
			ProcessProtectionInformation = 0x3D,
			ProcessMemoryExhaustion = 0x3E,
			ProcessFaultInformation = 0x3F,
			ProcessTelemetryIdInformation = 0x40,
			ProcessCommitReleaseInformation = 0x41,
			ProcessDefaultCpuSetsInformation = 0x42,
			ProcessAllowedCpuSetsInformation = 0x43,
			ProcessSubsystemProcess = 0x44,
			ProcessJobMemoryInformation = 0x45,
			ProcessInPrivate = 0x46,
			ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
			ProcessIumChallengeResponse = 0x48,
			ProcessChildProcessInformation = 0x49,
			ProcessHighGraphicsPriorityInformation = 0x4A,
			ProcessSubsystemInformation = 0x4B,
			ProcessEnergyValues = 0x4C,
			ProcessActivityThrottleState = 0x4D,
			ProcessActivityThrottlePolicy = 0x4E,
			ProcessWin32kSyscallFilterInformation = 0x4F,
			ProcessDisableSystemAllowedCpuSets = 0x50,
			ProcessWakeInformation = 0x51,
			ProcessEnergyTrackingState = 0x52,
			ProcessManageWritesToExecutableMemory = 0x53,
			ProcessCaptureTrustletLiveDump = 0x54,
			ProcessTelemetryCoverage = 0x55,
			ProcessEnclaveInformation = 0x56,
			ProcessEnableReadWriteVmLogging = 0x57,
			ProcessUptimeInformation = 0x58,
			ProcessImageSection = 0x59,
			ProcessDebugAuthInformation = 0x5A,
			ProcessSystemResourceManagement = 0x5B,
			ProcessSequenceNumber = 0x5C,
			ProcessLoaderDetour = 0x5D,
			ProcessSecurityDomainInformation = 0x5E,
			ProcessCombineSecurityDomainsInformation = 0x5F,
			ProcessEnableLogging = 0x60,
			ProcessLeapSecondInformation = 0x61,
			ProcessFiberShadowStackAllocation = 0x62,
			ProcessFreeFiberShadowStackAllocation = 0x63,
			MaxProcessInfoClass = 0x64
		};

		typedef NTSTATUS(__stdcall* NtSuspendProcess_fn)(HANDLE);
		typedef NTSTATUS(__stdcall* NtResumeProcess_fn)(HANDLE);
		typedef NTSTATUS(__stdcall* NtQueryInformationProcess_fn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

		// Relevant information pertaining a target thread.
		struct ThreadInformation_t
		{
			std::uint32_t		m_dThreadID = 0;
			std::uint32_t		m_dThreadStartAddress = 0;
			bool		        m_bIsThreadSuspended = false;
		};

		// Relevant information pertaining a target module.
		struct ModuleInformation_t
		{
			std::string    m_szName = "";
			std::string	   m_szPath = "";
			std::uint32_t  m_nSize = 0u;
			std::uintptr_t m_BaseAddress = 0u;
		};

		// Caching all loaded modules in target process.
		std::vector<Process_t::ModuleInformation_t> m_EnumeratedModulesCached = {};

		bool m_bHasCachedProcessesModules = false;

		// Get architecture of target process. 
		eProcessArchitecture GetProcessArchitecture_Internal();

		// Get name of target process.
		std::string GetProcessName_Internal();

		// Get filesystem path of target process.
		std::string GetProcessPath_Internal();

		// Internal manual map function.
		bool ManualMapInject_Internal(std::uint8_t* m_ImageBuffer, std::size_t m_nImageSize, eManualMapInjectionFlags m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);
	public:

		// Helper function to get architecture of target process. 
		eProcessArchitecture GetProcessArchitecture();

		// Helper function to get PE header data of target process.
		PEHeaderData_t GetPEHeaderData();

		// Helper function to get filesystem path of target process.
		std::string GetPath();

		// Helper function to get name of target process.
		std::string GetName();

		// The base address of the target process.
		std::uintptr_t GetBaseAddress();

		// The process ID of the target process. (lol)
		std::uint32_t GetProcessID();

		// The PEB of the target process.
		PEB GetPEB();

		// Ensure we found a HANDLE to the target process.
		bool IsValid();

		// Is target process 32-bit running on 64-bit OS?
		bool IsWow64();

		// Did we suspend the target process ourselves?
		bool IsManuallySuspended();

		// Is the target process suspended?
		bool IsSuspended();

		// Is the target process running under a debugger?
		bool IsBeingDebugged();

		// Manual map injection from module on disk.
		bool ManualMapInject(const char* m_szDLLPath, eManualMapInjectionFlags m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);

		// Manual map injection from module in memory.
		bool ManualMapInject(std::uint8_t* m_ImageBuffer, std::size_t m_nImageSize, eManualMapInjectionFlags m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);

		// Manual map injection from ImageFile_t.
		bool ManualMapInject(ImageFile_t& m_ImageFile, eManualMapInjectionFlags m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);

		// LoadLibrary injection from module on disk.
		bool LoadLibraryInject(const char* m_szDLLPath);

		// Traverse and cache data about all threads in a target process.
		std::vector<ThreadInformation_t> EnumerateThreads();

		// Traverse and cache data about all loaded modules in a target process.
		std::vector<ModuleInformation_t> EnumerateModules(bool m_bUseCachedData = false);

		// Sets debug privileges of a target process.
		bool SetDebugPrivilege(bool m_bShouldEnable);

		// Suspend every thread in a target process.
		void Suspend();

		// Resume every previously suspended thread in a target process.
		void Resume();

		// ReadProcessMemory implementation.
		template <class T>
		T Read(std::uintptr_t m_ReadAddress);

		// ReadProcessMemory implementation - allows byte arrays.
		template <typename S>
		std::size_t Read(std::uintptr_t m_ReadAddress, S m_pBuffer, std::size_t m_nBufferSize);

		// WriteProcessMemory implementation.
		template<typename S>
		std::size_t Write(std::uintptr_t m_WriteAddress,  S m_WriteValue);

		// WriteProcessMemory implementation.
		template<typename S>
		std::size_t Write(std::uintptr_t m_WriteAddress,  S m_WriteValue, std::size_t m_WriteSize);

		// VirtualAllocEx implementation.
		std::uintptr_t Allocate(std::size_t m_AllocationSize, DWORD m_dProtectionType);

		// VirtualFreeEx implementation.
		BOOL Free(LPVOID m_FreeAddress);

		// VirtualQueryEx implementation.
		std::size_t Query(LPCVOID m_QueryAddress, MEMORY_BASIC_INFORMATION* m_MemoryInformation);

		// _CreateRemoteThread implementation.
		std::int32_t _CreateRemoteThread(LPVOID m_lpStartAddress, LPVOID m_lpParameter);
	};


	namespace misc
	{

	}
}