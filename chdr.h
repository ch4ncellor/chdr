#pragma once

#include <Windows.h>
#include <vector>
#include <winnt.h>
#include <TlHelp32.h>
#include <fstream>
#include <comdef.h>
#include <Psapi.h>
#include <filesystem>
 
namespace chdr
{
	
#if 1
#define SHOULD_PRINT_DEBUG_LOGS // Log errors/verbose information.
#endif

#ifdef SHOULD_PRINT_DEBUG_LOGS
	// Custom debug assert/log.
#define CH_ASSERT(x, b, s, ...) if (!(b)) {  if (s) { std::printf("[!] "); printf_s(s, __VA_ARGS__); std::printf("\n"); } if constexpr (x) return;  }
#define CH_LOG(s, ...) std::printf("[!] "); std::printf(s, __VA_ARGS__); std::printf("\n");
#else
	// Custom debug assert/log.
#define CH_ASSERT(x, b, s, ...) if (!(b)) { if (x) return;  }
#define CH_LOG(s, ...) (void)0
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
			std::string m_szSectionName = "";
			DWORD		m_dSectionAddress = 0;
			DWORD		m_dSectionSize = 0;
		};

		struct ExportData_t
		{
			std::string m_szExportName = "";
			DWORD		m_dExportAddress = 0;
			DWORD		m_dOrdinalNumber = 0;
		};

		struct ImportData_t
		{
			std::string m_szModuleName = "";
			std::string m_szImportName = "";
		};
		
		// For caching desired data.
		std::vector<SectionData_t> m_SectionData = {};
		std::vector<ExportData_t> m_ExportData = {};
		std::vector<ImportData_t> m_ImportData = {};

		PIMAGE_DOS_HEADER        m_pDOSHeaders = { 0 };
		PIMAGE_NT_HEADERS        m_pNTHeaders = { 0 };
		PIMAGE_FILE_HEADER       m_pFileHeaders = { 0 };
		PIMAGE_SECTION_HEADER    m_pSectionHeaders = { 0 };

		DWORD					 m_dExportedFunctionCount = 0;
	public:

		// Default ctor
		PEHeaderData_t() { }

		// Parsing data out of this image's buffer.
		PEHeaderData_t(std::uint8_t* m_ImageBuffer, std::size_t m_ImageSize);

		// Parsing data out of this image's process.
		PEHeaderData_t(Process_t& m_Process, DWORD m_dCustomBaseAddress = NULL);

	public:

		// Helper function to get DOS header of PE image.
		PIMAGE_DOS_HEADER GetDOSHeader();

		// Helper function to get NT headers of PE image.
		PIMAGE_NT_HEADERS GetNTHeader();

		// Helper function to get section data of PE image.
		std::vector<SectionData_t> GetSectionData();

		// Helper function to get exported functions' data of PE image.
		std::vector<ExportData_t> GetExportData();

		// Helper function to get imported functions' data of PE image.
		std::vector<ImportData_t> GetImportData();

	};

	// PE Image utility helpers
	class ImageFile_t
	{
		PEHeaderData_t m_PEHeaderData = { };
	public:

		// Used for parsing PE's from file.
		ImageFile_t(std::string m_szImagePath);

		// Used for parsing PE's from memory.
		ImageFile_t(std::uint8_t* m_ImageBuffer, std::size_t m_nImageSize);

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

	// TODO:
	class Module_t
	{
		DWORD m_dModuleBaseAddress = NULL;
		DWORD m_dModuleSize = NULL;
		ByteArray_t m_ModuleData = { };

	public:
		// Default ctor
		Module_t() { }

		// Setup module in process by (non-case sensitive) name. 
		Module_t(chdr::Process_t& m_Process, const char *m_szModuleName);

		// Setup module in process by address in process. (plz pass correct data here :D)
		Module_t(chdr::Process_t& m_Process, DWORD m_dModuleBaseAddress, DWORD m_dModuleSize);

		// Ease of use for building constructors.
		void SetupModule_Internal(chdr::Process_t& m_Process);
	public:

		// Ensure we found the target module in memory.
		bool IsValid();
	};

	class Thread_t
	{
		// Basic thread information.
		DWORD m_dThreadID = 0;
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
		Thread_t(DWORD m_dThreadID);

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
		std::string GetOwningModule(chdr::Process_t &m_Process, DWORD m_dStartAddress);

		// Ensure we found a HANDLE to the target thread.
		bool IsValid();

		// Is the target thread suspended?
		bool IsSuspended();

		// Did we suspend the target thread ourselves?
		bool IsManuallySuspended();

		// Get's the start address of a target thread.
		DWORD GetStartAddress();
	};

	// Process utility helpers
	class Process_t
	{
	public:
		// Default ctor
		Process_t() { }

		// Get target proces by name.
		Process_t(const wchar_t* m_wszProcessName, DWORD m_dDesiredAccess = NULL);

		// Get target proces by PID.
		Process_t(DWORD m_nProcessID, DWORD m_dDesiredAccess = NULL);

		// Get target proces by HANDLE.
		Process_t(HANDLE m_hProcessHandle);

		// Default dtor
		~Process_t();

		enum class eManualMapInjectionFlags
		{
			INJECTION_NONE = (0 << 0),
			INJECTION_MODE_THREADHIJACK = (1 << 1),
			INJECTION_MODE_CREATEREMOTETHREAD = (1 << 2),
			INJECTION_EXTRA_WIPEPEHEADERS = (1 << 3),
			INJECTION_EXTRA_WIPEGARBAGESECTIONS = (1 << 4),
			INJECTION_MAXIMUM = INJECTION_EXTRA_WIPEGARBAGESECTIONS + 1
		};

		enum class eProcessArchitecture
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
		DWORD  m_nTargetProcessID = 0;

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

		typedef NTSTATUS(__stdcall* NtSuspendProcess_fn)(HANDLE);
		typedef NTSTATUS(__stdcall* NtResumeProcess_fn)(HANDLE);

		// Relevant information pertaining a target thread.
		struct ThreadInformation_t
		{
			DWORD		m_dThreadID = 0;
			DWORD		m_dThreadStartAddress = 0;
			bool		m_bIsThreadSuspended = false;
		//	Thread_t    m_Thread = { };		// For manipulating this thread.
		};

		// Relevant information pertaining a target module.
		struct ModuleInformation_t
		{
			std::string m_szModuleName = "";
			std::string m_szModulePath = "";
			DWORD		m_dModuleSize = 0;
			DWORD		m_dModuleBaseAddress = 0;
		//	Module_t    m_Module = { };		// For manipulating this module.
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
		DWORD GetBaseAddress();

		// The process ID of the target process. (lol)
		DWORD GetProcessID();

		// Ensure we found a HANDLE to the target process.
		bool IsValid();

		// Is target process 32-bit running on 64-bit OS?
		bool IsWow64();

		// Did we suspend the target process ourselves?
		bool IsManuallySuspended();

		// Is the target process suspended?
		bool IsSuspended();

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
		T Read(LPCVOID m_ReadAddress);

		// ReadProcessMemory implementation - allows byte arrays.

		template <typename S>
		void Read(LPCVOID m_ReadAddress, S &m_pBuffer, std::size_t m_nBufferSize);

		// WriteProcessMemory implementation.
		template<typename S>
		std::size_t Write(LPVOID m_WriteAddress, const S& m_WriteValue);

		// WriteProcessMemory implementation.
		template<typename S>
		std::size_t Write(LPVOID m_WriteAddress, const S& m_WriteValue, std::size_t m_WriteSize);

		// VirtualAllocEx implementation.
		LPVOID Allocate(std::size_t m_AllocationSize, DWORD m_dProtectionType);

		// VirtualFreeEx implementation.
		BOOL Free(LPVOID m_FreeAddress);

		// VirtualQueryEx implementation.
		std::size_t Query(LPCVOID m_QueryAddress, MEMORY_BASIC_INFORMATION* m_MemoryInformation);

		// _CreateRemoteThread implementation.
		HANDLE _CreateRemoteThread(LPVOID m_lpStartAddress, LPVOID m_lpParameter);
	};


	namespace misc
	{
		DWORD RvaToOffset(PIMAGE_NT_HEADERS m_pNTHeaders, DWORD Rva);
	}
}
