#pragma once

#include <Windows.h>
#include <vector>
#include <winnt.h>
#include <TlHelp32.h>
#include <fstream>
#include <comdef.h> 
#include <functional>
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
#define CH_LOG(s, ...) { std::printf("[!] "); std::printf(XOR(s), __VA_ARGS__); std::printf("\n"); }
#define CH_ASSERT(x, b, s, ...) if (!(b)) {  CH_LOG(s, __VA_ARGS__) if constexpr (x) return;  }
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
	class Address_t;

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
		};

		struct DebugData_t
		{
			std::string         m_szPDBPath = "";
			std::string		    m_szGUIDSignature = "";
			std::uint32_t		m_Age = 0u;
			std::uint32_t		m_CVSignature = 0u;
		};

		// Only for PDB7.0 format!
		struct CV_INFO_PDB70 
		{
			DWORD	CvSignature;
			GUID	Signature;
			DWORD	Age;
			BYTE	PdbFileName[MAX_PATH];
		};

		// For caching desired data.
		std::vector<SectionData_t>          m_SectionData = { };
		std::map<std::string, ExportData_t> m_ExportData = { };
		std::map<std::string, ImportData_t>           m_ImportData = { };
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
		std::map<std::string, ImportData_t> GetImportData();

		// Helper function to get debug directories' data of PE image.
		DebugData_t GetDebugData();

		// Convert relative virtual address to file offset.
		std::uint32_t RvaToOffset(std::uint32_t m_nRva);

		// Convert file offset to relative virtual address.
		std::uint32_t OffsetToRva(std::uint32_t m_nOffset);

		// Get certain section by address in memory.
		SectionData_t GetSectionByAddress(std::uint32_t m_nAddress);
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

		// Helper function to find some bytes in the module data.
		Address_t FindIDASignature(std::string_view m_szSignature);
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

		// Get context of this thread.
		CONTEXT GetThreadCTX();

		// Set context of this thread.
		void SetThreadCTX(CONTEXT m_Context);

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
			INJECTION_EXTRA_CUSTOMARGUMENTS = (1 << 3),
			INJECTION_EXTRA_WIPEPEHEADERS = (1 << 4),
			INJECTION_EXTRA_WIPEENTRYPOINT = (1 << 5),
			INJECTION_EXTRA_WIPEGARBAGESECTIONS = (1 << 6),
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
			std::uint32_t		m_nThreadID = 0;
			std::uint32_t		m_nThreadStartAddress = 0;
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

		struct AllocatedMemoryData_t
		{
			std::uintptr_t m_AllocatedAddress = 0u;
			std::size_t m_nAllocatedSize = 0u;
		};

		// Caching all loaded modules in target process.
		std::vector<Process_t::ModuleInformation_t> m_EnumeratedModulesCached = {};

		// Track allocated memory (removed on ::VirtualFreeEx calls).
		std::map<std::uintptr_t, std::size_t> m_AllocatedMemoryTracker;

		// Keep track of modules already initialized.
		std::unordered_map<const char*, Module_t> m_AllocatedModules;

		bool m_bHasCachedProcessesModules = false;

		// Get architecture of target process. 
		eProcessArchitecture GetProcessArchitecture_Internal();

		// Get name of target process.
		std::string GetProcessName_Internal();

		// Get filesystem path of target process.
		std::string GetProcessPath_Internal();

		// Internal manual map function.
		bool ManualMapInject_Internal(std::uint8_t* m_ImageBuffer,  std::int32_t m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);
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
		bool ManualMapInject(const char* m_szDLLPath, std::int32_t m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);

		// Manual map injection from module in memory.
		bool ManualMapInject(std::uint8_t* m_ImageBuffer, std::int32_t m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);

		// Manual map injection from ImageFile_t.
		bool ManualMapInject(ImageFile_t& m_ImageFile, std::int32_t m_eInjectionFlags = eManualMapInjectionFlags::INJECTION_NONE);

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

		// Get desired export address by name.
		std::uintptr_t GetRemoteProcAddress(const char* m_szModuleName, const char* m_szExportName);

		// ReadProcessMemory implementation.
		template <class T> T Read(std::uintptr_t m_ReadAddress) 
		{
			T m_pOutputRead;
			ReadProcessMemory(this->m_hTargetProcessHandle, (LPCVOID)m_ReadAddress, &m_pOutputRead, sizeof(T), nullptr);
			return m_pOutputRead;
		}

		// ReadProcessMemory implementation - allows byte arrays.
		template <typename S> std::size_t Read(std::uintptr_t m_ReadAddress, S m_pBuffer, std::size_t m_nBufferSize) 
		{
			SIZE_T m_nBytesRead = 0u;
			ReadProcessMemory(this->m_hTargetProcessHandle, (LPCVOID)m_ReadAddress, m_pBuffer, m_nBufferSize, &m_nBytesRead);
			return m_nBytesRead;
		}

		// WriteProcessMemory implementation.
		template <typename S> std::size_t Write(std::uintptr_t m_WriteAddress, S m_WriteValue) 
		{
			SIZE_T lpNumberOfBytesWritten = NULL; // Fuck you MSVC.
			WriteProcessMemory(this->m_hTargetProcessHandle, (LPVOID)m_WriteAddress, (LPCVOID)m_WriteValue, sizeof(S), &lpNumberOfBytesWritten);
			return lpNumberOfBytesWritten;
		}

		// WriteProcessMemory implementation.
		template <typename S> std::size_t Write(std::uintptr_t m_WriteAddress, S m_WriteValue, std::size_t m_WriteSize) 
		{
			SIZE_T lpNumberOfBytesWritten = NULL; // Fuck you MSVC.
			WriteProcessMemory(this->m_hTargetProcessHandle, (LPVOID)m_WriteAddress, (LPCVOID)m_WriteValue, m_WriteSize, &lpNumberOfBytesWritten);
			return lpNumberOfBytesWritten;
		}

		// VirtualAllocEx implementation.
		std::uintptr_t Allocate(std::size_t m_AllocationSize, DWORD m_dProtectionType, bool m_bShouldTrack = true);

		// VirtualFreeEx implementation.
		bool Free(std::uintptr_t m_FreeAddress);

		// VirtualQueryEx implementation.
		std::size_t Query(LPCVOID m_QueryAddress, MEMORY_BASIC_INFORMATION* m_MemoryInformation);

		// _CreateRemoteThread implementation.
		std::int32_t _CreateRemoteThread(LPVOID m_lpStartAddress, LPVOID m_lpParameter);

		// GetModule implementation.
		Module_t& GetModule(const char* m_szModuleName, std::int32_t m_ParseType = PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_ALL);
	};

	// Address helper class
	class Address_t 
	{
	private:
		uintptr_t m_dAddress = NULL;
	public:
		Address_t() { };

		// Templated ctor.
		template <class T> Address_t(const T m_Address) 
		{
			m_dAddress = CH_R_CAST<std::uintptr_t>(m_Address);
		}

		// Operator.
		bool operator==(const Address_t& m_Address) const 
		{
			return m_dAddress == m_Address.Get<uintptr_t>();
		}

		// Operator.
		bool operator!=(const Address_t& m_Address) const 
		{
			return m_dAddress != m_Address.Get<uintptr_t>();
		}

		// Getter.
		template <class T> T Get() const 
		{
			return m_dAddress ? T(m_dAddress) : T();
		}

		// Dereferences one time and casts.
		template <class T> T& To() 
		{
			return *CH_R_CAST<T*>(m_dAddress);
		}

		// Offset current address. 
		template <class T> T Offset(std::ptrdiff_t m_Offset) 
		{
			return m_dAddress ? CH_R_CAST<T>(m_dAddress + m_Offset) : T();
		}

		// Dereferences address X times.
		template <class T> T Deref(std::size_t m_nCount) 
		{
			if (!m_dAddress) {
				CH_LOG("Invalid address called @Address_t::Deref.");
				return T();
			}

			std::uintptr_t m_Address = m_dAddress;
			while (m_nCount--)
				if (m_Address)
					m_Address = *CH_R_CAST<uintptr_t*>(m_Address);

			return CH_R_CAST<T>(m_Address);
		}

		// Follows relative jmp. - E8 
		template <class T> T Relative(std::ptrdiff_t m_Offset) 
		{
			if (!m_dAddress) {
				CH_LOG("Invalid address called @Address_t::Relative.");
				return T();
			}

			const std::uintptr_t m_Address = m_dAddress + m_Offset;
			const std::ptrdiff_t m_RelativeOffset = *CH_R_CAST<std::ptrdiff_t*>(m_Address);
			if (!m_RelativeOffset) {
				CH_LOG("Invalid relative offset @Address_t::Relative.");
				return T();
			}

			return CH_R_CAST<T>(m_Address + m_RelativeOffset + sizeof(uint32_t));
		}
	};

	namespace math
	{
		class Color
		{
		public:
			float r = 0.0f;
			float g = 0.0f;
			float b = 0.0f;
			float a = 255.0f;
		public:
			Color() : r{}, g{}, b{}, a{} { }
			Color(float _r, float _g, float _b, float _a) : r{ _r }, g{ _g }, b{ _b }, a{ _a } { }

			bool operator==(const Color& v) const { return v.r == this->r && v.g == this->g && v.b == this->b && v.a == this->a; }
			bool operator!=(const Color& v) const { return v.r != this->r || v.g != this->g || v.b != this->b || v.a != this->a; }

			void Reset(float _r = 0.0f, float _g = 0.0f, float _b = 0.0f, float _a = 0.0f) { this->r = _r; this->g = _g; this->b = _b; this->a = _a; }
		};

		class Vector2D
		{
		public:
			int x = 0;
			int y = 0;
		public:
			Vector2D() : x{}, y{} { }
			Vector2D(int _x, int _y) : x{ _x }, y{ _y } { }

			bool operator==(const Vector2D& v) const { return v.x == this->x && v.y == this->y; }
			bool operator!=(const Vector2D& v) const { return v.x != this->x || v.y != this->y; }

			// TODO: more arithmetic operators, too lazy to type it all out rn.
			Vector2D operator-(const Vector2D& v) const { return { this->x - v.x, this->y - v.y}; }
			Vector2D operator+(const Vector2D& v) const { return { this->x + v.x, this->y + v.y }; }
			Vector2D operator-=(const Vector2D& v) { return { this->x -= v.x, this->y -= v.y }; }
			Vector2D operator+=(const Vector2D& v) { return { this->x += v.x, this->y += v.y }; }
			Vector2D operator/=(const Vector2D& v) { return { this->x /= v.x, this->y /= v.y }; }
			Vector2D operator*=(const Vector2D& v) { return { this->x *= v.x, this->y *= v.y }; }

			void Reset(int _x = 0, int _y = 0) { this->x = _x; this->y = _y; }
		};
		
		class Vector3D
		{
		public:
			float x = 0.0f;
			float y = 0.0f;
			float z = 0.0f;
		public:
			Vector3D() : x{}, y{}, z{} { }
			Vector3D(float _x, float _y, float _z) : x{ _x }, y{ _y }, z{ _z } { }

			bool operator==(const Vector3D& v) const { return v.x == this->x && v.y == this->y && v.z == this->z; }
			bool operator!=(const Vector3D& v) const { return v.x != this->x || v.y != this->y || v.z != this->z; }

			// TODO: more arithmetic operators, too lazy to type it all out rn.
			Vector3D operator-(const Vector3D& v) const { return { this->x - v.x, this->y - v.y, this->z - v.z }; }
			Vector3D operator+(const Vector3D& v) const { return { this->x + v.x, this->y + v.y,  this->z + v.z }; }
			Vector3D operator-=(const Vector3D& v) { return { this->x -= v.x, this->y -= v.y, this->z -= v.z }; }
			Vector3D operator+=(const Vector3D& v) { return { this->x += v.x, this->y += v.y, this->z += v.z }; }
			Vector3D operator/=(const Vector3D& v) { return { this->x /= v.x, this->y /= v.y, this->z /= v.z  }; }
			Vector3D operator*=(const Vector3D& v) { return { this->x *= v.x, this->y *= v.y, this->z *= v.z }; }

			bool IsValid() const { return this->x != 0.0f && this->y != 0.0f && this->z != 0.0f; }
			void Reset(float _x = 0.0f, float _y = 0.0f, float _z = 0.0f) { this->x = _x; this->y = _y; this->z = _z; }

			float Length() const { return std::sqrtf(this->LengthSqr()); }
			float LengthSqr() const { return (this->x * this->x) + (this->y * this->y) + (this->z * this->z);  }
			float Length2DSqr() const { return (this->x * this->x) + (this->y * this->y); }
			float Length2D() const { return std::sqrtf(this->x * this->x + this->y * this->y); }
			float Distance(const Vector3D& v) const { Vector3D m_vecDelta = { this->x - v.x, this->y - v.y, this->z - v.z }; return m_vecDelta.Length2D();  }
		};
	}

	namespace misc
	{
#define XOR(str) []() { constexpr auto s = chdr::misc::StringEncryption<sizeof(str) / sizeof(str[0])>(str); return s.Decrypted(); }()
		constexpr std::size_t COMPILETIME_SEED = (__TIME__[3] - '0') * 10 + (__TIME__[4] - '0'); // Temp, make this more unique lmfao.
		 
		template <std::size_t nStringSize>
		class StringEncryption 
		{ 
			std::int8_t m_Xored[nStringSize][2] = { 0 };
		public:
			constexpr StringEncryption(const char* m_szToEncrypt) {
				for (std::size_t i = 0u; i < nStringSize; i++) {
					this->m_Xored[i][0] = CH_S_CAST<std::int8_t>(COMPILETIME_SEED * i);
					this->m_Xored[i][1] = m_szToEncrypt[i] ^ this->m_Xored[i][0];
				}
			}

			const char* Decrypted() const {
				static char m_DecryptedData[nStringSize];
				m_DecryptedData[0] = this->m_Xored[0][1];

				for (std::size_t i = 1u; m_DecryptedData[i - 1u]; ++i) 
					m_DecryptedData[i] = this->m_Xored[i][1] ^ this->m_Xored[i][0];

				return m_DecryptedData;
			}
		};

#define CREATE_XORED_POINTER(type, ptr) chdr::misc::PointerEncryption<type>(ptr);

#pragma optimize( "", off )
		template <class T>
		class PointerEncryption
		{
			std::uintptr_t m_Xored[2] = { 0 };
		public:
			PointerEncryption(T* m_pToEncrypt) {
				this->m_Xored[0] = CH_R_CAST<std::uintptr_t>(m_pToEncrypt) ^ CH_R_CAST<std::uintptr_t>(m_pToEncrypt);
				this->m_Xored[1] = this->m_Xored[0] ^ (CH_R_CAST<std::uintptr_t>(m_pToEncrypt) + (COMPILETIME_SEED * 0xB00B1E));
			}

			__forceinline T* operator->() { return this->Decrypted(); }
			__forceinline bool IsValid() const { return CH_R_CAST<std::uintptr_t>(this->Decrypted()) != NULL; }
			__forceinline T* Decrypted() const { return CH_R_CAST<T*>((this->m_Xored[0] ^ this->m_Xored[1]) - (COMPILETIME_SEED * 0xB00B1E)); }
		};
#pragma optimize( "", on )

#define ADD_SCOPE_HANDLER(a, b) chdr::misc::QueuedScopeHandler ScopeHandler(a, b);
#define PUSH_SCOPE_HANDLER(a, b) ScopeHandler.AddToTail(a, b);

		// This is fine for now, but because the template is class-specific, you can't currently queue more than one type.
		template <typename Callback, typename... Parameters>
		class QueuedScopeHandler
		{
			std::vector<std::pair<Callback, Parameters...>> m_QueuedCalls;
		public:
			QueuedScopeHandler(Callback call, Parameters ...param) { this->AddToTail( call, param...); }
			~QueuedScopeHandler() { for (const auto& QueuedCalls : this->m_QueuedCalls) std::invoke(QueuedCalls.first, QueuedCalls.second); }

			void AddToTail(Callback call, Parameters ...param) { this->m_QueuedCalls.push_back({ call, param... }); }
		};
	}
}