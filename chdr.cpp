#include "chdr.h"

// Process_t definitions and functions.
namespace chdr
{
	// Get target proces by name.
	Process_t::Process_t(const wchar_t* m_wszProcessName, DWORD m_dDesiredAccess)
	{
		HANDLE m_hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);

		while (Process32NextW(m_hSnapShot, &entry))
		{
			if (wcscmp(entry.szExeFile, m_wszProcessName) != 0)
				continue;

			this->m_nTargetProcessID = entry.th32ProcessID;
			this->m_hTargetProcessHandle = OpenProcess(m_dDesiredAccess != NULL ? m_dDesiredAccess : PROCESS_ALL_ACCESS, false, this->m_nTargetProcessID);
			break;
		}

		CloseHandle(m_hSnapShot);

		CH_ASSERT(true, this->m_hTargetProcessHandle && this->m_hTargetProcessHandle != INVALID_HANDLE_VALUE,
			"Couldn't obtain valid HANDLE for process %ws", m_wszProcessName);

		this->m_bShouldFreeHandleAtDestructor = this->m_hTargetProcessHandle && this->m_hTargetProcessHandle != INVALID_HANDLE_VALUE;
		this->m_eProcessArchitecture = this->GetProcessArchitecture_Internal();

		this->m_szProcessPath = this->GetProcessPath_Internal();
		this->m_szProcessName = this->GetProcessName_Internal();

		this->m_PEHeaderData = PEHeaderData_t(*this);
	}

	// Get target proces by PID.
	Process_t::Process_t(DWORD m_nProcessID, DWORD m_dDesiredAccess)
	{
		this->m_nTargetProcessID = m_nProcessID;
		this->m_hTargetProcessHandle = OpenProcess(m_dDesiredAccess != NULL ? m_dDesiredAccess : PROCESS_ALL_ACCESS, false, this->m_nTargetProcessID);

		CH_ASSERT(true, this->m_hTargetProcessHandle && this->m_hTargetProcessHandle != INVALID_HANDLE_VALUE,
			"Couldn't obtain valid HANDLE for PID %i", m_nProcessID);

		this->m_bShouldFreeHandleAtDestructor = this->m_hTargetProcessHandle && this->m_hTargetProcessHandle != INVALID_HANDLE_VALUE;
		this->m_eProcessArchitecture = this->GetProcessArchitecture_Internal();

		this->m_szProcessPath = this->GetProcessPath_Internal();
		this->m_szProcessName = this->GetProcessName_Internal();

		this->m_PEHeaderData = PEHeaderData_t(*this);
	}

	// Get target proces by HANDLE.
	Process_t::Process_t(HANDLE m_hProcessHandle)
	{
		this->m_hTargetProcessHandle = m_hProcessHandle;
		this->m_nTargetProcessID = GetProcessId(this->m_hTargetProcessHandle);

		this->m_bShouldFreeHandleAtDestructor = this->m_hTargetProcessHandle && this->m_hTargetProcessHandle != INVALID_HANDLE_VALUE;
		this->m_eProcessArchitecture = this->GetProcessArchitecture_Internal();

		this->m_szProcessPath = this->GetProcessPath_Internal();
		this->m_szProcessName = this->GetProcessName_Internal();

		this->m_PEHeaderData = PEHeaderData_t(*this);
	}

	// Default dtor
	Process_t::~Process_t()
	{
		// Not allowed to release this HANDLE, or was already released.
		CH_ASSERT(true,
			this->m_bShouldFreeHandleAtDestructor &&
			this->m_hTargetProcessHandle &&
			this->m_hTargetProcessHandle != INVALID_HANDLE_VALUE,
			"adawdasd");

		CloseHandle(m_hTargetProcessHandle);
	}

	// The process ID of the target process. (lol)
	DWORD Process_t::GetProcessID()
	{
		return this->m_nTargetProcessID;
	}

	// Ensure we found a HANDLE to the target process.
	bool Process_t::IsValid()
	{
		return this->m_hTargetProcessHandle && this->m_hTargetProcessHandle != INVALID_HANDLE_VALUE;
	}

	// Is this process 32-bit running on 64-bit OS?
	bool Process_t::IsWow64()
	{
		BOOL m_bIsWow64 = FALSE;
		IsWow64Process(this->m_hTargetProcessHandle, &m_bIsWow64);

		return m_bIsWow64;
	}

	// Get name of target process.
	std::string Process_t::GetProcessName_Internal()
	{
		TCHAR m_szProcessNameBuffer[MAX_PATH];
		GetModuleBaseName(this->m_hTargetProcessHandle, NULL, m_szProcessNameBuffer, MAX_PATH);

		// TCHAR->string
		_bstr_t m_szPreProcessName(m_szProcessNameBuffer);
		return std::string(m_szPreProcessName);
	}

	// The base address of the target process.
	DWORD Process_t::GetBaseAddress()
	{
		for (auto& CurrentModule : this->EnumerateModules(true))
		{
			if (strcmp(CurrentModule.m_szModuleName.c_str(), this->m_szProcessName.c_str()) != 0)
				continue;

			return CurrentModule.m_dModuleBaseAddress;
		}
		return NULL;
	}

	// Helper function to get name of target process.
	std::string Process_t::GetName()
	{
		return this->m_szProcessName;
	}

	// Get filesystem path of target process.
	std::string Process_t::GetProcessPath_Internal()
	{
		TCHAR m_szProcessPathBuffer[MAX_PATH];
		GetModuleFileNameEx(this->m_hTargetProcessHandle, NULL, m_szProcessPathBuffer, MAX_PATH);

		// TCHAR->string
		_bstr_t m_szPreProcessPath(m_szProcessPathBuffer);
		return std::string(m_szPreProcessPath);
	}

	// Helper function to get filesystem path of target process.
	std::string Process_t::GetPath()
	{
		return this->m_szProcessPath;
	}

	// Get architecture of target process.
	Process_t::eProcessArchitecture Process_t::GetProcessArchitecture_Internal()
	{
		SYSTEM_INFO m_SystemInformation = { 0 };
		GetNativeSystemInfo(&m_SystemInformation);

		// Native x86, or WOW64 process.
		if (m_SystemInformation.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL || this->IsWow64())
			return eProcessArchitecture::ARCHITECTURE_x86;

		// Everything else should be native x64.
		return eProcessArchitecture::ARCHITECTURE_x64;
	}

	// Helper function to get architecture of target process. 
	Process_t::eProcessArchitecture Process_t::GetProcessArchitecture()
	{
		return this->m_eProcessArchitecture;
	}

	// Helper function to get PE header data of target process.
	PEHeaderData_t Process_t::GetPEHeaderData()
	{
		return this->m_PEHeaderData;
	}

	// Did we suspend the target process ourselves?
	bool Process_t::IsManuallySuspended()
	{
		return this->m_bIsProcessManuallySuspended;
	}

	// Is the target process suspended?
	bool Process_t::IsSuspended()
	{
		bool m_bIsProcessSuspended = true;

		// Traverse all threads, and ensure each is in a suspended state.
		for (auto& CurrentThread : this->EnumerateThreads())
		{
			if (!CurrentThread.m_bIsThreadSuspended)
			{
				m_bIsProcessSuspended = false; // Found a thread that's still alive, cache and exit loop.
				break;
			}
		}
		return m_bIsProcessSuspended;
	}

	// Is the target process running under a debugger?
	bool Process_t::IsBeingDebugged()
	{
		BOOL m_bHasRemoteDebugger = FALSE;
		CheckRemoteDebuggerPresent(this->m_hTargetProcessHandle, &m_bHasRemoteDebugger);

		if (m_bHasRemoteDebugger)
			return true;

		const PEB m_PEB = this->GetPEB();
		if (m_PEB.BeingDebugged)
			return true;

		return false;
	}

	// The PEB of the target process.
	PEB Process_t::GetPEB()
	{
		const HMODULE m_hNTDLL = GetModuleHandleA("ntdll.dll");
		if (!m_hNTDLL)
		{
			CH_LOG("Couldn't find loaded module ntdll!");
			return {};
		}

		NtQueryInformationProcess_fn NtQueryInformationProcess = CH_R_CAST<NtQueryInformationProcess_fn>(GetProcAddress(m_hNTDLL, "NtQueryInformationProcess"));
		PROCESS_BASIC_INFORMATION m_ProcessBasicInformation;

		// Get address where PEB resides in this target process.
		if (NtQueryInformationProcess(this->m_hTargetProcessHandle, PROCESSINFOCLASS::ProcessBasicInformation,
			&m_ProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), nullptr) != 0x00000000/*STATUS_SUCCESS*/)
		{
			CH_LOG("NtQueryInformationProcess failure!");
			return {};
		}

		// Read PEB from found base address.
		const PEB m_PEB = this->Read<PEB>(CH_R_CAST<LPCVOID>(m_ProcessBasicInformation.PebBaseAddress));
		return m_PEB;
	}

	// Internal manual map function.
	bool Process_t::ManualMapInject_Internal(std::uint8_t* m_ImageBuffer, std::size_t m_nImageSize, eManualMapInjectionFlags m_eInjectionFlags)
	{
		// Grab DOS header.
		const PIMAGE_DOS_HEADER m_pDosHeaders = CH_R_CAST<PIMAGE_DOS_HEADER>(m_ImageBuffer);
		if (m_pDosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
		{
			CH_LOG("Couldn't find IMAGE_DOS_SIGNATURE for m_ImageBuffer");
			return false;
		}

		// Grab NT header.
		const PIMAGE_NT_HEADERS m_pNTHeaders = CH_R_CAST<PIMAGE_NT_HEADERS>(m_ImageBuffer + m_pDosHeaders->e_lfanew);
		if (m_pNTHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			CH_LOG("Couldn't find IMAGE_NT_SIGNATURE for m_ImageBuffer");
			return false;
		}

		// Address our module will be in context of target process.
		const std::uintptr_t m_TargetBaseAddress = CH_R_CAST<std::uintptr_t>(this->Allocate(m_pNTHeaders->OptionalHeader.SizeOfImage/*0x1000*/, PAGE_EXECUTE_READWRITE));

		// Copy over PE Header to target process.
		this->Write(CH_R_CAST<LPVOID>(m_TargetBaseAddress), m_ImageBuffer, m_pNTHeaders->OptionalHeader.SizeOfImage/*0x1000*/);

		// Copy over needed sections to target process.
		PIMAGE_SECTION_HEADER m_pSectionHeaders = IMAGE_FIRST_SECTION(m_pNTHeaders);
		for (UINT i = 0; i != m_pNTHeaders->FileHeader.NumberOfSections; ++i, ++m_pSectionHeaders)
		{
			if (!this->Write(CH_R_CAST<LPVOID>(m_TargetBaseAddress + m_pSectionHeaders->VirtualAddress),
				m_ImageBuffer + m_pSectionHeaders->PointerToRawData, m_pSectionHeaders->SizeOfRawData))
			{
				CH_LOG("Couldn't copy over section %s to target process.", CH_R_CAST<char*>(m_pSectionHeaders->Name));
				return false;
			}
		}

		// TODO:
		return true;
	}

	// Manual map injection from module on disk.
	bool Process_t::ManualMapInject(const char* m_szDLLPath, eManualMapInjectionFlags m_eInjectionFlags)
	{
		ByteArray_t m_FileImageBuffer = { 0 };

		// Fill local image buffer from file on disk.
		std::ifstream m_fFile(m_szDLLPath, std::ios::binary);
		(&m_FileImageBuffer)->assign((std::istreambuf_iterator<char>(m_fFile)), std::istreambuf_iterator<char>());
		m_fFile.close();

		std::uint8_t* m_ImageBuffer = m_FileImageBuffer.data();
		const std::size_t m_nImageSize = m_FileImageBuffer.size();

		if (!m_nImageSize)
		{
			CH_LOG("Couldn't parse desired m_ImageBuffer to manual map.");
			return false;
		}

		return ManualMapInject_Internal(m_ImageBuffer, m_nImageSize, m_eInjectionFlags);
	}

	// Manual map injection from module in memory.
	bool Process_t::ManualMapInject(std::uint8_t* m_ImageBuffer, std::size_t m_nImageSize, eManualMapInjectionFlags m_eInjectionFlags)
	{
		if (!m_nImageSize)
		{
			CH_LOG("Couldn't parse desired m_ImageBuffer to manual map.");
			return false;
		}

		return ManualMapInject_Internal(m_ImageBuffer, m_nImageSize);
	}

	// Manual map injection from ImageFile_t.
	bool Process_t::ManualMapInject(ImageFile_t& m_ImageFile, eManualMapInjectionFlags m_eInjectionFlags)
	{
		if (!m_ImageFile.m_ImageBuffer.size())
		{
			CH_LOG("Couldn't parse desired ImageFile_t to manual map.");
			return false;
		}

		const std::uint8_t* m_TrueImageBuffer = m_ImageFile.m_ImageBuffer.data();
	}

	// LoadLibrary injection from module on disk.
	bool Process_t::LoadLibraryInject(const char* m_szDLLPath)
	{
		// Allocate memory in target process.
		LPVOID m_AllocatedMemory = this->Allocate(strlen(m_szDLLPath), PAGE_READWRITE);
		if (!m_AllocatedMemory)
		{
			CH_LOG("Couldn't allocate memory to target process. Error code was #%i", GetLastError());
			return false;
		}

		// Write string name for our module in previously allocated space.
		const std::size_t m_nWrittenBytes = this->Write(m_AllocatedMemory, CH_C_CAST<char*>(m_szDLLPath));
		if (!m_nWrittenBytes)
		{
			CH_LOG("Couldn't write module name to target process. Error code was #%i", GetLastError());
			return false;
		}

		// Load DLL by invoking LoadLibrary(m_szDLLPath) in a target process
		const HANDLE m_hRemoteThread = this->_CreateRemoteThread(CH_R_CAST<LPVOID>(LoadLibraryA), m_AllocatedMemory);
		if (!m_hRemoteThread || m_hRemoteThread == INVALID_HANDLE_VALUE)
		{
			CH_LOG("Couldn't create remote thread to target process. Error code was #%i", GetLastError());
			return false;
		}

		return true;
	}

	// Traverse and cache data about all threads in a target process.
	std::vector<Process_t::ThreadInformation_t> Process_t::EnumerateThreads()
	{
		std::vector<Process_t::ThreadInformation_t> m_EnumeratedThreads = {};

		const HMODULE m_hNTDLL = GetModuleHandleA("ntdll.dll");
		if (!m_hNTDLL)
		{
			CH_LOG("Couldn't find loaded module ntdll!");
			return {};
		}

		HANDLE m_hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, this->m_nTargetProcessID);
		Thread_t::NtQueryInformationThread_fn NtQueryInformationThread = CH_R_CAST<Thread_t::NtQueryInformationThread_fn>(GetProcAddress(m_hNTDLL, "NtQueryInformationThread"));

		THREADENTRY32 mEntry = { 0 };
		mEntry.dwSize = sizeof(mEntry);

		if (!Thread32First(m_hSnapShot, &mEntry))
			return {};

		while (Thread32Next(m_hSnapShot, &mEntry))
		{
			// Ensure our target process owns this thread.
			if (mEntry.th32OwnerProcessID != this->m_nTargetProcessID)
				continue;

			// Open handle to this specific thread.
			HANDLE m_hThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, mEntry.th32ThreadID);
			if (!m_hThreadHandle || m_hThreadHandle == INVALID_HANDLE_VALUE)
				continue;

			DWORD m_dThreadStartAddress = 0;
			if (NtQueryInformationThread(m_hThreadHandle,
				Thread_t::THREADINFOCLASS::ThreadQuerySetWin32StartAddress,
				&m_dThreadStartAddress,
				this->m_eProcessArchitecture == eProcessArchitecture::ARCHITECTURE_x64 ? sizeof(DWORD) * 2 : sizeof(DWORD),
				nullptr) != 0x00000000/*STATUS_SUCCESS*/)
			{
				CloseHandle(m_hThreadHandle);
				continue;
			}

			const bool m_bIsThreadSuspended = WaitForSingleObject(m_hThreadHandle, 0) == WAIT_ABANDONED;

			CloseHandle(m_hThreadHandle);

			m_EnumeratedThreads.push_back(
				{ mEntry.th32ThreadID, m_dThreadStartAddress, m_bIsThreadSuspended/*, Thread_t(mEntry.th32ThreadID)*/ }
			);
		}

		CloseHandle(m_hSnapShot);

		return m_EnumeratedThreads;
	}



	// Traverse and cache data about all loaded modules in a target process.
	std::vector<Process_t::ModuleInformation_t> Process_t::EnumerateModules(bool m_bUseCachedData)
	{
		// To take up less processing power, or if you know nothing will be loaded into the target process unexpectedly.
		if (m_bUseCachedData && this->m_bHasCachedProcessesModules)
		{
			if (!this->m_EnumeratedModulesCached.empty())
				return this->m_EnumeratedModulesCached;
		}

		// Wipe any previously cached data.
		this->m_EnumeratedModulesCached.clear();

		HANDLE m_hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->m_nTargetProcessID);

		MODULEENTRY32 mEntry = { 0 };
		mEntry.dwSize = sizeof(mEntry);

		while (Module32NextW(m_hSnapShot, &mEntry))
		{
			WCHAR m_wszModPath[MAX_PATH];
			if (!K32GetModuleFileNameExW(this->m_hTargetProcessHandle, mEntry.hModule, m_wszModPath, sizeof(m_wszModPath) / sizeof(WCHAR)))
				continue;

			// Convert wstring->string.
			_bstr_t m_bszPreModulePath(m_wszModPath);
			_bstr_t m_bszPreModuleName(mEntry.szModule);

			std::string m_szModulePath(m_bszPreModulePath);
			std::string m_szModuleName(m_bszPreModuleName);

			this->m_EnumeratedModulesCached.push_back(
				{ m_szModuleName, m_szModulePath, mEntry.modBaseSize, CH_R_CAST<DWORD>(mEntry.modBaseAddr)/*, Module_t(*this, (DWORD)mEntry.modBaseAddr, mEntry.modBaseSize)*/ }
			);
		}

		CloseHandle(m_hSnapShot);

		return this->m_EnumeratedModulesCached;
	}

	// Sets debug privileges of a target process.
	bool Process_t::SetDebugPrivilege(bool m_bShouldEnable)
	{
		HANDLE m_hToken;
		if (!OpenProcessToken(this->m_hTargetProcessHandle, TOKEN_ALL_ACCESS, &m_hToken))
			return false;

		LUID m_LUID;
		if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &m_LUID))
			return false;

		TOKEN_PRIVILEGES m_TokenPrivileges;
		m_TokenPrivileges.PrivilegeCount = 1;
		m_TokenPrivileges.Privileges[0].Luid = m_LUID;
		m_TokenPrivileges.Privileges[0].Attributes = m_bShouldEnable ? SE_PRIVILEGE_ENABLED : 0;

		if (!AdjustTokenPrivileges(m_hToken, false, &m_TokenPrivileges, sizeof(m_TokenPrivileges), NULL, NULL))
			return false;

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
			return false;

		CloseHandle(m_hToken);
	}

	// Suspend every thread in a target process.
	void Process_t::Suspend()
	{
		const HMODULE m_hNTDLL = GetModuleHandleA("ntdll.dll");
		CH_ASSERT(true, m_hNTDLL, "Couldn't find loaded module ntdll!");

		NtSuspendProcess_fn NtSuspendProcess = CH_R_CAST<NtSuspendProcess_fn>(GetProcAddress(m_hNTDLL, "NtSuspendProcess"));
		this->m_bIsProcessManuallySuspended = NtSuspendProcess(this->m_hTargetProcessHandle) == 0x00000000/*STATUS_SUCCESS*/;

		CH_ASSERT(false, this->m_bIsProcessManuallySuspended, "Failed to suspend process!");
	}

	// Resume every previously suspended thread in a target process.
	void Process_t::Resume()
	{
		// TODO: Is there any use case of resuming a suspended process (that WE didn't suspend??).
		CH_ASSERT(true, this->m_bIsProcessManuallySuspended, "Attempted to resume process that was never suspended!");

		const HMODULE m_hNTDLL = GetModuleHandleA("ntdll.dll");
		CH_ASSERT(true, m_hNTDLL, "Couldn't find loaded module ntdll!");

		NtResumeProcess_fn NtResumeProcess = CH_R_CAST<NtResumeProcess_fn>(GetProcAddress(m_hNTDLL, "NtResumeProcess"));

		this->m_bIsProcessManuallySuspended = NtResumeProcess(this->m_hTargetProcessHandle) != 0x00000000/*STATUS_SUCCESS*/;
		CH_ASSERT(false, this->m_bIsProcessManuallySuspended == false, "Failed to resume suspended process!");
	}

	// ReadProcessMemory implementation.
	template <class T>
	T Process_t::Read(LPCVOID m_ReadAddress)
	{
		T m_pOutputRead;
		if (!ReadProcessMemory(this->m_hTargetProcessHandle, m_ReadAddress, &m_pOutputRead, sizeof(T), NULL))
		{
			CH_LOG("Failed to read memory at addr 0x%X, with error code #%i.", m_ReadAddress, GetLastError());
		}

		return m_pOutputRead;
	}

	// ReadProcessMemory implementation - allows byte arrays.
	template <typename S>
	void Process_t::Read(LPCVOID m_ReadAddress, S& m_pBuffer, std::size_t m_nBufferSize)
	{
		if (!ReadProcessMemory(this->m_hTargetProcessHandle, m_ReadAddress, &m_pBuffer, m_nBufferSize, NULL))
		{
			CH_LOG("Failed to read memory at addr 0x%X, with error code #%d.", m_ReadAddress, GetLastError());
		}
	}

	// WriteProcessMemory implementation.
	template<typename S>
	std::size_t Process_t::Write(LPVOID m_WriteAddress, const S& m_WriteValue)
	{
		SIZE_T lpNumberOfBytesWritten = NULL; // Fuck you MSVC.
		if (!WriteProcessMemory(this->m_hTargetProcessHandle, m_WriteAddress, m_WriteValue, sizeof(S), &lpNumberOfBytesWritten))
		{
			CH_LOG("Failed to write memory at addr 0x%X, with error code #%d.", m_WriteAddress, GetLastError());
		}

		return lpNumberOfBytesWritten;
	}

	// WriteProcessMemory implementation.
	template<typename S>
	std::size_t Process_t::Write(LPVOID m_WriteAddress, const S& m_WriteValue, std::size_t m_WriteSize)
	{
		SIZE_T lpNumberOfBytesWritten = NULL; // Fuck you MSVC.
		if (!WriteProcessMemory(this->m_hTargetProcessHandle, m_WriteAddress, m_WriteValue, m_WriteSize, &lpNumberOfBytesWritten))
		{
			CH_LOG("Failed to write memory at addr 0x%X, with error code #%d.", m_WriteAddress, GetLastError());
		}

		return lpNumberOfBytesWritten;
	}

	// VirtualAllocEx implementation.
	LPVOID Process_t::Allocate(std::size_t m_AllocationSize, DWORD m_dProtectionType)
	{
		const LPVOID m_AllocatedMemory = VirtualAllocEx(this->m_hTargetProcessHandle, nullptr, m_AllocationSize, MEM_COMMIT | MEM_RESERVE, m_dProtectionType);
		if (!m_AllocatedMemory)
		{
			CH_LOG("Failed to allocate memory with error code #%i.", GetLastError());
		}

		return m_AllocatedMemory;
	}

	// VirtualFreeEx implementation.
	BOOL Process_t::Free(LPVOID m_FreeAddress)
	{
		const BOOL m_bDidSucceed = VirtualFreeEx(this->m_hTargetProcessHandle, m_FreeAddress, NULL, MEM_RELEASE);
		if (!m_bDidSucceed)
		{
			CH_LOG("Failed to free memory with error code #%i.", GetLastError());
		}

		return m_bDidSucceed;
	}

	// VirtualQueryEx implementation.
	std::size_t Process_t::Query(LPCVOID m_QueryAddress, MEMORY_BASIC_INFORMATION* m_MemoryInformation)
	{
		return VirtualQueryEx(this->m_hTargetProcessHandle, m_QueryAddress, m_MemoryInformation, sizeof(MEMORY_BASIC_INFORMATION));
	}

	// CreateRemoteThread implementation.
	HANDLE Process_t::_CreateRemoteThread(LPVOID m_lpStartAddress, LPVOID m_lpParameter)
	{
		return CreateRemoteThread(this->m_hTargetProcessHandle,
			NULL,
			NULL,
			CH_R_CAST<LPTHREAD_START_ROUTINE>(m_lpStartAddress),
			m_lpParameter,
			NULL,
			NULL
		);
	}
}

// PEHeaderData_t definitions and functions.
namespace chdr
{
	// Parsing data out of this image's buffer.
	PEHeaderData_t::PEHeaderData_t(std::uint8_t* m_ImageBuffer, std::size_t m_ImageSize)
	{
		CH_ASSERT(true, m_ImageBuffer, "Failed to read PE image.");

		this->m_pDOSHeaders = CH_R_CAST<PIMAGE_DOS_HEADER>(m_ImageBuffer);
		this->m_pNTHeaders = CH_R_CAST<PIMAGE_NT_HEADERS>(CH_R_CAST<ULONG_PTR>(m_ImageBuffer) + this->m_pDOSHeaders->e_lfanew);

		// Ensure image PE headers was valid.
		CH_ASSERT(true, this->IsValid(), "Couldn't find MZ&NT header.");

		PIMAGE_SECTION_HEADER m_pSectionHeaders = IMAGE_FIRST_SECTION(this->m_pNTHeaders);
		for (UINT i = 0; i != m_pNTHeaders->FileHeader.NumberOfSections; ++i)
		{
			this->m_SectionData.push_back(
				{ CH_R_CAST<char*>(m_pSectionHeaders->Name),
				m_pSectionHeaders->VirtualAddress,
				m_pSectionHeaders->Misc.VirtualSize }
			);

			// Move onto next section.
			++m_pSectionHeaders;
		}

		const DWORD m_dSavedExportVirtualAddress = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		const DWORD m_dSavedExportSize = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		if (!m_dSavedExportVirtualAddress || !m_dSavedExportSize)
		{
			CH_LOG("Export table didn't exist for current region. 0x%x | 0X%x", m_dSavedExportVirtualAddress, m_dSavedExportSize);
		}
		else // Export table parsing.
		{
			const PIMAGE_EXPORT_DIRECTORY m_pExportDirectory = CH_R_CAST<PIMAGE_EXPORT_DIRECTORY>(CH_R_CAST<ULONG_PTR>(m_ImageBuffer) + chdr::misc::RvaToOffset(this->m_pNTHeaders, m_dSavedExportVirtualAddress));
			this->m_dExportedFunctionCount = m_pExportDirectory->NumberOfNames;

			WORD* m_pOrdinalAddress = CH_R_CAST<WORD*>(m_pExportDirectory->AddressOfNameOrdinals + CH_R_CAST<uintptr_t>(m_pExportDirectory) - m_dSavedExportVirtualAddress);
			DWORD* m_pNamesAddress = CH_R_CAST<DWORD*>(m_pExportDirectory->AddressOfNames + CH_R_CAST<uintptr_t>(m_pExportDirectory) - m_dSavedExportVirtualAddress);
			DWORD* m_pFunctionAddress = CH_R_CAST<DWORD*>(m_pExportDirectory->AddressOfFunctions + CH_R_CAST<uintptr_t>(m_pExportDirectory) - m_dSavedExportVirtualAddress);

			for (DWORD i = 0; i < this->m_dExportedFunctionCount; ++i)
			{
				char* m_szExportName = CH_R_CAST<char*>(m_pNamesAddress[i] + CH_R_CAST<uintptr_t>(m_pExportDirectory) - m_dSavedExportVirtualAddress);
				this->m_ExportData.push_back({ m_szExportName, m_pFunctionAddress[m_pOrdinalAddress[i]], m_pOrdinalAddress[i] });
			}
		}

		const DWORD m_dSavedImportVirtualAddress = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		const DWORD m_dSavedImportSize = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

		if (!m_dSavedImportVirtualAddress || !m_dSavedImportSize)
		{
			CH_LOG("Import table didn't exist for current region. 0x%X | 0x%X", m_dSavedImportVirtualAddress, m_dSavedImportSize);
		}
		else // Import table parsing.
		{
			PIMAGE_IMPORT_DESCRIPTOR m_pImportDescriptor = CH_R_CAST<PIMAGE_IMPORT_DESCRIPTOR>(CH_R_CAST<ULONG_PTR>(m_ImageBuffer) + chdr::misc::RvaToOffset(this->m_pNTHeaders, m_dSavedImportVirtualAddress));

			while (m_pImportDescriptor->Name)
			{
				// Read module name.
				char* m_szModuleName = CH_R_CAST<char*>(CH_R_CAST<ULONG_PTR>(m_ImageBuffer) + chdr::misc::RvaToOffset(this->m_pNTHeaders, m_pImportDescriptor->Name));

				std::size_t m_nThunkOffset = m_pImportDescriptor->OriginalFirstThunk ? m_pImportDescriptor->OriginalFirstThunk : m_pImportDescriptor->FirstThunk;
				PIMAGE_THUNK_DATA m_pThunkData = CH_R_CAST<PIMAGE_THUNK_DATA>(CH_R_CAST<ULONG_PTR>(m_ImageBuffer) + chdr::misc::RvaToOffset(this->m_pNTHeaders, m_nThunkOffset));

				while (m_pThunkData->u1.AddressOfData)
				{
					if (!(m_pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
					{
						// Read function name.
						char* m_szFunctionName = CH_R_CAST<char*>(CH_R_CAST<ULONG_PTR>(m_ImageBuffer) + chdr::misc::RvaToOffset(this->m_pNTHeaders, (m_pThunkData->u1.AddressOfData + 2)));

						// Cache desired data.
						this->m_ImportData.push_back({ m_szModuleName, m_szFunctionName });
					}
					else
					{
						// TODO: Imports by ordinal, dunno how I will make this nice.
					}

					// Move onto next thunk.
					++m_pThunkData;
				}

				// Move onto next descriptor.
				++m_pImportDescriptor;
			}
		}
	}

	// Parsing data out of this image's process.
	PEHeaderData_t::PEHeaderData_t(Process_t& m_Process, DWORD m_dCustomBaseAddress)
	{
		const DWORD m_dProcessBaseAddress = m_dCustomBaseAddress != NULL ? m_dCustomBaseAddress : m_Process.GetBaseAddress();
		CH_ASSERT(true, m_dProcessBaseAddress, "Couldn't find base address of target process.");

		IMAGE_DOS_HEADER m_pDOSHeadersTemporary = m_Process.Read<IMAGE_DOS_HEADER>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress));
		this->m_pDOSHeaders = &m_pDOSHeadersTemporary;

		IMAGE_NT_HEADERS m_NTHeadersTemporary = m_Process.Read<IMAGE_NT_HEADERS>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + this->m_pDOSHeaders->e_lfanew));
		this->m_pNTHeaders = &m_NTHeadersTemporary;

		// Ensure image PE headers was valid.
		CH_ASSERT(true, this->IsValid(), "Couldn't find MZ&NT header.");

		for (UINT i = 0; i < m_pNTHeaders->FileHeader.NumberOfSections; ++i)
		{
			static std::size_t m_nSectionOffset = sizeof(IMAGE_NT_HEADERS);
			IMAGE_SECTION_HEADER m_pSectionHeaders = m_Process.Read<IMAGE_SECTION_HEADER>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + this->m_pDOSHeaders->e_lfanew + m_nSectionOffset));

			this->m_SectionData.push_back(
				{ CH_R_CAST<char*>(m_pSectionHeaders.Name),
				m_pSectionHeaders.VirtualAddress,
				m_pSectionHeaders.Misc.VirtualSize }
			);

			// Move onto next section.
			m_nSectionOffset += sizeof(IMAGE_SECTION_HEADER);
		}

		const DWORD m_dSavedExportVirtualAddress = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		const DWORD m_dSavedExportSize = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		if (!m_dSavedExportVirtualAddress || !m_dSavedExportSize)
		{
			CH_LOG("Export table didn't exist for current region. 0x%x | 0X%x", m_dSavedExportVirtualAddress, m_dSavedExportSize);
		}
		else // Export table parsing.
		{
			IMAGE_EXPORT_DIRECTORY m_pExportDirectory = m_Process.Read<IMAGE_EXPORT_DIRECTORY>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_dSavedExportVirtualAddress));
			this->m_dExportedFunctionCount = m_pExportDirectory.NumberOfNames;

			for (DWORD i = 0; i < this->m_dExportedFunctionCount; ++i)
			{
				char m_szExportName[MAX_PATH];
				m_Process.Read(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_Process.Read<std::uint32_t>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_pExportDirectory.AddressOfNames + (i * 4)))), m_szExportName, sizeof(m_szExportName));
				m_szExportName[MAX_PATH - 1] = '\0';

				const std::uint16_t m_dOrdinalNumber = m_Process.Read<std::uint16_t>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_pExportDirectory.AddressOfNameOrdinals + (i * 2)));
				const std::uint32_t m_pFunctionAddress = m_Process.Read<std::uint32_t>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_pExportDirectory.AddressOfFunctions + (m_dOrdinalNumber * 4)));

				// Cache desired data.
				this->m_ExportData.push_back({ m_szExportName, m_pFunctionAddress, m_dOrdinalNumber });
			}
		}

		const DWORD	m_dSavedImportVirtualAddress = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		const DWORD m_dSavedImportSize = this->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

		if (!m_dSavedImportVirtualAddress || !m_dSavedImportSize)
		{
			CH_LOG("Import table didn't exist for current region. 0x%X | 0x%X", m_dSavedImportVirtualAddress, m_dSavedImportSize);
		}
		else // Import table parsing.
		{
			DWORD m_dDescriptorOffset = m_dSavedImportVirtualAddress;
			IMAGE_IMPORT_DESCRIPTOR m_pImportDescriptor = m_Process.Read<IMAGE_IMPORT_DESCRIPTOR>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_dDescriptorOffset));

			while (m_pImportDescriptor.Name)
			{
				// Read module name.
				char m_szModuleName[MAX_PATH];
				m_Process.Read(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_pImportDescriptor.Name), m_szModuleName, sizeof(m_szModuleName));
				m_szModuleName[MAX_PATH - 1] = '\0';

				std::size_t m_nThunkOffset = m_pImportDescriptor.OriginalFirstThunk ? m_pImportDescriptor.OriginalFirstThunk : m_pImportDescriptor.FirstThunk;
				IMAGE_THUNK_DATA m_pThunkData = m_Process.Read<IMAGE_THUNK_DATA>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_nThunkOffset));

				while (m_pThunkData.u1.AddressOfData)
				{
					if (!(m_pThunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG32))
					{
						// Read function name.
						char m_szFunctionName[MAX_PATH];
						m_Process.Read(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + (m_pThunkData.u1.AddressOfData + 2)), m_szFunctionName, sizeof(m_szFunctionName));
						m_szFunctionName[MAX_PATH - 1] = '\0';

						// Cache desired data.
						this->m_ImportData.push_back({ m_szModuleName, m_szFunctionName });
					}
					else
					{
						// TODO: Imports by ordinal, dunno how I will make this nice.
					}

					// Move onto next thunk.
					m_nThunkOffset += sizeof(IMAGE_THUNK_DATA32);
					m_pThunkData = m_Process.Read<IMAGE_THUNK_DATA>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_nThunkOffset));
				}

				// Move onto next descriptor.
				m_dDescriptorOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
				m_pImportDescriptor = m_Process.Read<IMAGE_IMPORT_DESCRIPTOR>(CH_R_CAST<LPCVOID>(m_dProcessBaseAddress + m_dDescriptorOffset));
			}
		}

	}

	// Ensure we found the target PE header.
	bool PEHeaderData_t::IsValid()
	{
		return this->m_pDOSHeaders->e_magic == IMAGE_DOS_SIGNATURE && this->m_pNTHeaders->Signature == IMAGE_NT_SIGNATURE;
	}

	// Helper function to get DOS header of PE image.
	PIMAGE_DOS_HEADER PEHeaderData_t::GetDOSHeader()
	{
		return this->m_pDOSHeaders;
	}

	// Helper function to get NT headers of PE image.
	PIMAGE_NT_HEADERS PEHeaderData_t::GetNTHeader()
	{
		return this->m_pNTHeaders;
	}

	// Helper function to get section data of PE image.
	std::vector<PEHeaderData_t::SectionData_t> PEHeaderData_t::GetSectionData()
	{
		return this->m_SectionData;
	}

	// Helper function to get exported functions' data of PE image.
	std::vector<PEHeaderData_t::ExportData_t> PEHeaderData_t::GetExportData()
	{
		return this->m_ExportData;
	}

	// Helper function to get imported functions' data of PE image.
	std::vector<PEHeaderData_t::ImportData_t> PEHeaderData_t::GetImportData()
	{
		return this->m_ImportData;
	}
}

// ImageFile_t definitions and functions.
namespace chdr
{
	// Used for parsing PE's from file.
	ImageFile_t::ImageFile_t(std::string m_szImagePath)
	{
		CH_ASSERT(true, std::filesystem::exists(m_szImagePath), "File at %s doesn't exist, or wasn't accessible.", m_szImagePath.c_str());

		// Fill image buffer.
		std::ifstream m_fFile(m_szImagePath.c_str(), std::ios::binary);
		(&m_ImageBuffer)->assign((std::istreambuf_iterator<char>(m_fFile)), std::istreambuf_iterator<char>());
		m_fFile.close();

		// Parse PE header information.
		m_PEHeaderData = PEHeaderData_t((&m_ImageBuffer)->data(), (&m_ImageBuffer)->size());
	}

	// Used for parsing PE's from memory.
	ImageFile_t::ImageFile_t(std::uint8_t* m_ImageBuffer, std::size_t m_nImageSize)
	{
		// Copy over to object-specific variable to possibly use later.
		this->m_ImageBuffer.resize(m_nImageSize);
		std::memcpy(&this->m_ImageBuffer[0], m_ImageBuffer, m_nImageSize);

		// Parse PE header information.
		m_PEHeaderData = PEHeaderData_t(m_ImageBuffer, m_nImageSize);
	}

	// Ensure we found the target PE image.
	bool ImageFile_t::IsValid()
	{
		return this->m_ImageBuffer.size() != 0;
	}

	// Helper function to get PE header data of PE image.
	PEHeaderData_t ImageFile_t::GetPEHeaderData()
	{
		return this->m_PEHeaderData;
	}

	void ImageFile_t::WriteToFile(const char* m_szFilePath)
	{
		std::ofstream file(m_szFilePath, std::ios_base::out | std::ios_base::binary);
		file.write(CH_R_CAST<char*>(m_ImageBuffer.data()), m_ImageBuffer.size());
		file.close();
	}
}

// Driver_t definitions and functions.
namespace chdr
{
	Driver_t::Driver_t(const char* m_szDriverPath)
	{
		// Object-specific driver path.
		this->m_szDriverPath = m_szDriverPath;
	}

	// Initialize by driver information.
	Driver_t::Driver_t(const char* m_szDriverName, DWORD m_dDesiredAccess, DWORD m_dSharedMode, DWORD m_dCreationDisposition, DWORD m_dFlagsAndAttributes)
	{
		this->m_hTargetDriverHandle = CreateFileA(m_szDriverName,
			m_dDesiredAccess,
			m_dSharedMode,
			nullptr,
			m_dCreationDisposition,
			m_dFlagsAndAttributes,
			nullptr);

		CH_ASSERT(false, this->m_hTargetDriverHandle && this->m_hTargetDriverHandle != INVALID_HANDLE_VALUE, "Failed to get HANDLE to desired service!");
	}

	// For opening an HANDLE to a currently loaded driver.
	bool Driver_t::SetupHandle(const char* m_szDriverName, DWORD m_dDesiredAccess, DWORD m_dSharedMode, DWORD m_dCreationDisposition, DWORD m_dFlagsAndAttributes)
	{
		this->m_hTargetDriverHandle = CreateFileA(m_szDriverName,
			m_dDesiredAccess,
			m_dSharedMode,
			nullptr,
			m_dCreationDisposition,
			m_dFlagsAndAttributes,
			nullptr);

		return this->m_hTargetDriverHandle && this->m_hTargetDriverHandle != INVALID_HANDLE_VALUE;
	}

	// For destroying a HANDLE to a currently loaded driver.
	bool Driver_t::DestroyHandle()
	{
		if (!this->m_hTargetDriverHandle || this->m_hTargetDriverHandle == INVALID_HANDLE_VALUE)
		{
			// Sir, why have you tried to release this handle without ensuring it was setup correctly?!
			CH_LOG("Tried to release an invalid HANDLE!");
			return NULL;
		}

		const bool m_bDidSucceed = CloseHandle(this->m_hTargetDriverHandle);
		return m_bDidSucceed;
	}

	// Send IOCTL request to the target driver, returning the response.
	DWORD Driver_t::SendIOCTL(DWORD m_dControlCode, LPVOID m_pInBuffer, DWORD m_dBufferSize, LPVOID m_pOutBuffer, DWORD m_dOutBufferSize)
	{
		DWORD m_dBytesReturned = { 0 };
		const BOOL m_bDidSucceed = DeviceIoControl(this->m_hTargetDriverHandle,
			m_dControlCode, m_pInBuffer,
			m_dBufferSize, m_pOutBuffer,
			m_dOutBufferSize, &m_dBytesReturned,
			nullptr);

		if (!m_bDidSucceed)
		{
			CH_LOG("DeviceIoControl failed with error code #%i!", GetLastError());
			return NULL;
		}

		return m_dBytesReturned;
	}

	// Loads a target driver through the service manager. Obviously, these drivers must be SIGNED.
	SC_HANDLE Driver_t::LoadDriver(const char* m_szDriverPaths, const char* m_szDriverName)
	{
		// Create HANDLE to the service manager.
		const SC_HANDLE m_hServiceManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
		if (!m_hServiceManager || m_hServiceManager == INVALID_HANDLE_VALUE)
		{
			CH_LOG("Couldn't obtain valid HANDLE to service manager!");
			return CH_R_CAST<SC_HANDLE>(INVALID_HANDLE_VALUE);
		}
		// Tell service manager to create&intialize our service.
		const SC_HANDLE m_hCreatedService = CreateServiceA(m_hServiceManager,
			m_szDriverName, m_szDriverName,
			SERVICE_START | SERVICE_STOP | DELETE,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
			m_szDriverPaths, nullptr, nullptr, nullptr, nullptr, nullptr);

		if (!m_hCreatedService || m_hCreatedService == INVALID_HANDLE_VALUE)
		{
			CH_LOG("Failed to create desired service!");
			CloseServiceHandle(m_hServiceManager);
			return CH_R_CAST<SC_HANDLE>(INVALID_HANDLE_VALUE);
		}

		// Finally, start the service.
		const BOOL m_bDidServiceStartSuccessfully = StartServiceA(m_hCreatedService, NULL, nullptr);
		if (!m_bDidServiceStartSuccessfully)
		{
			CH_LOG("Failed to start desired service!");
		}

		// Release unneeded handle.
		CloseServiceHandle(m_hServiceManager);

		return m_hCreatedService;
	}

	// Unloads a target driver that was previously loaded through the service manager.
	void Driver_t::UnloadDriver(const SC_HANDLE m_hLoadedStartedService)
	{
		// Send STOP signal to desired service.
		SERVICE_STATUS m_ServiceStatus{};
		ControlService(m_hLoadedStartedService, SERVICE_CONTROL_STOP, &m_ServiceStatus);

		// Finally, delete the service.
		DeleteService(m_hLoadedStartedService);
	}
}

// Thread_t definitions and functions.
namespace chdr
{
	// Initialize with TID.
	Thread_t::Thread_t(DWORD m_dThreadID)
	{
		this->m_dThreadID = m_dThreadID;
		this->m_hThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, this->m_dThreadID);

		// Only release this HANDLE if we've actually got access to it.
		this->m_bShouldFreeHandleAtDestructor = this->m_hThreadHandle && this->m_hThreadHandle != INVALID_HANDLE_VALUE;
	}

	// Initialize with TID&HANDLE.
	Thread_t::Thread_t(HANDLE m_hThreadHandle)
	{
		this->m_hThreadHandle = m_hThreadHandle;
		this->m_dThreadID = GetThreadId(this->m_hThreadHandle);

		// We should NEVER try to release this HANDLE, as it's a copy of another.
		this->m_bShouldFreeHandleAtDestructor = false;
	}

	// Default dtor
	Thread_t::~Thread_t()
	{
		// Not allowed to release this HANDLE, or was already released.
		CH_ASSERT(true,
			this->m_bShouldFreeHandleAtDestructor &&
			this->m_hThreadHandle &&
			this->m_hThreadHandle != INVALID_HANDLE_VALUE,
			"");

		// FIXME:
		CloseHandle(this->m_hThreadHandle);
	}

#pragma warning( push )
#pragma warning( disable : 6258 ) // Using TerminateThread does not allow proper thread clean.
	// Terminating a target thread.
	void Thread_t::Terminate()
	{
		CH_ASSERT(true, this->m_hThreadHandle && this->m_hThreadHandle != INVALID_HANDLE_VALUE, "Tried to terminate a target thread with an empty HANDLE!");

		TerminateThread(this->m_hThreadHandle, EXIT_FAILURE/*To give some sort of graceful termination.*/);
		CloseHandle(this->m_hThreadHandle); // Can we even do this? Common sense dictates no.
	}
#pragma warning( pop )

	// Suspending a target thread.
	void Thread_t::Suspend()
	{
		CH_ASSERT(true, this->m_hThreadHandle && this->m_hThreadHandle != INVALID_HANDLE_VALUE, "Tried to suspend a target thread with an empty HANDLE!");

		this->m_bIsThreadManuallySuspended = SuspendThread(this->m_hThreadHandle) != 0;
	}

	// Resuming a target thread.
	void Thread_t::Resume()
	{
		CH_ASSERT(true, this->m_hThreadHandle && this->m_hThreadHandle != INVALID_HANDLE_VALUE, "Tried to resume a target thread with an empty HANDLE!");

		this->m_bIsThreadManuallySuspended = ResumeThread(this->m_hThreadHandle) == 0;
		CH_ASSERT(true, !this->m_bIsThreadManuallySuspended, "Failed to resume thread with TID %i!", this->m_dThreadID);
	}

	// Check which module this thread is associated with.
	std::string Thread_t::GetOwningModule(chdr::Process_t& m_Process, DWORD m_dStartAddress)
	{
		// Using cached data here, maybe this can be bad if all of a sudden a new module is loaded.
		// But honestly, idc because it's so much faster than enumerating modules again..
		for (auto& CurrentModule : m_Process.EnumerateModules(true))
		{
			// Too high.
			if (m_dStartAddress < CurrentModule.m_dModuleBaseAddress)
				continue;

			// Too low.
			if (m_dStartAddress > CurrentModule.m_dModuleBaseAddress + CurrentModule.m_dModuleSize)
				continue;

			// Just right :).
			return CurrentModule.m_szModuleName;
		}
		return "N/A (ERROR)";
	}

	// Ensure we found a HANDLE to the target thread.
	bool Thread_t::IsValid()
	{
		return this->m_hThreadHandle && this->m_hThreadHandle != INVALID_HANDLE_VALUE;
	}

	// Is the target thread suspended?
	bool Thread_t::IsSuspended()
	{
		bool m_bIsThreadSuspended = WaitForSingleObject(this->m_hThreadHandle, 0) == WAIT_ABANDONED;
		return m_bIsThreadSuspended;
	}

	// Did we suspend the target thread ourselves?
	bool Thread_t::IsManuallySuspended()
	{
		return this->m_bIsThreadManuallySuspended;
	}

	// Get's the start address of a target thread.
	DWORD Thread_t::GetStartAddress()
	{
		const HMODULE m_hNTDLL = GetModuleHandleA("ntdll.dll");
		if (!m_hNTDLL)
		{
			CH_LOG("Couldn't find loaded module ntdll!");
			return NULL;
		}

		NtQueryInformationThread_fn NtQueryInformationThread = CH_R_CAST<NtQueryInformationThread_fn>(GetProcAddress(m_hNTDLL, "NtQueryInformationThread"));

		DWORD m_dThreadStartAddress = NULL;
		NtQueryInformationThread(m_hThreadHandle, THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &m_dThreadStartAddress, sizeof(DWORD), nullptr);
		return m_dThreadStartAddress;
	}
}

// Module_t definitions and functions.
namespace chdr
{
	// Setup module in process by (non-case sensitive) name. 
	Module_t::Module_t(chdr::Process_t& m_Process, const char* m_szModuleName)
	{

		// Walk all loaded modules until we land on the wish module.
		for (auto& CurrentModule : m_Process.EnumerateModules())
		{
			if (strcmp(CurrentModule.m_szModuleName.c_str(), m_szModuleName) != 0)
				continue;

			this->m_dModuleBaseAddress = CurrentModule.m_dModuleBaseAddress;
			this->m_dModuleSize = CurrentModule.m_dModuleSize;
			break; // Found what we needed, exit loop.
		}

		CH_ASSERT(true, this->m_dModuleBaseAddress && this->m_dModuleSize, "Couldn't find desired module %s", m_szModuleName);

		//	this->SetupModule_Internal(m_Process);
	}

	// Setup module in process by address in processes' memory space.
	Module_t::Module_t(chdr::Process_t& m_Process, DWORD m_dModuleBaseAddress, DWORD m_dModuleSize)
	{
		this->m_dModuleBaseAddress = m_dModuleBaseAddress;
		this->m_dModuleSize = m_dModuleSize;

		//	this->SetupModule_Internal(m_Process);
	}

	void Module_t::SetupModule_Internal(chdr::Process_t& m_Process)
	{
		// Ensure vector holding image buffer has sufficient size.
		this->m_ModuleData.resize(this->m_dModuleSize);

		std::size_t m_nCurrentSize = NULL;
		MEMORY_BASIC_INFORMATION m_MemoryInformation = { 0 };

		while (m_Process.Query(CH_R_CAST<LPCVOID>(this->m_dModuleBaseAddress + m_nCurrentSize), &m_MemoryInformation) && m_nCurrentSize < this->m_dModuleSize)
		{
			// Read position's data to buffer.
			const auto m_CurrentRegionData = std::make_unique<std::uint8_t[]>(m_MemoryInformation.RegionSize);


			// Add this region's data to our local object's buffer.

			// Append position we're currently at.
			m_nCurrentSize += m_MemoryInformation.RegionSize;
		}
	}

	// Ensure we found the target module in memory.
	bool Module_t::IsValid()
	{
		return this->m_ModuleData.size() != 0;
	}
}

// Miscelleanous functions.
namespace chdr
{
	namespace misc
	{
		// Convert relative virtual address to file offset.
		DWORD RvaToOffset(PIMAGE_NT_HEADERS m_pNTHeaders, DWORD Rva)
		{
			PIMAGE_SECTION_HEADER m_pSectionHeader = IMAGE_FIRST_SECTION(m_pNTHeaders);
			if (Rva < m_pSectionHeader->PointerToRawData)
				return Rva;

			for (WORD i = 0; i < m_pNTHeaders->FileHeader.NumberOfSections; ++i)
			{
				if (Rva < m_pSectionHeader[i].VirtualAddress)
					continue;

				DWORD Limit = m_pSectionHeader[i].SizeOfRawData ? m_pSectionHeader[i].SizeOfRawData : m_pSectionHeader[i].Misc.VirtualSize;
				if (Rva >= m_pSectionHeader[i].VirtualAddress + Limit)
					continue;

				if (m_pSectionHeader[i].PointerToRawData == 0)
					return Rva;

				DWORD Offset = Rva;
				Offset -= m_pSectionHeader[i].VirtualAddress;
				Offset += m_pSectionHeader[i].PointerToRawData;

				return Offset;
			}
			return NULL;
		}
	}
}