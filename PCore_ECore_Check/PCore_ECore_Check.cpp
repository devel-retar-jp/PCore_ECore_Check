/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PCore_ECore.cpp : アプリケーションのエントリ ポイントを定義します。
//
// P Core、E Coreの種類と個数を取得
// Windows専用
//
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "PCore_ECore_Check.h"
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CPU Clock Info show
void PrintPropertyValueShow(const VARIANT& vtProp) {
	switch (vtProp.vt) {
	case VT_BSTR:
	case VT_LPWSTR:
		wprintf(L"%s\n", vtProp.bstrVal);
		break;
	case VT_BOOL:
		wprintf(L"%s\n", vtProp.boolVal ? L"TRUE" : L"FALSE");
		break;
	case VT_UI4:
	case VT_UI2:
	case VT_UI1:
	case VT_UI8:
	case VT_UINT:
	case VT_I2:
	case VT_I4:
	case VT_I1:
	case VT_I8:
	case VT_INT:
		wprintf(L"%u\n", vtProp.uintVal);
		break;
	case VT_NULL:
	case VT_EMPTY:
		wprintf(L">> NO DATA <<\n");
		break;
	default:
		wprintf(L"Type not handled\n");
		break;
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//CPU Info -> WMI (Windows Management Instrumentation)
void CPUInfo(void)
{
	HRESULT hres;

	// Step 1: Initialize COM
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		std::cerr << "Failed to initialize COM library. Error code: " << hres << std::endl;
		return;
	}

	// Step 2: Set general COM security levels
	hres = CoInitializeSecurity(
		nullptr,
		-1,                          // Default authentication service
		nullptr,                     // Default authentication level
		nullptr,                     // Default principal name
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication level for calls
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default impersonation level for calls
		nullptr,                     // Default authorization service
		EOAC_NONE,                   // Additional capabilities of the client or server
		nullptr                      // Reserved
	);

	if (FAILED(hres)) {
		std::cerr << "Failed to initialize security. Error code: " << hres << std::endl;
		CoUninitialize();
		return;
	}

	// Step 3: Obtain the initial locator to WMI
	IWbemLocator* pLoc = nullptr;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		nullptr,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		reinterpret_cast<LPVOID*>(&pLoc)
	);

	if (FAILED(hres)) {
		std::cerr << "Failed to create IWbemLocator object. Error code: " << hres << std::endl;
		CoUninitialize();
		return;
	}

	// Step 4: Connect to WMI through the IWbemLocator::ConnectServer method
	IWbemServices* pSvc = nullptr;

	// Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		nullptr,                  // User name
		nullptr,                  // User password
		0,                        // Locale
		NULL,                  // Security flags
		0,                        // Authority
		0,                        // Context object
		&pSvc                     // IWbemServices proxy
	);

	if (FAILED(hres)) {
		std::cerr << "Could not connect. Error code: " << hres << std::endl;
		pLoc->Release();
		CoUninitialize();
		return ;
	}

	// Step 5: Set security levels on the proxy
	hres = CoSetProxyBlanket(
		pSvc,                          // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,             // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,              // RPC_C_AUTHZ_xxx
		nullptr,                       // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,        // RPC_C_AUTHN_LEVEL_xxx
		RPC_C_IMP_LEVEL_IMPERSONATE,   // RPC_C_IMP_LEVEL_xxx
		nullptr,                       // client identity
		EOAC_NONE                      // proxy capabilities
	);

	if (FAILED(hres)) {
		std::cerr << "Could not set proxy blanket. Error code: " << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return ;
	}

	// Step 6: Use the IWbemServices pointer to make requests of WMI
	IEnumWbemClassObject* pEnumerator = nullptr;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_Processor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator
	);

	if (FAILED(hres)) {
		std::cerr << "Query for operating system name failed. Error code: " << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return ;
	}
	//
	//
	// Step 7: Retrieve the data from the query in step 6
	IWbemClassObject* pclsObj = nullptr;
	ULONG uReturn = 0;

	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn) {
			break;
		}

		// Begin enumeration of properties
		hr = pclsObj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
		if (SUCCEEDED(hr)) {
			// Iterate through properties
			BSTR propName = nullptr;
			VARIANT vtProp;
			VariantInit(&vtProp);

			while ((hr = pclsObj->Next(0, &propName, &vtProp, nullptr, nullptr)) != WBEM_S_NO_MORE_DATA) {
				// Print property name
				wprintf(L"Property : %40s : ", propName);

				// Print property value
				PrintPropertyValueShow(vtProp);

			}
			// Clear VARIANT and free allocated resources
			VariantClear(&vtProp);
			SysFreeString(propName);

			// End enumeration of properties
			pclsObj->EndEnumeration();
		}

		pclsObj->Release();
	}

	// Step 8: Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return ;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//CPU Name => Windows Management Instrumentation (WMI) API
//            レジストリの内容をとってくるような奴
//            セキュリティレベルとかがありいやらしいAPI
std::string CPUName(void)
{
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Step 1: Initialize COM
	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		return "Failed to initialize COM library. Error code: ";
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Step 2: Initialize security
	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities
		NULL                         // Reserved
	);
	//
	if (FAILED(hres)) {
		//std::cerr << "Failed to initialize security. Error code: " << hres << std::endl;
		CoUninitialize();
		return  "Failed to initialize security. Error code: ";
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Step 3: Obtain the initial locator to WMI
	IWbemLocator* pLoc = NULL;
	//
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&pLoc
	);
	//
	if (FAILED(hres)) {
		//std::cerr << "Failed to create IWbemLocator object. Error code: " << hres << std::endl;
		CoUninitialize();
		return "Failed to create IWbemLocator object. Error code: ";
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Step 4: Connect to WMI
	IWbemServices* pSvc = NULL;
	//
	// Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name
		NULL,                    // User password
		0,                       // Locale
		NULL,                    // Security flags
		0,                       // Authority
		0,                       // Context object
		&pSvc                    // IWbemServices proxy
	);
	//
	if (FAILED(hres)) {
		//std::cerr << "Could not connect to WMI namespace. Error code: " << hres << std::endl;
		pLoc->Release();
		CoUninitialize();
		return "Could not connect to WMI namespace. Error code: ";
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Step 5: Set the security levels on the proxy
	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities
	);
	//
	if (FAILED(hres)) {
		//std::cerr << "Could not set proxy blanket. Error code: " << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return "Could not set proxy blanket. Error code: ";
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Step 6: Use the IWbemServices pointer to make requests of WMI.
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_Processor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);
	//
	if (FAILED(hres)) {
		//std::cerr << "Query for operating system name failed. Error code: " << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return "Query for operating system name failed. Error code: ";
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Step 7: Retrieve the data from the query in step 6.
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	//
	std::string bstrValNarrow = "";
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		//
		if (0 == uReturn) {
			break;
		}
		//
		VARIANT vtProp = {};
		//
		// Get the value of the "Name" property
		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		//wprintf(L"CPU Name: %s\n", vtProp.bstrVal);
		//
		// Create a locale object with the default locale
		std::locale loc;
		//
		// Create a std::wstring_convert
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		//
		// Convert wide string to narrow string
		bstrValNarrow = converter.to_bytes(vtProp.bstrVal);
		//
		VariantClear(&vtProp);
		pclsObj->Release();
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//return
	return bstrValNarrow;
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Core数 : SYSTEM_INFO ->　昔はこれだけでOKでした
int checkNumberOfProcessors(void)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	// 利用可能なプロセッサコアの数を取得
	return sysInfo.dwNumberOfProcessors;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//CountSetBits function : Counting the number of set bits in a given bitmask.
//                        ビットマスクをDWORD型にする
DWORD CountSetBits(ULONG_PTR bitMask)
{
	DWORD bitSetCount = 0;
	//
	while (bitMask)
	{
		bitSetCount += bitMask & 1;
		bitMask >>= 1;
	}
	//
	return bitSetCount;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//P Core E core check Functiuon
// PCore : 0  
// ECore : 1 
// PCore the maximum number of threads that can run on each physical P Core : 2 
// ECore the maximum number of threads that can run on each physical P Core : 3 
std::vector<int>checkCoreFunc(int coreType = 0)
{
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// プロセッサコアをpcoreとecoreに分類
	std::vector<int> pcoreList;
	int pcoreNum = 0;
	std::vector<int> ecoreList;
	int ecoreNum = 0;
	std::vector<int> pcoreLogicalCount;
	std::vector<int> ecoreLogicalCount;
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//// Output the number of processor cores
	DWORD pCore_processorCoreCount = 0;
	DWORD eCore_processorCoreCount = 0;
	// Calculate the maximum number of threads that can run on each physical core
	DWORD pCore_logicalProcessorCount = 0;
	DWORD eCore_logicalProcessorCount = 0;
	//
	// Get information about logical processors
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION* buffer = nullptr;
	DWORD bufferSize = 0;
	//
	//malloc buffer
	GetLogicalProcessorInformation(nullptr, &bufferSize);
	buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)malloc(bufferSize);
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	if (GetLogicalProcessorInformation(buffer, &bufferSize)) {
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Count physical core
		for (DWORD i = 0; i < bufferSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION); ++i) {

			//P Core
			if (buffer[i].Relationship == RelationProcessorCore
				&& buffer[i].ProcessorCore.Flags == LTP_PC_SMT
				)
			{
				++pCore_processorCoreCount;
				pcoreList.push_back(pcoreNum);
				pcoreNum++;
			}

			//E Core -> LTP_PC_SMTじゃない？で良いんかな？
			if (buffer[i].Relationship == RelationProcessorCore
				&& buffer[i].ProcessorCore.Flags != LTP_PC_SMT
				)
			{
				++eCore_processorCoreCount;
				ecoreList.push_back(ecoreNum);
				ecoreNum++;
			}
		}
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Calculate the maximum number of threads that can run on each physical core
		for (DWORD i = 0; i < bufferSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION); ++i)
		{
			//P Core
			if (
				buffer[i].Relationship == RelationProcessorCore
				&& buffer[i].ProcessorCore.Flags == LTP_PC_SMT
				)
			{
				pCore_logicalProcessorCount += CountSetBits(buffer[i].ProcessorMask);
			}
			//E Core -> LTP_PC_SMTじゃない？で良いんかな？
			if (
				buffer[i].Relationship == RelationProcessorCore
				&& buffer[i].ProcessorCore.Flags != LTP_PC_SMT
				)
			{
				eCore_logicalProcessorCount += CountSetBits(buffer[i].ProcessorMask);
			}
		}
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//コア数を演算
		if (pCore_processorCoreCount != 0)
		{
			pcoreLogicalCount.push_back(pCore_logicalProcessorCount / pCore_processorCoreCount);
		}
		if (eCore_processorCoreCount != 0)
		{
			ecoreLogicalCount.push_back(eCore_logicalProcessorCount / eCore_processorCoreCount);
		}
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	}
	else {
		std::cerr << "Error getting logical processor information." << std::endl;
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//後始末
	free(buffer);
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//P Coreの数
	if (coreType == 0)
	{
		return pcoreList;
	}
	//E Coreの数
	if (coreType == 1)
	{
		return ecoreList;
	}
	//P Coreの1コア当たりの論理コア数
	if (coreType == 2)
	{
		return { pcoreLogicalCount };
	}
	//E Coreの1コア当たりの論理コア数
	if (coreType == 3)
	{
		return { ecoreLogicalCount };
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//エラー時
	return {};
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main()
{
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//CPU Info
	std::cout << "------------------------------------------------------------------------------------------------\r\n" << std::flush;
	std::cout << "           WMI (Windows Management Instrumentation) " << std::endl;
	CPUInfo();
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//CPU Name
	std::cout << "------------------------------------------------------------------------------------------------\r\n" << std::flush;
	std::cout << "Property :                                 CPU Name : " << CPUName() << "\n";
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//論理コア sysInfo.dwNumberOfProcessors
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	std::cout << "------------------------------------------------------------------------------------------------\r\n" << std::flush;
	//std::cout << "\n";
	std::cout << "          SYSTEM_INFO ->" << "\n";
	//std::cout << "\n";
	//std::cout << "dwActiveProcessorMask       : " << sysInfo.dwActiveProcessorMask << "\n";
	//std::cout << "dwAllocationGranularity     : " << sysInfo.dwAllocationGranularity << "\n";
	std::cout << "             dwNumberOfProcessors : Maximum threads : " << sysInfo.dwNumberOfProcessors << "\n";
	//std::cout << "dwOemId                     : " << sysInfo.dwOemId << "\n";
	//std::cout << "dwPageSize                  : " << sysInfo.dwPageSize << "\n";
	//std::cout << "dwProcessorType             : " << sysInfo.dwProcessorType << "\n";
	//std::cout << "lpMaximumApplicationAddress : " << sysInfo.lpMaximumApplicationAddress << "\n";
	//std::cout << "lpMinimumApplicationAddress : " << sysInfo.lpMinimumApplicationAddress << "\n";
	//std::cout << "wProcessorArchitecture      : " << sysInfo.wProcessorArchitecture << "\n";
	//std::cout << "wProcessorLevel             : " << sysInfo.wProcessorLevel << "\n";
	//std::cout << "wProcessorRevision          : " << sysInfo.wProcessorRevision << "\n";
	//std::cout << "wReserved                   : " << sysInfo.wReserved << "\n";
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// プロセッサコアをpcoreとecoreに分類
	std::vector<int> pcoreList = checkCoreFunc(0);
	std::vector<int> pcorelogicalList = checkCoreFunc(2);
	std::vector<int> ecoreList = checkCoreFunc(1);
	std::vector<int> ecorelogicalList = checkCoreFunc(3);
	std::cout << "------------------------------------------------------------------------------------------------\r\n" << std::flush;
	std::cout << "  P Core :                Number of processor cores : ";
	for (int core : pcoreList) {
		std::cout << core << " ";
	}
	std::cout << std::endl;
	//
	std::cout << "  P Core :        Maximum threads per physical core : ";
	for (int core : pcorelogicalList) {
		std::cout << core << " ";
	}
	std::cout << std::endl;
	//
	std::cout << "  E Core :                Number of processor cores : ";
	for (int core : ecoreList) {
		std::cout << core << " ";
	}
	std::cout << std::endl;
	//
	std::cout << "  E Core :        Maximum threads per physical core : ";
	for (int core : ecorelogicalList) {
		std::cout << core << " ";
	}
	std::cout << std::endl;
	std::cout << "------------------------------------------------------------------------------------------------\r\n" << std::flush;
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	return 0;
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
