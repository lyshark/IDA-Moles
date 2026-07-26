#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <time.h>
#include <string>
#include <algorithm>
#include <climits>
#include "mongoose.h"
#include "cJSON.h"
#include <windows.h>
#include <TlHelp32.h>
#include <wininet.h>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <hexrays.hpp>
#include <range.hpp>
#include <typeinf.hpp>
#include <segment.hpp>
#include <frame.hpp>
#include <nalt.hpp>
#include <bytes.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <entry.hpp>
#include <ctype.h>

#define PLUGIN_VERSION "1.0.8"

netnode ignore_micro;

enum class RequestType
{
	Unknown,
	Info_GetBasicInfo,
	Info_GetImageInfo,
	Function_GetFunction,
	Function_GetFunctionInfo,
	Function_GetFunctionCount,
	Function_GetFunctionByAddr,
	Function_GetFunctionByName,
	Function_FindFunctionByName,
	Function_GetImportFunctions,
	Segment_GetSegment,
	Segment_GetSegmentCount,
	Segment_GetSegmentFromAddr,
	Reverse_GetMicroCode,
	Reverse_DeompileChecked,
	Reverse_DisassembleFunction,
	Reverse_DisassemblyCount,
	Reverse_DisassemblyRange,
	Reverse_DecompileFunctionFromAddr,
	Reverse_DecompileFunctionFromName,
	Reverse_DecompileAddressToLine,
	Reverse_DecompileLineToAddress,
	Reverse_GetSelectDecompile,
	Reverse_GetSelectDisassembly,
	Reverse_GetSelectHex,
	Memory_GetEntryPoints,
	Memory_GetDefinedStruct,
	Memory_GetMemoryBytes,
	Memory_GetMemoryByte,
	Memory_GetMemoryWord,
	Memory_GetMemoryDword,
	Memory_GetMemoryQword,
	Memory_GetStringInfo,
	Memory_MemorySearch,
	Memory_GetTypeByName,
	Memory_XrefCodeFirstTo,
	Memory_XrefCodeFirstFrom,
	Memory_XrefDataFirstTo,
	Memory_XrefDataFirstFrom,
	Memory_XrefCodeToArray,
	Memory_XrefCodeFromArray,
	Memory_XrefDataToArray,
	Memory_XrefDataFromArray,
	Memory_XrefGetListArray,
	Other_SetAssemblyComment,
	Other_SetFunctionComment,
	Other_GetFunctionName,
	Other_SetFunctionName,
	Other_SwitchPseudoCodeTo,
	Other_GetFunctionVarName,
	Other_SetFunctionVarName,
	Other_GetStructMemberName,
	Other_SetStructMemberName,
	Other_GetCurrentSelect
};

qstring g_decompiled_code = { 0 };

namespace Tools
{
	std::string decToHex(long long num)
	{
		if (num == 0)
		{
			return "0";
		}

		bool isNegative = false;
		unsigned long long n;
		if (num < 0)
		{
			isNegative = true;
			n = -num;
		}
		else {
			n = num;
		}

		const std::string hexDigits = "0123456789ABCDEF";
		std::string hexStr;

		while (n > 0)
		{
			int remainder = n % 16;
			hexStr += hexDigits[remainder];
			n /= 16;
		}

		if (isNegative)
		{
			hexStr += "-";
		}
		reverse(hexStr.begin(), hexStr.end());
		return hexStr;
	}

	long long hexToDec(const std::string& hexStr)
	{
		if (hexStr.empty())
		{
			return 0;
		}

		long long result = 0;
		int start = 0;
		bool isNegative = false;

		if (hexStr[0] == '-')
		{
			isNegative = true;
			start = 1;
		}

		if (hexStr.size() - start >= 2
			&& hexStr[start] == '0'
			&& (hexStr[start + 1] == 'x' || hexStr[start + 1] == 'X'))
		{
			start += 2;
		}

		if (start >= hexStr.size())
		{
			return 0;
		}

		for (int i = start; i < hexStr.size(); ++i)
		{
			char c = hexStr[i];
			int val;

			if (c >= '0' && c <= '9')
			{
				val = c - '0';
			}
			else if (c >= 'A' && c <= 'F')
			{
				val = 10 + (c - 'A');
			}
			else if (c >= 'a' && c <= 'f')
			{
				val = 10 + (c - 'a');
			}
			else
			{
				return 0;
			}

			if (result > (LLONG_MAX - val) / 16)
			{
				return 0;
			}

			result = result * 16 + val;
		}

		if (isNegative)
		{
			if (result > LLONG_MAX)
			{
				return 0;
			}
			result = -result;
		}

		return result;
	}

	std::string binToHex(const void* data, size_t len)
	{
		if (data == nullptr || len == 0)
		{
			return "";
		}

		const uint8_t* bytes = static_cast<const uint8_t*>(data);
		std::stringstream ss;
		ss << std::hex << std::setfill('0');

		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << static_cast<uint32_t>(bytes[i]);
		}

		return ss.str();
	}
};

struct RequestData
{
	RequestType type;
	std::vector<std::string> params;
};

struct CJsonDeleter
{
	void operator()(cJSON* ptr) const
	{
		if (ptr != nullptr)
		{
			cJSON_Delete(ptr);
		}
	}
};

using CJsonPtr = std::unique_ptr<cJSON, CJsonDeleter>;

struct ResponseData
{
	bool success;
	CJsonPtr result;

	ResponseData() : success(false), result(cJSON_CreateObject()) {}
};

class ThreadUtils
{
public:
	using ThreadHandle = HANDLE;
	using MutexHandle = HANDLE;

	static ThreadHandle create_thread(LPTHREAD_START_ROUTINE func)
	{
		return CreateThread(nullptr, 0, func, nullptr, 0, nullptr);
	}

	static void join_thread(ThreadHandle handle)
	{
		if (handle != nullptr)
		{
			WaitForSingleObject(handle, INFINITE);
			CloseHandle(handle);
		}
	}

	static MutexHandle create_mutex()
	{
		return CreateMutex(nullptr, FALSE, nullptr);
	}

	static void lock_mutex(MutexHandle mutex)
	{
		WaitForSingleObject(mutex, INFINITE);
	}

	static void unlock_mutex(MutexHandle mutex)
	{
		ReleaseMutex(mutex);
	}

	static void destroy_mutex(MutexHandle mutex)
	{
		CloseHandle(mutex);
	}
};

class ServerContext
{
public:
	mg_mgr mgr;
	std::atomic<bool> running;
	ThreadUtils::ThreadHandle thread;
	ThreadUtils::MutexHandle mutex;
	std::string listen_addr;
	class RequestHandler* handler;

	ServerContext() : running(false), handler(nullptr)
	{
		mutex = ThreadUtils::create_mutex();
		mg_mgr_init(&mgr);
	}

	~ServerContext()
	{
		ThreadUtils::destroy_mutex(mutex);
		mg_mgr_free(&mgr);
	}
};

class RequestParser
{
public:
	static RequestData parse(cJSON* req_json)
	{
		RequestData data;
		data.type = RequestType::Unknown;

		cJSON* class_name = cJSON_GetObjectItemCaseSensitive(req_json, "class");
		cJSON* interface = cJSON_GetObjectItemCaseSensitive(req_json, "interface");
		cJSON* param_list = cJSON_GetObjectItemCaseSensitive(req_json, "params");

		if (!cJSON_IsString(class_name) || !class_name->valuestring ||
			!cJSON_IsString(interface) || !interface->valuestring ||
			!cJSON_IsArray(param_list))
		{
			return data;
		}

		for (int i = 0; i < cJSON_GetArraySize(param_list); i++)
		{
			cJSON* param = cJSON_GetArrayItem(param_list, i);
			if (cJSON_IsString(param) && param->valuestring)
			{
				data.params.push_back(param->valuestring);
			}
		}

		std::string cls = class_name->valuestring;
		std::string iface = interface->valuestring;

		if (cls == "Info")
		{
			if (iface == "GetBasicInfo")
			{
				data.type = RequestType::Info_GetBasicInfo;
				msg("[Parsing Request] Retrieving basic information\n");
			}
			else if (iface == "GetImageInfo")
			{
				data.type = RequestType::Info_GetImageInfo;
				msg("[Parsing Request] Retrieving image metadata\n");
			}
		}

		if (cls == "Function")
		{
			if (iface == "GetFunction")
			{
				data.type = RequestType::Function_GetFunction;
				msg("[Parsing Request] Fetching function details\n");
			}
			else if (iface == "GetFunctionInfo")
			{
				data.type = RequestType::Function_GetFunctionInfo;
				msg("[Parsing Request] Getting function properties\n");
			}
			else if (iface == "GetFunctionCount")
			{
				data.type = RequestType::Function_GetFunctionCount;
				msg("[Parsing Request] Counting total functions\n");
			}
			else if (iface == "GetFunctionByAddr")
			{
				data.type = RequestType::Function_GetFunctionByAddr;
				msg("[Parsing Request] Locating function by address\n");
			}
			else if (iface == "GetFunctionByName")
			{
				data.type = RequestType::Function_GetFunctionByName;
				msg("[Parsing Request] Finding function by name\n");
			}
			else if (iface == "FindFunctionByName")
			{
				data.type = RequestType::Function_FindFunctionByName;
				msg("[Parsing Request] Searching function by name pattern\n");
			}
			else if (iface == "GetImportFunctions")
			{
				data.type = RequestType::Function_GetImportFunctions;
				msg("[Parsing Request] Retrieving imported functions list\n");
			}
		}

		if (cls == "Segment")
		{
			if (iface == "GetSegmentCount")
			{
				data.type = RequestType::Segment_GetSegmentCount;
				msg("[Parsing Request] Counting binary segments\n");
			}
			else if (iface == "GetSegment")
			{
				data.type = RequestType::Segment_GetSegment;
				msg("[Parsing Request] Fetching segment details\n");
			}
			else if (iface == "GetSegmentFromAddr")
			{
				data.type = RequestType::Segment_GetSegmentFromAddr;
				msg("[Parsing Request] Locating segment by address\n");
			}
		}

		if (cls == "Reverse")
		{
			if (iface == "GetMicroCode")
			{
				data.type = RequestType::Reverse_GetMicroCode;
				msg("[Parsing Request] Extracting microcode instructions\n");
			}
			else if (iface == "DeompileChecked")
			{
				data.type = RequestType::Reverse_DeompileChecked;
				msg("[Parsing Request] Decompiling selected items\n");
			}
			else if (iface == "DecompileFunctionFromAddr")
			{
				data.type = RequestType::Reverse_DecompileFunctionFromAddr;
				msg("[Parsing Request] Decompiling function from address\n");
			}
			else if (iface == "DecompileFunctionFromName")
			{
				data.type = RequestType::Reverse_DecompileFunctionFromName;
				msg("[Parsing Request] Decompiling function from name\n");
			}
			else if (iface == "DisassembleFunction")
			{
				data.type = RequestType::Reverse_DisassembleFunction;
				msg("[Parsing Request] Disassembling function instructions\n");
			}
			else if (iface == "DisassemblyCount")
			{
				data.type = RequestType::Reverse_DisassemblyCount;
				msg("[Parsing Request] Counting disassembly entries\n");
			}
			else if (iface == "DisassemblyRange")
			{
				data.type = RequestType::Reverse_DisassemblyRange;
				msg("[Parsing Request] Disassembling address range\n");
			}
			else if (iface == "DecompileAddressToLine")
			{
				data.type = RequestType::Reverse_DecompileAddressToLine;
				msg("[Parsing Request] Mapping address to source line\n");
			}
			else if (iface == "DecompileLineToAddress")
			{
				data.type = RequestType::Reverse_DecompileLineToAddress;
				msg("[Parsing Request] Mapping source line to address\n");
			}
			else if (iface == "GetSelectDecompile")
			{
				data.type = RequestType::Reverse_GetSelectDecompile;
				msg("[Parsing Request] Reverse GetSelectDecompile\n");
			}
			else if (iface == "GetSelectDisassembly")
			{
				data.type = RequestType::Reverse_GetSelectDisassembly;
				msg("[Parsing Request] Reverse GetSelectDisassembly\n");
			}
			else if (iface == "GetSelectHex")
			{
				data.type = RequestType::Reverse_GetSelectHex;
				msg("[Parsing Request] Reverse GetSelectHex\n");
			}
		}

		if (cls == "Memory")
		{
			if (iface == "GetEntryPoints")
			{
				data.type = RequestType::Memory_GetEntryPoints;
				msg("[Parsing Request] Retrieving program entry points\n");
			}
			else if (iface == "GetDefinedStruct")
			{
				data.type = RequestType::Memory_GetDefinedStruct;
				msg("[Parsing Request] Fetching defined data structures\n");
			}
			else if (iface == "GetMemoryBytes")
			{
				data.type = RequestType::Memory_GetMemoryBytes;
				msg("[Parsing Request] Reading memory byte sequence\n");
			}
			else if (iface == "GetMemoryByte")
			{
				data.type = RequestType::Memory_GetMemoryByte;
				msg("[Parsing Request] Reading single memory byte\n");
			}
			else if (iface == "GetMemoryWord")
			{
				data.type = RequestType::Memory_GetMemoryWord;
				msg("[Parsing Request] Reading memory word (16-bit)\n");
			}
			else if (iface == "GetMemoryDword")
			{
				data.type = RequestType::Memory_GetMemoryDword;
				msg("[Parsing Request] Reading memory dword (32-bit)\n");
			}
			else if (iface == "GetMemoryQword")
			{
				data.type = RequestType::Memory_GetMemoryQword;
				msg("[Parsing Request] Reading memory qword (64-bit)\n");
			}
			else if (iface == "GetStringInfo")
			{
				data.type = RequestType::Memory_GetStringInfo;
				msg("[Parsing Request] Retrieving string details from memory\n");
			}
			else if (iface == "MemorySearch")
			{
				data.type = RequestType::Memory_MemorySearch;
				msg("[Parsing Request] Searching for pattern in memory\n");
			}
			else if (iface == "GetTypeByName")
			{
				data.type = RequestType::Memory_GetTypeByName;
				msg("[Parsing Request] Finding type by name\n");
			}
			else if (iface == "XrefCodeFirstTo")
			{
				data.type = RequestType::Memory_XrefCodeFirstTo;
				msg("[Parsing Request] Getting first code reference to address\n");
			}
			else if (iface == "XrefCodeFirstFrom")
			{
				data.type = RequestType::Memory_XrefCodeFirstFrom;
				msg("[Parsing Request] Getting first code reference from address\n");
			}
			else if (iface == "XrefDataFirstTo")
			{
				data.type = RequestType::Memory_XrefDataFirstTo;
				msg("[Parsing Request] Getting first data reference to address\n");
			}
			else if (iface == "XrefDataFirstFrom")
			{
				data.type = RequestType::Memory_XrefDataFirstFrom;
				msg("[Parsing Request] Getting first data reference from address\n");
			}
			else if (iface == "XrefCodeToArray")
			{
				data.type = RequestType::Memory_XrefCodeToArray;
				msg("[Parsing Request] Getting first data reference from address\n");
			}
			else if (iface == "XrefCodeFromArray")
			{
				data.type = RequestType::Memory_XrefCodeFromArray;
				msg("[Parsing Request] Getting first data reference from address\n");
			}
			else if (iface == "XrefDataToArray")
			{
				data.type = RequestType::Memory_XrefDataToArray;
				msg("[Parsing Request] Getting first data reference from address\n");
			}
			else if (iface == "XrefDataFromArray")
			{
				data.type = RequestType::Memory_XrefDataFromArray;
				msg("[Parsing Request] Getting first data reference from address\n");
			}
			else if (iface == "XrefGetListArray")
			{
				data.type = RequestType::Memory_XrefGetListArray;
				msg("[Parsing Request] Getting XrefGetListArray\n");
			}
		}

		if (cls == "Other")
		{
			if (iface == "SetAssemblyComment")
			{
				data.type = RequestType::Other_SetAssemblyComment;
				msg("[Parsing Request] Setting comment for Assembly\n");
			}
			else if (iface == "SetFunctionComment")
			{
				data.type = RequestType::Other_SetFunctionComment;
				msg("[Parsing Request] Setting comment for function\n");
			}
			else if (iface == "GetFunctionName")
			{
				data.type = RequestType::Other_GetFunctionName;
				msg("[Parsing Request] Retrieving function name\n");
			}
			else if (iface == "SetFunctionName")
			{
				data.type = RequestType::Other_SetFunctionName;
				msg("[Parsing Request] Renaming function\n");
			}
			else if (iface == "GetFunctionVarName")
			{
				data.type = RequestType::Other_GetFunctionVarName;
				msg("[Parsing Request] Retrieving function variable name\n");
			}
			else if (iface == "SetFunctionVarName")
			{
				data.type = RequestType::Other_SetFunctionVarName;
				msg("[Parsing Request] Renaming function variable\n");
			}
			else if (iface == "SwitchPseudoCodeTo")
			{
				data.type = RequestType::Other_SwitchPseudoCodeTo;
				msg("[Parsing Request] Switching to pseudocode view\n");
			}
			else if (iface == "GetStructMemberName")
			{
				data.type = RequestType::Other_GetStructMemberName;
				msg("[Parsing Request] GetStructMemberName\n");
			}
			else if (iface == "SetStructMemberName")
			{
				data.type = RequestType::Other_SetStructMemberName;
				msg("[Parsing Request] SetStructMemberName\n");
			}
			else if (iface == "GetCurrentSelect")
			{
				data.type = RequestType::Other_GetCurrentSelect;
				msg("[Parsing Request] GetCurrentSelect\n");
			}
		}

		return data;
	}
};

class DebuggerHandler
{
private:
	static const char* filetype_to_str(filetype_t ft)
	{
		switch (ft)
		{
		case f_EXE_old: return "MS DOS EXE File (old)";
		case f_COM_old: return "MS DOS COM File (old)";
		case f_BIN: return "Binary File";
		case f_DRV: return "MS DOS Driver";
		case f_WIN: return "New Executable (NE)";
		case f_HEX: return "Intel Hex Object File";
		case f_MEX: return "MOS Technology Hex Object File";
		case f_LX: return "Linear Executable (LX)";
		case f_LE: return "Linear Executable (LE)";
		case f_NLM: return "Netware Loadable Module (NLM)";
		case f_COFF: return "Common Object File Format (COFF)";
		case f_PE: return "Portable Executable (PE)";
		case f_OMF: return "Object Module Format";
		case f_SREC: return "Motorola SREC (S-record)";
		case f_ZIP: return "ZIP file";
		case f_OMFLIB: return "Library of OMF Modules";
		case f_AR: return "ar library";
		case f_LOADER: return "File loaded using LOADER DLL";
		case f_ELF: return "Executable and Linkable Format (ELF)";
		case f_W32RUN: return "Watcom DOS32 Extender (W32RUN)";
		case f_AOUT: return "Linux a.out (AOUT)";
		case f_PRC: return "PalmPilot program file";
		case f_EXE: return "MS DOS EXE File";
		case f_COM: return "MS DOS COM File";
		case f_AIXAR: return "AIX ar library";
		case f_MACHO: return "Mac OS X Mach-O";
		case f_PSXOBJ: return "Sony Playstation PSX object file";
		case f_MD1IMG: return "Mediatek Firmware Image";
		default: return "Unknown file type";
		}
	}

	static const char* ostype_to_str(uint16_t ostype)
	{
		switch (ostype)
		{
		case 0:  return "Unknown OS";
		case 1:  return "DOS";
		case 2:  return "Windows 16-bit";
		case 3:  return "Windows 32-bit";
		case 4:  return "Windows 64-bit";
		case 5:  return "Linux";
		case 6:  return "macOS";
		case 7:  return "Solaris";
		case 8:  return "FreeBSD";
		case 9:  return "NetBSD";
		case 10: return "OpenBSD";
		case 11: return "VXworks";
		case 12: return "QNX";
		case 13: return "Android";
		case 14: return "iOS";
		default: return "Unknown OS type";
		}
	}

	static const char* apptype_to_str(uint16_t apptype)
	{
		switch (apptype)
		{
		case 0:  return "Unknown Application";
		case 1:  return "Console Application";
		case 2:  return "GUI Application";
		case 3:  return "Dynamic Link Library (DLL)";
		case 4:  return "System Driver";
		case 5:  return "Kernel Module";
		case 6:  return "Static Library";
		case 7:  return "Object File";
		case 8:  return "Boot Loader";
		default: return "Unknown application type";
		}
	}

	static const char* asmtype_to_str(uint8_t asmtype)
	{
		switch (asmtype)
		{
		case 0:  return "Intel Syntax";
		case 1:  return "AT&T Syntax";
		case 2:  return "MASM (Microsoft Assembler)";
		case 3:  return "TASM (Turbo Assembler)";
		case 4:  return "GAS (GNU Assembler)";
		case 5:  return "ARM Assembler";
		case 6:  return "PowerPC Assembler";
		case 7:  return "MIPS Assembler";
		default: return "Unknown assembler type";
		}
	}

	typedef struct
	{
		uint16_t version;
		char procname[IDAINFO_PROCNAME_SIZE];
		uint16_t genflags;
		bool auto_enabled;
		bool use_allasm;
		bool loading_idc;
		bool no_store_user_info;
		bool readonly_idb;
		bool check_manual_ops;
		bool allow_non_matched_ops;
		bool is_graph_view;
		uint32_t lflags;
		bool decode_fpp;
		bool is_32bit_or_higher;
		bool is_32bit_exactly;
		bool is_16bit;
		bool is_64bit;
		bool is_ilp32;
		bool is_dll;
		bool is_flat_off32;
		bool is_be;
		bool is_wide_high_byte_first;
		bool dbg_no_store_path;
		bool is_snapshot;
		bool pack_idb;
		bool compress_idb;
		bool is_kernel_mode;
		uint8_t app_bitness;
		uint32_t database_change_count;
		filetype_t filetype;
		uint16_t ostype;
		uint16_t apptype;
		uint8_t asmtype;
		uint8_t specsegs;
		uint32_t af;
		bool trace_flow;
		bool mark_code;
		bool create_jump_tables;
		bool noflow_to_data;
		bool create_all_xrefs;
		bool del_no_xref_insns;
		bool create_func_from_ptr;
		bool create_func_from_call;
		bool create_func_tails;
		bool should_create_stkvars;
		bool propagate_stkargs;
		bool propagate_regargs;
		bool should_trace_sp;
	} program_info_t;

	static std::string md5_to_string(const unsigned char md5[16])
	{
		const std::string hex_digits = "0123456789abcdef";
		std::string result;
		result.reserve(32);
		for (int i = 0; i < 16; ++i)
		{
			unsigned char byte = md5[i];
			result += hex_digits[(byte >> 4) & 0x0F];
			result += hex_digits[byte & 0x0F];
		}
		return result;
	}

	static std::string bytes_to_hex(const uint8_t* data, size_t len)
	{
		std::stringstream ss;
		ss << std::hex << std::setfill('0');
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << static_cast<uint32_t>(data[i]);
		}
		return ss.str();
	}

	static std::string timestamp_to_str(uint32_t timestamp)
	{
		time_t t = timestamp;
		struct tm* tm = localtime(&t);
		char buf[64];
		strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", tm);
		return buf;
	}

	static std::string bin_to_hex(const void* data, size_t len)
	{
		const uint8_t* bytes = static_cast<const uint8_t*>(data);
		std::stringstream ss;
		ss << std::hex << std::setfill('0');
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << static_cast<uint32_t>(bytes[i]);
		}
		return ss.str();
	}

	static const char* get_inf_str(inftag_t tag)
	{
		uint64 val = getinf(tag);
		return val != 0 ? reinterpret_cast<const char*>(val) : "N/A";
	}

	static void init_program_info(program_info_t* info)
	{
		if (info == NULL)
			return;
		memset(info, 0, sizeof(program_info_t));
	}

	static bool get_full_program_info(program_info_t* info)
	{
		if (info == NULL)
			return false;
		init_program_info(info);

		info->version = inf_get_version();
		getinf_buf(INF_PROCNAME, info->procname, IDAINFO_PROCNAME_SIZE);
		info->genflags = inf_get_genflags();
		info->auto_enabled = inf_is_auto_enabled();
		info->use_allasm = inf_use_allasm();
		info->loading_idc = inf_loading_idc();
		info->no_store_user_info = inf_no_store_user_info();
		info->readonly_idb = inf_readonly_idb();
		info->check_manual_ops = inf_check_manual_ops();
		info->allow_non_matched_ops = inf_allow_non_matched_ops();
		info->is_graph_view = inf_is_graph_view();
		info->lflags = inf_get_lflags();
		info->decode_fpp = inf_decode_fpp();
		info->is_32bit_or_higher = inf_is_32bit_or_higher();
		info->is_32bit_exactly = inf_is_32bit_exactly();
		info->is_16bit = inf_is_16bit();
		info->is_64bit = inf_is_64bit();
		info->is_ilp32 = inf_is_ilp32();
		info->is_dll = inf_is_dll();
		info->is_flat_off32 = inf_is_flat_off32();
		info->is_be = inf_is_be();
		info->is_wide_high_byte_first = inf_is_wide_high_byte_first();
		info->dbg_no_store_path = inf_dbg_no_store_path();
		info->is_snapshot = inf_is_snapshot();
		info->pack_idb = inf_pack_idb();
		info->compress_idb = inf_compress_idb();
		info->is_kernel_mode = inf_is_kernel_mode();
		info->app_bitness = inf_get_app_bitness();
		info->database_change_count = inf_get_database_change_count();
		info->filetype = inf_get_filetype();
		info->ostype = inf_get_ostype();
		info->apptype = inf_get_apptype();
		info->asmtype = inf_get_asmtype();
		info->specsegs = inf_get_specsegs();
		info->af = inf_get_af();
		info->trace_flow = inf_trace_flow();
		info->mark_code = inf_mark_code();
		info->create_jump_tables = inf_create_jump_tables();
		info->noflow_to_data = inf_noflow_to_data();
		info->create_all_xrefs = inf_create_all_xrefs();
		info->del_no_xref_insns = inf_del_no_xref_insns();
		info->create_func_from_ptr = inf_create_func_from_ptr();
		info->create_func_from_call = inf_create_func_from_call();
		info->create_func_tails = inf_create_func_tails();
		info->should_create_stkvars = inf_should_create_stkvars();
		info->propagate_stkargs = inf_propagate_stkargs();
		info->propagate_regargs = inf_propagate_regargs();
		info->should_trace_sp = inf_should_trace_sp();
		return true;
	}

	static void add_inftag_json(cJSON* parent_obj)
	{
		cJSON* inftag_obj = cJSON_CreateObject();
		for (int tag = INF_VERSION; tag < INF_LAST; ++tag)
		{
			inftag_t inf_tag = static_cast<inftag_t>(tag);
			uint64 val = getinf(inf_tag);
			std::string name = { 0 };
			std::string value = { 0 };
			std::stringstream ss;

			switch (inf_tag)
			{
			case INF_VERSION:         name = "INF_VERSION";         value = std::to_string(val); break;
			case INF_PROCNAME:        name = "INF_PROCNAME";        value = get_inf_str(inf_tag); break;
			case INF_GENFLAGS:        name = "INF_GENFLAGS";        ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_LFLAGS:          name = "INF_LFLAGS";          ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_DATABASE_CHANGE_COUNT: name = "INF_DATABASE_CHANGE_COUNT"; value = std::to_string(val); break;
			case INF_FILETYPE:        name = "INF_FILETYPE";        value = std::to_string(val); break;
			case INF_OSTYPE:          name = "INF_OSTYPE";          value = std::to_string(val); break;
			case INF_APPTYPE:         name = "INF_APPTYPE";         value = std::to_string(val); break;
			case INF_ASMTYPE:         name = "INF_ASMTYPE";         value = std::to_string(val); break;
			case INF_SPECSEGS:        name = "INF_SPECSEGS";        value = std::to_string(val); break;
			case INF_AF:              name = "INF_AF";              ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_BASEADDR:        name = "INF_BASEADDR";        ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_START_EA:        name = "INF_START_EA";        ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_MIN_EA:          name = "INF_MIN_EA";          ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_MAX_EA:          name = "INF_MAX_EA";          ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_IMAGEBASE:       name = "INF_IMAGEBASE";       ss << "0x" << std::hex << val; value = ss.str(); break;
			case INF_FSIZE:           name = "INF_FSIZE";           value = std::to_string(val) + " bytes"; break;
			case INF_INPUT_FILE_PATH: name = "INF_INPUT_FILE_PATH"; value = get_inf_str(inf_tag); break;
			case INF_IDA_VERSION:     name = "INF_IDA_VERSION";     value = get_inf_str(inf_tag); break;
			default:
				name = "UNKNOWN_TAG_" + std::to_string(tag);
				ss << "0x" << std::hex << val;
				value = ss.str();
				break;
			}

			cJSON_AddStringToObject(inftag_obj, name.c_str(), value.c_str());
		}
		cJSON_AddItemToObject(parent_obj, "inftag_info", inftag_obj);
	}

public:
	static ResponseData handle_get_basic_info(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for basic info request");
			response.success = false;
			return response;
		}

		program_info_t prog_info;
		if (!get_full_program_info(&prog_info))
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to retrieve program basic information");
			response.success = false;
			return response;
		}

		cJSON* basic_info = cJSON_CreateObject();
		cJSON_AddNumberToObject(basic_info, "database_version", prog_info.version);
		cJSON_AddStringToObject(basic_info, "processor_name", prog_info.procname);
		cJSON_AddNumberToObject(basic_info, "raw_genflags", prog_info.genflags);
		cJSON_AddBoolToObject(basic_info, "auto_analysis_enabled", prog_info.auto_enabled);
		cJSON_AddBoolToObject(basic_info, "is_idb_readonly", prog_info.readonly_idb);
		cJSON_AddBoolToObject(basic_info, "current_view_is_graph", prog_info.is_graph_view);
		cJSON_AddItemToObject(response.result.get(), "basic_version_info", basic_info);

		cJSON* bitness_info = cJSON_CreateObject();
		cJSON_AddNumberToObject(bitness_info, "app_bitness", prog_info.app_bitness);
		cJSON_AddBoolToObject(bitness_info, "is_16bit", prog_info.is_16bit);
		cJSON_AddBoolToObject(bitness_info, "is_32bit", prog_info.is_32bit_exactly);
		cJSON_AddBoolToObject(bitness_info, "is_64bit", prog_info.is_64bit);
		cJSON_AddBoolToObject(bitness_info, "is_dll", prog_info.is_dll);
		cJSON_AddBoolToObject(bitness_info, "is_kernel_mode", prog_info.is_kernel_mode);
		cJSON_AddBoolToObject(bitness_info, "is_big_endian", prog_info.is_be);
		cJSON_AddItemToObject(response.result.get(), "bitness_attr_info", bitness_info);

		cJSON* file_info = cJSON_CreateObject();
		cJSON_AddStringToObject(file_info, "file_type", filetype_to_str(prog_info.filetype));
		cJSON_AddNumberToObject(file_info, "file_type_code", prog_info.filetype);
		cJSON_AddStringToObject(file_info, "os_type", ostype_to_str(prog_info.ostype));
		cJSON_AddStringToObject(file_info, "app_type", apptype_to_str(prog_info.apptype));
		cJSON_AddStringToObject(file_info, "assembler_type", asmtype_to_str(prog_info.asmtype));
		cJSON_AddNumberToObject(file_info, "database_change_count", prog_info.database_change_count);
		cJSON_AddItemToObject(response.result.get(), "file_system_info", file_info);

		cJSON* analysis_info = cJSON_CreateObject();
		cJSON_AddNumberToObject(analysis_info, "raw_analysis_flags", prog_info.af);
		cJSON_AddBoolToObject(analysis_info, "trace_exec_flow", prog_info.trace_flow);
		cJSON_AddBoolToObject(analysis_info, "create_jump_tables", prog_info.create_jump_tables);
		cJSON_AddBoolToObject(analysis_info, "create_stack_vars", prog_info.should_create_stkvars);
		cJSON_AddBoolToObject(analysis_info, "trace_stack_pointer", prog_info.should_trace_sp);
		cJSON_AddItemToObject(response.result.get(), "analysis_config_info", analysis_info);

		add_inftag_json(response.result.get());

		cJSON* hash_info = cJSON_CreateObject();

		unsigned char md5[16] = { 0 };
		if (retrieve_input_file_md5(md5))
		{
			cJSON_AddStringToObject(hash_info, "md5", md5_to_string(md5).c_str());
		}
		else
		{
			cJSON_AddStringToObject(hash_info, "md5", "Failed to retrieve");
		}

		uint32_t crc32 = retrieve_input_file_crc32();
		std::stringstream crc32_ss;
		crc32_ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc32;
		std::string crc32_str = crc32_ss.str();
		cJSON_AddStringToObject(hash_info, "crc32", crc32_str.c_str());

		unsigned char sha256[32] = { 0 };
		if (retrieve_input_file_sha256(sha256))
		{
			cJSON_AddStringToObject(hash_info, "sha256", bytes_to_hex(sha256, 32).c_str());
		}
		else
		{
			cJSON_AddStringToObject(hash_info, "sha256", "Failed to retrieve");
		}
		cJSON_AddItemToObject(response.result.get(), "input_file_hash", hash_info);

		cJSON* statistical_info = cJSON_CreateObject();

		char finam[64] = { 0 };
		get_root_filename(finam, sizeof(finam));
		std::string filename = (finam[0] != '\0') ? finam : "Unknown";
		std::string file_ext = get_file_ext(finam);
		if (file_ext.empty()) file_ext = "Unknown";

		cJSON_AddStringToObject(statistical_info, "database_filename", filename.c_str());
		cJSON_AddStringToObject(statistical_info, "file_extension", file_ext.c_str());

		size_t dbctx_count = get_dbctx_qty();
		cJSON_AddNumberToObject(statistical_info, "dbctx_count", dbctx_count);

		int encoding_count = get_encoding_qty();
		cJSON_AddNumberToObject(statistical_info, "supported_encoding_count", encoding_count);

		int seg_count = get_segm_qty();
		cJSON_AddNumberToObject(statistical_info, "program_segment_count", seg_count);

		int func_count = get_func_qty();
		cJSON_AddNumberToObject(statistical_info, "recognized_function_count", func_count);

		int import_module_count = get_import_module_qty();
		cJSON_AddNumberToObject(statistical_info, "imported_module_count", import_module_count);

		int fchunk_count = get_fchunk_qty();
		cJSON_AddNumberToObject(statistical_info, "function_chunk_count", fchunk_count);

		int hidden_count = get_hidden_range_qty();
		cJSON_AddNumberToObject(statistical_info, "hidden_range_count", hidden_count);

		int idasgn_count = get_idasgn_qty();
		cJSON_AddNumberToObject(statistical_info, "ida_assigned_symbol_count", idasgn_count);

		size_t mapping_count = get_mappings_qty();
		cJSON_AddNumberToObject(statistical_info, "memory_mapping_count", mapping_count);

		int thread_count = get_thread_qty();
		cJSON_AddNumberToObject(statistical_info, "thread_count", thread_count);

		cJSON_AddItemToObject(response.result.get(), "statistical_info", statistical_info);

		response.success = true;
		return response;
	}

	static ResponseData handle_get_image_info(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for image info request");
			response.success = false;
			return response;
		}

		ea_t omin_ea = inf_get_omin_ea();
		ea_t omax_ea = inf_get_omax_ea();
		ea_t image_size = omax_ea - omin_ea;

		cJSON_AddNumberToObject(response.result.get(), "omin_ea", omin_ea);
		cJSON_AddNumberToObject(response.result.get(), "omax_ea", omax_ea);
		cJSON_AddNumberToObject(response.result.get(), "image_size", image_size);
		cJSON_AddStringToObject(response.result.get(), "omin_ea_hex", ("0x" + Tools::decToHex(omin_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "omax_ea_hex", ("0x" + Tools::decToHex(omax_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "image_size_hex", ("0x" + Tools::decToHex(image_size)).c_str());

		response.success = true;
		return response;
	}
};

class FunctionHandler
{
private:
	struct import_func_t
	{
		ea_t ea;
		std::string name;
		uval_t ord;
		import_func_t(ea_t e, const char* n, uval_t o) : ea(e), name(n ? n : ""), ord(o) {}
	};

	struct module_import_data_t
	{
		int module_idx;
		std::string module_name;
		std::vector<import_func_t> functions;

		module_import_data_t(int idx, const char* name) : module_idx(idx), module_name(name ? name : "") {}
	};

	static int idaapi import_callback(ea_t ea, const char* name, uval_t ord, void* user_data)
	{
		if (user_data == nullptr) return false;
		module_import_data_t* data = static_cast<module_import_data_t*>(user_data);
		data->functions.emplace_back(ea, name, ord);
		return true;
	}

public:
	static ResponseData handle_get_function(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected");
			response.success = false;
			return response;
		}

		cJSON* functions = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "functions", functions);

		for (int f = 0; f < get_func_qty(); f++)
		{
			func_t* curFunc = getn_func(f);
			if (curFunc == nullptr)
				continue;

			cJSON* func_obj = cJSON_CreateObject();

			qstring funcName = { 0 };
			get_func_name(&funcName, curFunc->start_ea);

			cJSON_AddNumberToObject(func_obj, "index", f);
			cJSON_AddStringToObject(func_obj, "name", funcName.c_str());
			cJSON_AddNumberToObject(func_obj, "start_address", curFunc->start_ea);
			cJSON_AddStringToObject(func_obj, "start_address_hex", ("0x" + Tools::decToHex(curFunc->start_ea)).c_str());
			cJSON_AddNumberToObject(func_obj, "end_address", curFunc->start_ea + calc_func_size(curFunc));
			cJSON_AddStringToObject(func_obj, "end_address_hex", ("0x" + Tools::decToHex(curFunc->start_ea + (ea_t)calc_func_size(curFunc))).c_str());
			cJSON_AddBoolToObject(func_obj, "is_entry", is_func_entry(curFunc));
			cJSON_AddBoolToObject(func_obj, "is_tail", is_func_tail(curFunc));
			cJSON_AddNumberToObject(func_obj, "bitness", get_func_bits(curFunc));
			cJSON_AddNumberToObject(func_obj, "total_size", calc_func_size(curFunc));
			cJSON_AddBoolToObject(func_obj, "visible", is_visible_func(curFunc));
			cJSON_AddBoolToObject(func_obj, "returns", func_does_return(curFunc->start_ea));

			cJSON* flags_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(flags_obj, "raw_value", curFunc->flags);
			cJSON_AddBoolToObject(flags_obj, "FUNC_NORET", (curFunc->flags & FUNC_NORET) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_FAR", (curFunc->flags & FUNC_FAR) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_LIB", (curFunc->flags & FUNC_LIB) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_STATICDEF", (curFunc->flags & FUNC_STATICDEF) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_FRAME", (curFunc->flags & FUNC_FRAME) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_THUNK", (curFunc->flags & FUNC_THUNK) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_SP_READY", (curFunc->flags & FUNC_SP_READY) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_PROLOG_OK", (curFunc->flags & FUNC_PROLOG_OK) != 0);
			cJSON_AddItemToObject(func_obj, "flags", flags_obj);

			if (is_func_entry(curFunc))
			{
				cJSON* frame_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(frame_obj, "frame_netnode", curFunc->frame);
				cJSON_AddNumberToObject(frame_obj, "local_vars_size", curFunc->frsize);
				cJSON_AddNumberToObject(frame_obj, "saved_regs_size", curFunc->frregs);
				cJSON_AddNumberToObject(frame_obj, "args_size", curFunc->argsize);
				cJSON_AddNumberToObject(frame_obj, "frame_delta", curFunc->fpd);
				cJSON_AddNumberToObject(frame_obj, "color", curFunc->color);
				cJSON_AddItemToObject(func_obj, "frame_info", frame_obj);
			}

			if (curFunc->regargqty > 0)
			{
				cJSON* regargs_array = cJSON_CreateArray();
				for (int i = 0; i < curFunc->regargqty; i++)
				{
					regarg_t* ra = &curFunc->regargs[i];
					cJSON* ra_obj = cJSON_CreateObject();

					cJSON_AddNumberToObject(ra_obj, "index", i);
					cJSON_AddNumberToObject(ra_obj, "reg", ra->reg);
					cJSON_AddStringToObject(ra_obj, "type", ra->type ? (char*)ra->type : "Unknown");
					cJSON_AddStringToObject(ra_obj, "name", ra->name ? ra->name : "Unnamed");

					cJSON_AddItemToArray(regargs_array, ra_obj);
				}
				cJSON_AddItemToObject(func_obj, "register_arguments", regargs_array);
			}

			if (curFunc->llabelqty > 0)
			{
				cJSON_AddNumberToObject(func_obj, "local_labels_count", curFunc->llabelqty);
			}

			if (is_func_entry(curFunc) && curFunc->tailqty > 0)
			{
				cJSON* tails_array = cJSON_CreateArray();
				func_tail_iterator_t fti(curFunc);
				for (bool ok = fti.first(); ok; ok = fti.next())
				{
					const range_t& tail = fti.chunk();
					cJSON* tail_obj = cJSON_CreateObject();

					cJSON_AddNumberToObject(tail_obj, "start", tail.start_ea);
					cJSON_AddStringToObject(tail_obj, "start_hex", ("0x" + Tools::decToHex(tail.start_ea)).c_str());
					cJSON_AddNumberToObject(tail_obj, "end", tail.end_ea);
					cJSON_AddStringToObject(tail_obj, "end_hex", ("0x" + Tools::decToHex(tail.end_ea)).c_str());
					cJSON_AddItemToArray(tails_array, tail_obj);
				}
				cJSON_AddItemToObject(func_obj, "function_tails", tails_array);
			}

			if (is_func_tail(curFunc) && curFunc->refqty > 0)
			{
				cJSON* referrers_array = cJSON_CreateArray();
				func_parent_iterator_t fpi(curFunc);
				for (bool ok = fpi.first(); ok; ok = fpi.next())
				{
					ea_t parent_ea = fpi.parent();
					qstring parent_name = { 0 };
					get_func_name(&parent_name, parent_ea);

					cJSON* ref_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(ref_obj, "address", parent_ea);
					cJSON_AddStringToObject(ref_obj, "address_hex", ("0x" + Tools::decToHex(parent_ea)).c_str());
					cJSON_AddStringToObject(ref_obj, "name", parent_name.c_str());

					cJSON_AddItemToArray(referrers_array, ref_obj);
				}
				cJSON_AddItemToObject(func_obj, "referrers", referrers_array);
			}
			cJSON_AddItemToArray(functions, func_obj);
		}
		response.success = true;
		return response;
	}

	static ResponseData handle_get_function_info(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Function address (hex string) is required as parameter");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format (support decimal/hex like 0x401000)");
			response.success = false;
			return response;
		}

		func_t* func = get_func(func_ea);
		if (func == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No function found at the specified address");
			response.success = false;
			return response;
		}

		ea_t func_start_ea = func->start_ea;
		ea_t func_end_ea = func_start_ea + calc_func_size(func);
		ea_t func_size = func_end_ea - func_start_ea;
		uval_t frame_id = func->frame;
		asize_t local_vars_size = func->frsize;
		ushort saved_regs_size = func->frregs;
		asize_t purged_args_size = func->argsize;
		asize_t frame_ptr_delta = func->fpd;
		uint32 sp_change_count = func->pntqty;
		int reg_var_count = func->regvarqty;
		int reg_arg_count = func->regargqty;
		int tail_count = func->tailqty;
		ea_t tail_owner = func->owner;
		int tail_ref_count = func->refqty;
		bool is_far_func = func->is_far();
		bool func_returns = func->does_return();
		bool sp_analyzed = func->analyzed_sp();
		bool need_prolog_analysis = func->need_prolog_analysis();

		cJSON* func_info = cJSON_CreateObject();
		cJSON_AddNumberToObject(func_info, "start_address", func_start_ea);
		cJSON_AddStringToObject(func_info, "start_address_hex", ("0x" + Tools::decToHex(func_start_ea)).c_str());
		cJSON_AddNumberToObject(func_info, "end_address", func_end_ea);
		cJSON_AddStringToObject(func_info, "end_address_hex", ("0x" + Tools::decToHex(func_end_ea)).c_str());
		cJSON_AddNumberToObject(func_info, "size", func_size);
		cJSON_AddStringToObject(func_info, "size_hex", ("0x" + Tools::decToHex(func_size)).c_str());
		cJSON_AddNumberToObject(func_info, "frame_id", frame_id);
		cJSON_AddStringToObject(func_info, "frame_id_hex", ("0x" + Tools::decToHex(frame_id)).c_str());
		cJSON_AddNumberToObject(func_info, "local_vars_size_bytes", local_vars_size);
		cJSON_AddNumberToObject(func_info, "saved_regs_size_bytes", saved_regs_size);
		cJSON_AddNumberToObject(func_info, "purged_args_size_bytes", purged_args_size);
		cJSON_AddNumberToObject(func_info, "frame_ptr_delta", frame_ptr_delta);
		cJSON_AddNumberToObject(func_info, "sp_change_count", sp_change_count);
		cJSON_AddNumberToObject(func_info, "reg_var_count", reg_var_count);
		cJSON_AddNumberToObject(func_info, "reg_arg_count", reg_arg_count);
		cJSON_AddNumberToObject(func_info, "tail_count", tail_count);
		cJSON_AddNumberToObject(func_info, "tail_owner", tail_owner);
		cJSON_AddStringToObject(func_info, "tail_owner_hex", ("0x" + Tools::decToHex(tail_owner)).c_str());
		cJSON_AddNumberToObject(func_info, "tail_ref_count", tail_ref_count);
		cJSON_AddBoolToObject(func_info, "is_far_func", is_far_func);
		cJSON_AddBoolToObject(func_info, "returns", func_returns);
		cJSON_AddBoolToObject(func_info, "sp_analyzed", sp_analyzed);
		cJSON_AddBoolToObject(func_info, "need_prolog_analysis", need_prolog_analysis);

		qstring func_name = { 0 };
		get_func_name(&func_name, func_start_ea);
		cJSON_AddStringToObject(func_info, "name", func_name.c_str());
		cJSON_AddItemToObject(response.result.get(), "function_info", func_info);

		response.success = true;
		return response;
	}

	static ResponseData handle_get_function_count(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for function count request");
			response.success = false;
			return response;
		}

		int func_count = get_func_qty();

		cJSON_AddNumberToObject(response.result.get(), "total_functions", func_count);
		response.success = true;

		return response;
	}

	static ResponseData handle_get_function_by_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty() || params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Exactly 1 parameter (function start address) is required");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t func_start_addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format (support decimal/hex like 0x401000)");
			response.success = false;
			return response;
		}

		func_t* curFunc = get_func(func_start_addr);
		if (curFunc == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No function found at the specified start address");
			response.success = false;
			return response;
		}

		cJSON* func_obj = cJSON_CreateObject();
		qstring funcName = { 0 };
		get_func_name(&funcName, curFunc->start_ea);

		cJSON_AddStringToObject(func_obj, "name", funcName.c_str());
		cJSON_AddNumberToObject(func_obj, "start_address", curFunc->start_ea);
		cJSON_AddStringToObject(func_obj, "start_address_hex", ("0x" + Tools::decToHex(curFunc->start_ea)).c_str());
		cJSON_AddNumberToObject(func_obj, "end_address", curFunc->start_ea + calc_func_size(curFunc));
		cJSON_AddStringToObject(func_obj, "end_address_hex", ("0x" + Tools::decToHex(curFunc->start_ea + (ea_t)calc_func_size(curFunc))).c_str());
		cJSON_AddBoolToObject(func_obj, "is_entry", is_func_entry(curFunc));
		cJSON_AddBoolToObject(func_obj, "is_tail", is_func_tail(curFunc));
		cJSON_AddNumberToObject(func_obj, "bitness", get_func_bits(curFunc));
		cJSON_AddNumberToObject(func_obj, "total_size", calc_func_size(curFunc));
		cJSON_AddBoolToObject(func_obj, "visible", is_visible_func(curFunc));
		cJSON_AddBoolToObject(func_obj, "returns", func_does_return(curFunc->start_ea));

		cJSON* flags_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(flags_obj, "raw_value", curFunc->flags);
		cJSON_AddBoolToObject(flags_obj, "FUNC_NORET", (curFunc->flags & FUNC_NORET) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_FAR", (curFunc->flags & FUNC_FAR) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_LIB", (curFunc->flags & FUNC_LIB) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_STATICDEF", (curFunc->flags & FUNC_STATICDEF) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_FRAME", (curFunc->flags & FUNC_FRAME) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_THUNK", (curFunc->flags & FUNC_THUNK) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_SP_READY", (curFunc->flags & FUNC_SP_READY) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_PROLOG_OK", (curFunc->flags & FUNC_PROLOG_OK) != 0);
		cJSON_AddItemToObject(func_obj, "flags", flags_obj);

		if (is_func_entry(curFunc))
		{
			cJSON* frame_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(frame_obj, "frame_netnode", curFunc->frame);
			cJSON_AddNumberToObject(frame_obj, "local_vars_size", curFunc->frsize);
			cJSON_AddNumberToObject(frame_obj, "saved_regs_size", curFunc->frregs);
			cJSON_AddNumberToObject(frame_obj, "args_size", curFunc->argsize);
			cJSON_AddNumberToObject(frame_obj, "frame_delta", curFunc->fpd);
			cJSON_AddNumberToObject(frame_obj, "color", curFunc->color);
			cJSON_AddItemToObject(func_obj, "frame_info", frame_obj);
		}

		if (curFunc->regargqty > 0)
		{
			cJSON* regargs_array = cJSON_CreateArray();
			for (int i = 0; i < curFunc->regargqty; i++)
			{
				regarg_t* ra = &curFunc->regargs[i];
				cJSON* ra_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(ra_obj, "index", i);
				cJSON_AddNumberToObject(ra_obj, "reg", ra->reg);
				cJSON_AddStringToObject(ra_obj, "type", ra->type ? (char*)ra->type : "Unknown");
				cJSON_AddStringToObject(ra_obj, "name", ra->name ? ra->name : "Unnamed");
				cJSON_AddItemToArray(regargs_array, ra_obj);
			}
			cJSON_AddItemToObject(func_obj, "register_arguments", regargs_array);
		}

		if (curFunc->llabelqty > 0)
		{
			cJSON_AddNumberToObject(func_obj, "local_labels_count", curFunc->llabelqty);
		}

		if (is_func_entry(curFunc) && curFunc->tailqty > 0)
		{
			cJSON* tails_array = cJSON_CreateArray();
			func_tail_iterator_t fti(curFunc);
			for (bool ok = fti.first(); ok; ok = fti.next())
			{
				const range_t& tail = fti.chunk();
				cJSON* tail_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(tail_obj, "start", tail.start_ea);
				cJSON_AddStringToObject(tail_obj, "start_hex", ("0x" + Tools::decToHex(tail.start_ea)).c_str());
				cJSON_AddNumberToObject(tail_obj, "end", tail.end_ea);
				cJSON_AddStringToObject(tail_obj, "end_hex", ("0x" + Tools::decToHex(tail.end_ea)).c_str());
				cJSON_AddItemToArray(tails_array, tail_obj);
			}
			cJSON_AddItemToObject(func_obj, "function_tails", tails_array);
		}

		if (is_func_tail(curFunc) && curFunc->refqty > 0)
		{
			cJSON* referrers_array = cJSON_CreateArray();
			func_parent_iterator_t fpi(curFunc);
			for (bool ok = fpi.first(); ok; ok = fpi.next())
			{
				ea_t parent_ea = fpi.parent();
				qstring parent_name;
				get_func_name(&parent_name, parent_ea);
				cJSON* ref_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(ref_obj, "address", parent_ea);
				cJSON_AddStringToObject(ref_obj, "address_hex", ("0x" + Tools::decToHex(parent_ea)).c_str());
				cJSON_AddStringToObject(ref_obj, "name", parent_name.c_str());
				cJSON_AddItemToArray(referrers_array, ref_obj);
			}
			cJSON_AddItemToObject(func_obj, "referrers", referrers_array);
		}

		cJSON_AddItemToObject(response.result.get(), "function", func_obj);
		response.success = true;
		return response;
	}

	static ResponseData handle_get_function_by_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty() || params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Exactly 1 parameter (function name) is required");
			response.success = false;
			return response;
		}

		const std::string target_name = params[0];
		if (target_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Function name cannot be empty");
			response.success = false;
			return response;
		}

		func_t* found_func = nullptr;
		int found_index = -1;
		const int total_funcs = get_func_qty();

		for (int f = 0; f < total_funcs; f++)
		{
			func_t* curFunc = getn_func(f);
			if (curFunc == nullptr)
				continue;

			qstring funcName = { 0 };
			get_func_name(&funcName, curFunc->start_ea);

			if (funcName.length() > 0 && funcName == target_name.c_str())
			{
				found_func = curFunc;
				found_index = f;
				break;
			}
		}

		if (found_func == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No function found with the specified name");
			response.success = false;
			return response;
		}

		cJSON* func_obj = cJSON_CreateObject();
		qstring funcName = { 0 };
		get_func_name(&funcName, found_func->start_ea);

		cJSON_AddNumberToObject(func_obj, "index", found_index);
		cJSON_AddStringToObject(func_obj, "name", funcName.c_str());
		cJSON_AddNumberToObject(func_obj, "start_address", found_func->start_ea);
		cJSON_AddStringToObject(func_obj, "start_address_hex", ("0x" + Tools::decToHex(found_func->start_ea)).c_str());
		cJSON_AddNumberToObject(func_obj, "end_address", found_func->start_ea + calc_func_size(found_func));
		cJSON_AddStringToObject(func_obj, "end_address_hex", ("0x" + Tools::decToHex(found_func->start_ea + (ea_t)calc_func_size(found_func))).c_str());
		cJSON_AddBoolToObject(func_obj, "is_entry", is_func_entry(found_func));
		cJSON_AddBoolToObject(func_obj, "is_tail", is_func_tail(found_func));
		cJSON_AddNumberToObject(func_obj, "bitness", get_func_bits(found_func));
		cJSON_AddNumberToObject(func_obj, "total_size", calc_func_size(found_func));
		cJSON_AddBoolToObject(func_obj, "visible", is_visible_func(found_func));
		cJSON_AddBoolToObject(func_obj, "returns", func_does_return(found_func->start_ea));

		cJSON* flags_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(flags_obj, "raw_value", found_func->flags);
		cJSON_AddBoolToObject(flags_obj, "FUNC_NORET", (found_func->flags & FUNC_NORET) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_FAR", (found_func->flags & FUNC_FAR) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_LIB", (found_func->flags & FUNC_LIB) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_STATICDEF", (found_func->flags & FUNC_STATICDEF) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_FRAME", (found_func->flags & FUNC_FRAME) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_THUNK", (found_func->flags & FUNC_THUNK) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_SP_READY", (found_func->flags & FUNC_SP_READY) != 0);
		cJSON_AddBoolToObject(flags_obj, "FUNC_PROLOG_OK", (found_func->flags & FUNC_PROLOG_OK) != 0);
		cJSON_AddItemToObject(func_obj, "flags", flags_obj);

		if (is_func_entry(found_func))
		{
			cJSON* frame_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(frame_obj, "frame_netnode", found_func->frame);
			cJSON_AddNumberToObject(frame_obj, "local_vars_size", found_func->frsize);
			cJSON_AddNumberToObject(frame_obj, "saved_regs_size", found_func->frregs);
			cJSON_AddNumberToObject(frame_obj, "args_size", found_func->argsize);
			cJSON_AddNumberToObject(frame_obj, "frame_delta", found_func->fpd);
			cJSON_AddNumberToObject(frame_obj, "color", found_func->color);
			cJSON_AddItemToObject(func_obj, "frame_info", frame_obj);
		}

		if (found_func->regargqty > 0)
		{
			cJSON* regargs_array = cJSON_CreateArray();
			for (int i = 0; i < found_func->regargqty; i++)
			{
				regarg_t* ra = &found_func->regargs[i];
				cJSON* ra_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(ra_obj, "index", i);
				cJSON_AddNumberToObject(ra_obj, "reg", ra->reg);
				cJSON_AddStringToObject(ra_obj, "type", ra->type ? (char*)ra->type : "Unknown");
				cJSON_AddStringToObject(ra_obj, "name", ra->name ? ra->name : "Unnamed");
				cJSON_AddItemToArray(regargs_array, ra_obj);
			}
			cJSON_AddItemToObject(func_obj, "register_arguments", regargs_array);
		}

		if (found_func->llabelqty > 0)
		{
			cJSON_AddNumberToObject(func_obj, "local_labels_count", found_func->llabelqty);
		}

		if (is_func_entry(found_func) && found_func->tailqty > 0)
		{
			cJSON* tails_array = cJSON_CreateArray();
			func_tail_iterator_t fti(found_func);
			for (bool ok = fti.first(); ok; ok = fti.next())
			{
				const range_t& tail = fti.chunk();
				cJSON* tail_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(tail_obj, "start", tail.start_ea);
				cJSON_AddStringToObject(tail_obj, "start_hex", ("0x" + Tools::decToHex(tail.start_ea)).c_str());
				cJSON_AddNumberToObject(tail_obj, "end", tail.end_ea);
				cJSON_AddStringToObject(tail_obj, "end_hex", ("0x" + Tools::decToHex(tail.end_ea)).c_str());
				cJSON_AddItemToArray(tails_array, tail_obj);
			}
			cJSON_AddItemToObject(func_obj, "function_tails", tails_array);
		}

		if (is_func_tail(found_func) && found_func->refqty > 0)
		{
			cJSON* referrers_array = cJSON_CreateArray();
			func_parent_iterator_t fpi(found_func);
			for (bool ok = fpi.first(); ok; ok = fpi.next())
			{
				ea_t parent_ea = fpi.parent();
				qstring parent_name = { 0 };
				get_func_name(&parent_name, parent_ea);
				cJSON* ref_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(ref_obj, "address", parent_ea);
				cJSON_AddStringToObject(ref_obj, "address_hex", ("0x" + Tools::decToHex(parent_ea)).c_str());
				cJSON_AddStringToObject(ref_obj, "name", parent_name.c_str());
				cJSON_AddItemToArray(referrers_array, ref_obj);
			}
			cJSON_AddItemToObject(func_obj, "referrers", referrers_array);
		}

		cJSON_AddItemToObject(response.result.get(), "function", func_obj);
		response.success = true;
		return response;
	}

	static ResponseData handle_find_function_by_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Exactly 1 parameter (search keyword) is required");
			response.success = false;
			return response;
		}

		const std::string keyword = params[0];
		if (keyword.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Search keyword cannot be empty");
			response.success = false;
			return response;
		}

		cJSON* functions_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "functions", functions_array);

		int match_count = 0;
		const int total_funcs = get_func_qty();

		for (int f = 0; f < total_funcs; f++)
		{
			func_t* curFunc = getn_func(f);
			if (curFunc == nullptr)
				continue;

			qstring funcName = { 0 };
			get_func_name(&funcName, curFunc->start_ea);
			if (funcName.length() == 0)
				continue;

			std::string name_str = funcName.c_str();
			std::string keyword_lower = keyword;

			std::transform(name_str.begin(), name_str.end(), name_str.begin(), ::tolower);
			std::transform(keyword_lower.begin(), keyword_lower.end(), keyword_lower.begin(), ::tolower);

			if (name_str.find(keyword_lower) == std::string::npos)
			{
				continue;
			}

			cJSON* func_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(func_obj, "index", f);
			cJSON_AddStringToObject(func_obj, "name", funcName.c_str());
			cJSON_AddNumberToObject(func_obj, "start_address", curFunc->start_ea);
			cJSON_AddStringToObject(func_obj, "start_address_hex", ("0x" + Tools::decToHex(curFunc->start_ea)).c_str());
			cJSON_AddNumberToObject(func_obj, "end_address", curFunc->start_ea + calc_func_size(curFunc));
			cJSON_AddStringToObject(func_obj, "end_address_hex", ("0x" + Tools::decToHex(curFunc->end_ea)).c_str());
			cJSON_AddBoolToObject(func_obj, "is_entry", is_func_entry(curFunc));
			cJSON_AddBoolToObject(func_obj, "is_tail", is_func_tail(curFunc));
			cJSON_AddNumberToObject(func_obj, "bitness", get_func_bits(curFunc));
			cJSON_AddNumberToObject(func_obj, "total_size", calc_func_size(curFunc));
			cJSON_AddBoolToObject(func_obj, "visible", is_visible_func(curFunc));
			cJSON_AddBoolToObject(func_obj, "returns", func_does_return(curFunc->start_ea));

			cJSON* flags_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(flags_obj, "raw_value", curFunc->flags);
			cJSON_AddBoolToObject(flags_obj, "FUNC_NORET", (curFunc->flags & FUNC_NORET) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_FAR", (curFunc->flags & FUNC_FAR) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_LIB", (curFunc->flags & FUNC_LIB) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_STATICDEF", (curFunc->flags & FUNC_STATICDEF) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_FRAME", (curFunc->flags & FUNC_FRAME) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_THUNK", (curFunc->flags & FUNC_THUNK) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_SP_READY", (curFunc->flags & FUNC_SP_READY) != 0);
			cJSON_AddBoolToObject(flags_obj, "FUNC_PROLOG_OK", (curFunc->flags & FUNC_PROLOG_OK) != 0);
			cJSON_AddItemToObject(func_obj, "flags", flags_obj);

			if (is_func_entry(curFunc))
			{
				cJSON* frame_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(frame_obj, "frame_netnode", curFunc->frame);
				cJSON_AddNumberToObject(frame_obj, "local_vars_size", curFunc->frsize);
				cJSON_AddNumberToObject(frame_obj, "saved_regs_size", curFunc->frregs);
				cJSON_AddNumberToObject(frame_obj, "args_size", curFunc->argsize);
				cJSON_AddNumberToObject(frame_obj, "frame_delta", curFunc->fpd);
				cJSON_AddNumberToObject(frame_obj, "color", curFunc->color);
				cJSON_AddItemToObject(func_obj, "frame_info", frame_obj);
			}

			if (curFunc->regargqty > 0)
			{
				cJSON* regargs_array = cJSON_CreateArray();
				for (int i = 0; i < curFunc->regargqty; i++)
				{
					regarg_t* ra = &curFunc->regargs[i];
					cJSON* ra_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(ra_obj, "index", i);
					cJSON_AddNumberToObject(ra_obj, "reg", ra->reg);
					cJSON_AddStringToObject(ra_obj, "type", ra->type ? (char*)ra->type : "Unknown");
					cJSON_AddStringToObject(ra_obj, "name", ra->name ? ra->name : "Unnamed");
					cJSON_AddItemToArray(regargs_array, ra_obj);
				}
				cJSON_AddItemToObject(func_obj, "register_arguments", regargs_array);
			}

			if (curFunc->llabelqty > 0)
			{
				cJSON_AddNumberToObject(func_obj, "local_labels_count", curFunc->llabelqty);
			}

			if (is_func_entry(curFunc) && curFunc->tailqty > 0)
			{
				cJSON* tails_array = cJSON_CreateArray();
				func_tail_iterator_t fti(curFunc);
				for (bool ok = fti.first(); ok; ok = fti.next())
				{
					const range_t& tail = fti.chunk();
					cJSON* tail_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(tail_obj, "start", tail.start_ea);
					cJSON_AddStringToObject(tail_obj, "start_hex", ("0x" + Tools::decToHex(tail.start_ea)).c_str());
					cJSON_AddNumberToObject(tail_obj, "end", tail.end_ea);
					cJSON_AddStringToObject(tail_obj, "end_hex", ("0x" + Tools::decToHex(tail.end_ea)).c_str());
					cJSON_AddItemToArray(tails_array, tail_obj);
				}
				cJSON_AddItemToObject(func_obj, "function_tails", tails_array);
			}

			if (is_func_tail(curFunc) && curFunc->refqty > 0)
			{
				cJSON* referrers_array = cJSON_CreateArray();
				func_parent_iterator_t fpi(curFunc);
				for (bool ok = fpi.first(); ok; ok = fpi.next())
				{
					ea_t parent_ea = fpi.parent();
					qstring parent_name = { 0 };
					get_func_name(&parent_name, parent_ea);

					cJSON* ref_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(ref_obj, "address", parent_ea);
					cJSON_AddStringToObject(ref_obj, "address_hex", ("0x" + Tools::decToHex(parent_ea)).c_str());
					cJSON_AddStringToObject(ref_obj, "name", parent_name.c_str());
					cJSON_AddItemToArray(referrers_array, ref_obj);
				}
				cJSON_AddItemToObject(func_obj, "referrers", referrers_array);
			}

			cJSON_AddItemToArray(functions_array, func_obj);
			match_count++;
		}

		cJSON_AddNumberToObject(response.result.get(), "match_count", match_count);
		response.success = true;

		return response;
	}

	static ResponseData handle_get_import_functions(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for import functions request");
			response.success = false;
			return response;
		}

		uint total_modules = get_import_module_qty();
		if (total_modules == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "message", "No import modules found");
			response.success = true;
			return response;
		}

		cJSON* modules_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "import_modules", modules_array);

		for (int module_idx = 0; module_idx < total_modules; module_idx++)
		{
			qstring module_name = { 0 };
			bool name_success = get_import_module_name(&module_name, module_idx);
			const char* mod_name = name_success && !module_name.empty() ? module_name.c_str() : "<unnamed_module>";

			module_import_data_t module_data(module_idx, mod_name);
			enum_import_names(module_idx, import_callback, &module_data);

			cJSON* module_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(module_obj, "module_index", module_data.module_idx);
			cJSON_AddStringToObject(module_obj, "module_name", module_data.module_name.c_str());

			cJSON* funcs_array = cJSON_CreateArray();
			cJSON_AddItemToObject(module_obj, "functions", funcs_array);

			for (const auto& func : module_data.functions)
			{
				cJSON* func_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(func_obj, "address", func.ea);
				cJSON_AddStringToObject(func_obj, "address_hex", ("0x" + Tools::decToHex(func.ea)).c_str());
				cJSON_AddStringToObject(func_obj, "name", func.name.empty() ? "<no_name>" : func.name.c_str());
				cJSON_AddNumberToObject(func_obj, "ordinal", func.ord);
				cJSON_AddItemToArray(funcs_array, func_obj);
			}

			cJSON_AddItemToArray(modules_array, module_obj);
		}

		response.success = true;
		return response;
	}
};

class SegmentHandler
{
public:
	static ResponseData handle_get_segment_count(const std::vector<std::string>& params)
	{
		ResponseData response;
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for segment count request");
			response.success = false;
			return response;
		}

		int segment_count = get_segm_qty();

		cJSON_AddNumberToObject(response.result.get(), "total_segments", segment_count);
		cJSON_AddStringToObject(response.result.get(), "description", "Total number of segments in the current disassembled file");

		response.success = true;
		return response;
	}

	static ResponseData handle_get_segment(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for reading all segments");
			response.success = false;
			return response;
		}

		cJSON* segments_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "segments", segments_array);

		int total_segments = get_segm_qty();
		for (int i = 0; i < total_segments; i++)
		{
			segment_t* cur_seg = getnseg(i);
			qstring seg_name = { 0 };

			if (get_segm_name(&seg_name, cur_seg) != -1)
			{
				cJSON* seg_obj = cJSON_CreateObject();

				cJSON_AddNumberToObject(seg_obj, "index", i);
				cJSON_AddStringToObject(seg_obj, "name", seg_name.c_str());
				cJSON_AddNumberToObject(seg_obj, "start_address", cur_seg->start_ea);
				cJSON_AddStringToObject(seg_obj, "start_address_hex", ("0x" + Tools::decToHex(cur_seg->start_ea)).c_str());
				cJSON_AddNumberToObject(seg_obj, "end_address", cur_seg->end_ea);
				cJSON_AddStringToObject(seg_obj, "end_address_hex", ("0x" + Tools::decToHex(cur_seg->end_ea)).c_str());
				cJSON_AddNumberToObject(seg_obj, "total_size", cur_seg->end_ea - cur_seg->start_ea);
				cJSON_AddNumberToObject(seg_obj, "type", cur_seg->type);
				cJSON_AddNumberToObject(seg_obj, "selector", cur_seg->sel);
				cJSON_AddNumberToObject(seg_obj, "bitness", cur_seg->bitness);
				cJSON_AddNumberToObject(seg_obj, "permissions", cur_seg->perm);

				qstring seg_class = { 0 };
				if (get_segm_class(&seg_class, cur_seg) != -1)
				{
					cJSON_AddStringToObject(seg_obj, "class", seg_class.c_str());
				}
				else
				{
					cJSON_AddStringToObject(seg_obj, "class", "Unknown");
				}

				cJSON_AddItemToArray(segments_array, seg_obj);
			}
		}

		cJSON_AddNumberToObject(response.result.get(), "total_segments", total_segments);
		cJSON_AddStringToObject(response.result.get(), "description", "Segments information based on template");

		response.success = true;
		return response;
	}

	static ResponseData handle_get_segment_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter is required");
			response.success = false;
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Only one address parameter is expected");
			response.success = false;
			return response;
		}

		ea_t address = BADADDR;

		char* endptr = nullptr;
		address = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		cJSON_AddNumberToObject(response.result.get(), "parsed_address", address);
		cJSON_AddStringToObject(response.result.get(), "parsed_address_hex", ("0x" + Tools::decToHex(address)).c_str());

		segment_t* seg = getseg(address);
		if (seg == nullptr)
		{
			cJSON_AddStringToObject(
				response.result.get(),
				"error",
				"No segment found containing the specified address. Check if address is valid for current binary."
			);

			cJSON_AddNumberToObject(response.result.get(), "total_segments", get_segm_qty());
			if (get_segm_qty() > 0)
			{
				segment_t* first_seg = getnseg(0);
				segment_t* last_seg = getnseg(get_segm_qty() - 1);
				cJSON_AddNumberToObject(response.result.get(), "first_segment_start", first_seg->start_ea);
				cJSON_AddStringToObject(response.result.get(), "first_segment_start_hex", ("0x" + Tools::decToHex(first_seg->start_ea)).c_str());
				cJSON_AddNumberToObject(response.result.get(), "last_segment_end", last_seg->end_ea);
				cJSON_AddStringToObject(response.result.get(), "last_segment_end_hex", ("0x" + Tools::decToHex(last_seg->end_ea)).c_str());
			}
			return response;
		}

		qstring seg_name = { 0 };
		if (get_segm_name(&seg_name, seg) == -1)
		{
			cJSON_AddStringToObject(response.result.get(), "segment_name", "Unknown");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "segment_name", seg_name.c_str());
		}

		cJSON_AddNumberToObject(response.result.get(), "address", address);
		cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(address)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "segment_start", seg->start_ea);
		cJSON_AddStringToObject(response.result.get(), "segment_start_hex", ("0x" + Tools::decToHex(seg->start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "segment_end", seg->end_ea);
		cJSON_AddStringToObject(response.result.get(), "segment_end_hex", ("0x" + Tools::decToHex(seg->end_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "description", "Segment containing the specified address");

		response.success = true;
		return response;
	}
};

class ReverseHandler
{
private:
	struct DecompileResult
	{
		bool success;
		ea_t func_ea;
		std::string func_name;
		std::string pseudocode;
		std::string error_msg;
	};

	struct InstructionInfo
	{
		ea_t addr;
		std::string addr_hex;
		uint64_t addr_dec;
		std::string opcode_hex;
		std::string disasm_text;
	};

	struct HexByteInfo
	{
		std::string address_hex;
		uint64_t address_dec;
		std::string byte_hex;
		char ascii_char;
	};

	static ea_t idaapi get_ea_line(ea_t target_ea)
	{
		func_t *pfn = get_func(target_ea);
		if (pfn == nullptr)
		{
			return BADADDR;
		}

		lock_func lock_pfn(pfn);
		mba_ranges_t mbr(pfn);
		hexrays_failure_t hf;
		cfuncptr_t cfunc_ptr = decompile(mbr, &hf, 0);
		if (cfunc_ptr == nullptr)
		{
			return BADADDR;
		}

		citem_t *target_item = nullptr;
		eamap_t &ea_map = cfunc_ptr->get_eamap();
		auto ea_it = ea_map.find(target_ea);
		if (ea_it != ea_map.end())
		{
			target_item = ea_it->second.front();
		}
		else
		{
			auto find_item_by_ea = [&](auto &&self, citem_t *item, int depth) -> citem_t *
			{
				if (item == nullptr || depth > 1000)
					return nullptr;
				if (item->ea == target_ea || (item->op == cit_block && func_contains(pfn, item->ea)))
					return item;

				if (item->is_expr())
				{
					cexpr_t *expr = (cexpr_t *)item;
					citem_t *found = nullptr;
					if (expr->x != nullptr) found = self(self, expr->x, depth + 1);
					if (found != nullptr) return found;
					if (expr->y != nullptr) found = self(self, expr->y, depth + 1);
					if (found != nullptr) return found;
					if (expr->z != nullptr) found = self(self, expr->z, depth + 1);
					return found;
				}
				else
				{
					cinsn_t *insn = (cinsn_t *)item;
					if (insn->cblock != nullptr)
						for (cinsn_t &sub_insn : *(insn->cblock))
						{
							citem_t *found = self(self, &sub_insn, depth + 1);
							if (found != nullptr) return found;
						}
					return nullptr;
				}
			};
			target_item = find_item_by_ea(find_item_by_ea, &(cfunc_ptr->body), 0);
		}

		if (target_item == nullptr)
		{
			return BADADDR;
		}
		int line_idx = -1;
		if (!cfunc_ptr->find_item_coords(target_item, nullptr, &line_idx))
		{
			return BADADDR;
		}

		int line_num = line_idx + 1;
		return line_num;
	}

	static void traverse_citems(citem_t *item, cfuncptr_t cfunc_ptr, int target_line, ea_t &result)
	{
		if (result != BADADDR || item == nullptr)
			return;

		int current_line = -1;
		if (cfunc_ptr->find_item_coords(item, nullptr, &current_line))
		{
			if (current_line == target_line)
			{
				result = item->ea;
				return;
			}
		}

		if (item->is_expr())
		{
			cexpr_t *expr = (cexpr_t *)item;
			if (expr->x != nullptr)
				traverse_citems(expr->x, cfunc_ptr, target_line, result);
			if (result != BADADDR)
				return;
			if (expr->y != nullptr)
				traverse_citems(expr->y, cfunc_ptr, target_line, result);
			if (result != BADADDR)
				return;
			if (expr->z != nullptr)
				traverse_citems(expr->z, cfunc_ptr, target_line, result);
		}
		else
		{
			cinsn_t *insn = (cinsn_t *)item;
			switch (insn->op)
			{
			case cit_block:
				if (insn->cblock != nullptr)
				{
					for (cinsn_t &sub_insn : *(insn->cblock))
					{
						traverse_citems(&sub_insn, cfunc_ptr, target_line, result);
						if (result != BADADDR) return;
					}
				}
				break;
			case cit_if:
				if (insn->cif != nullptr)
				{
					traverse_citems(&(insn->cif->expr), cfunc_ptr, target_line, result);
					if (result != BADADDR) return;
					if (insn->cif->ithen != nullptr)
						traverse_citems(insn->cif->ithen, cfunc_ptr, target_line, result);
					if (result != BADADDR) return;
					if (insn->cif->ielse != nullptr)
						traverse_citems(insn->cif->ielse, cfunc_ptr, target_line, result);
				}
				break;
			case cit_for:
				if (insn->cfor != nullptr)
				{
					if (insn->cfor->init.op != cot_empty)
						traverse_citems(&(insn->cfor->init), cfunc_ptr, target_line, result);
					if (result != BADADDR)
						return;
					traverse_citems(&(insn->cfor->expr), cfunc_ptr, target_line, result);
					if (result != BADADDR)
						return;
					if (insn->cfor->step.op != cot_empty)
						traverse_citems(&(insn->cfor->step), cfunc_ptr, target_line, result);
					if (result != BADADDR)
						return;
					if (insn->cfor->body != nullptr)
						traverse_citems(insn->cfor->body, cfunc_ptr, target_line, result);
				}
				break;
			case cit_while:
				if (insn->cwhile != nullptr)
				{
					traverse_citems(&(insn->cwhile->expr), cfunc_ptr, target_line, result);
					if (result != BADADDR)
						return;
					if (insn->cwhile->body != nullptr)
						traverse_citems(insn->cwhile->body, cfunc_ptr, target_line, result);
				}
				break;
			case cit_switch:
				if (insn->cswitch != nullptr)
				{
					traverse_citems(&(insn->cswitch->expr), cfunc_ptr, target_line, result);
					if (result != BADADDR)
						return;
					for (ccase_t &cs : insn->cswitch->cases)
					{
						traverse_citems(&cs, cfunc_ptr, target_line, result);
						if (result != BADADDR)
							return;
					}
				}
				break;

			case cit_expr:
				if (insn->cexpr != nullptr)
					traverse_citems(insn->cexpr, cfunc_ptr, target_line, result);
				break;
			default:
				break;
			}
		}
	}

	static ea_t idaapi get_line_ea(ea_t func_ea, int target_line)
	{
		func_t *pfn = get_func(func_ea);
		if (pfn == nullptr)
		{
			return BADADDR;
		}

		int line_idx = target_line - 1;
		if (line_idx < 0)
		{
			return BADADDR;
		}

		mba_ranges_t mbr(pfn);
		hexrays_failure_t hf;
		cfuncptr_t cfunc_ptr = decompile(mbr, &hf, DECOMP_NO_WAIT);
		if (cfunc_ptr == nullptr)
		{
			return BADADDR;
		}

		const strvec_t &pseudo_lines = cfunc_ptr->get_pseudocode();
		if (line_idx >= (int)pseudo_lines.size())
		{
			return BADADDR;
		}

		ea_t result = BADADDR;
		traverse_citems(&(cfunc_ptr->body), cfunc_ptr, line_idx, result);

		if (result != BADADDR)
			return result;
		else
			return BADADDR;

		return result;
	}

	static uint32_t get_insn_len_no_decode(ea_t ea)
	{
		if (!is_mapped(ea))
			return BADADDR;

		flags64_t f = get_flags(ea);
		if (!is_code(f))
			return BADADDR;

		return get_item_size(ea);
	}

	static bool dasm_collect_results(ea_t start_address, int count, std::vector<InstructionInfo>& out_insns, ea_t& out_end_ea)
	{
		ea_t current_ea = start_address;
		int processed = 0;
		out_insns.clear();
		out_end_ea = BADADDR;

		while (processed < count && is_mapped(current_ea))
		{
			uint32_t opcode_len = get_insn_len_no_decode(current_ea);
			if (opcode_len == 0)
				opcode_len = 1;

			qstring disasm_qstr = "<none>";
			if (!generate_disasm_line(&disasm_qstr, current_ea, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE))
				disasm_qstr = "<invalid>";

			uint8_t buf[16] = { 0 };
			int read_len = get_bytes(buf, opcode_len, current_ea, GMB_READALL);
			if (read_len < 0)
				read_len = 0;

			qstring opcode_hex_qstr = { 0 };
			for (int i = 0; i < opcode_len; ++i)
				opcode_hex_qstr.cat_sprnt("%02X ", buf[i]);
			if (opcode_hex_qstr.empty())
				opcode_hex_qstr = "- ";

			InstructionInfo insn;
			insn.addr = current_ea;
			insn.addr_dec = static_cast<uint64_t>(current_ea);

			char addr_hex_buf[32] = { 0 };
			sprintf_s(addr_hex_buf, sizeof(addr_hex_buf), "0x%X", current_ea);
			insn.addr_hex = addr_hex_buf;
			insn.opcode_hex = opcode_hex_qstr.c_str();
			insn.disasm_text = disasm_qstr.c_str();
			out_insns.push_back(insn);

			current_ea += opcode_len;
			processed++;
		}

		out_end_ea = current_ea;
		return processed == count;
	}

	static bool dasm_collect_range_results(ea_t start_ea, ea_t end_ea, std::vector<InstructionInfo>& out_insns, ea_t& out_final_ea, int& out_processed)
	{
		ea_t current_ea = start_ea;
		out_processed = 0;
		out_insns.clear();
		out_final_ea = BADADDR;

		if (start_ea >= end_ea)
		{
			return false;
		}

		if (!is_mapped(start_ea))
		{
			return false;
		}

		if (!is_loaded(start_ea))
		{
			return false;
		}

		if (!is_mapped(end_ea))
		{
			segment_t* seg = getseg(start_ea);
			if (seg)
				end_ea = seg->end_ea;
			else
				return false;
		}

		if (!is_loaded(end_ea))
		{
			segment_t* seg = getseg(start_ea);
			if (seg)
				end_ea = seg->end_ea;
			else
				return false;
		}

		while (current_ea < end_ea && is_mapped(current_ea) && is_loaded(current_ea))
		{
			uint32_t opcode_len = get_insn_len_no_decode(current_ea);
			if (opcode_len == 0)
			{
				opcode_len = 1;
			}

			if (current_ea + opcode_len > end_ea)
			{
				opcode_len = end_ea - current_ea;
			}

			qstring disasm_qstr = "<none>";
			if (!generate_disasm_line(&disasm_qstr, current_ea, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE))
			{
				disasm_qstr = "<invalid>";
			}

			uint8_t buf[16] = { 0 };
			int read_len = get_bytes(buf, opcode_len, current_ea, GMB_READALL);
			if (read_len < 0)
			{
				read_len = 0;
			}

			qstring opcode_hex_qstr = { 0 };
			for (int i = 0; i < opcode_len; ++i)
				opcode_hex_qstr.cat_sprnt("%02X ", buf[i]);
			if (opcode_hex_qstr.empty())
				opcode_hex_qstr = "- ";

			InstructionInfo insn;
			insn.addr = current_ea;
			insn.addr_dec = static_cast<uint64_t>(current_ea);
			char addr_hex_buf[32];
			sprintf_s(addr_hex_buf, sizeof(addr_hex_buf), "0x%X", current_ea);
			insn.addr_hex = addr_hex_buf;
			insn.opcode_hex = opcode_hex_qstr.c_str();
			insn.disasm_text = disasm_qstr.c_str();
			out_insns.push_back(insn);

			current_ea += opcode_len;
			out_processed++;
		}

		out_final_ea = current_ea;
		return current_ea >= end_ea;
	}

	static func_t* find_func_by_name(const std::string& func_name)
	{
		if (func_name.empty())
			return nullptr;

		for (size_t i = 0; i < get_func_qty(); ++i)
		{
			func_t* pfn = getn_func(i);
			if (!pfn)
				continue;

			qstring func_name_qstr = { 0 };
			if (get_func_name(&func_name_qstr, pfn->start_ea) &&
				func_name_qstr.c_str() == func_name)
			{
				return pfn;
			}
		}
		return nullptr;
	}

	static DecompileResult decompile_func_impl(func_t* pfn)
	{
		DecompileResult result;
		result.success = false;
		result.func_ea = pfn ? pfn->start_ea : BADADDR;

		if (!pfn)
		{
			result.error_msg = "Invalid pointer argument";
			result.success = false;
			return result;
		}

		qstring func_name_qstr = { 0 };
		result.func_name = get_func_name(&func_name_qstr, pfn->start_ea)
			? func_name_qstr.c_str()
			: std::string("0x") + std::to_string(pfn->start_ea);

		hexrays_failure_t decomp_err;
		const int decomp_flags = DECOMP_WARNINGS | DECOMP_NO_CACHE;

		cfuncptr_t cfunc = decompile_func(pfn, &decomp_err, decomp_flags);
		if (!cfunc)
		{
			result.error_msg = std::string("Failed to decompile the address:") + decomp_err.desc().c_str();
			result.success = false;
			return result;
		}

		const strvec_t& pseudocode = cfunc->get_pseudocode();
		if (pseudocode.empty())
		{
			result.error_msg = "No decompiled code generated";
			result.success = false;
			return result;
		}

		qstring plain_line = { 0 };
		for (const auto& line : pseudocode)
		{
			tag_remove(&plain_line, line.line.c_str());
			result.pseudocode += plain_line.c_str();
			result.pseudocode += "\n";
		}

		result.success = true;
		return result;
	}

	static struct microcode_printer_t : public vd_printer_t
	{
		qstring buffer = { 0 };
		virtual int print(int indent, const char* format, ...) override
		{
			va_list va;
			va_start(va, format);
			qstring line = { 0 };
			if (indent > 0)
			{
				line.fill(' ', indent);
			}

			line.cat_vsprnt(format, va);
			va_end(va);

			buffer.append(line);
			buffer.append("\n");
			return line.length();
		}
	};

public:

	static ResponseData handle_get_micro_code(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Function address parameter is required");
			response.success = false;
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Only one function address parameter is allowed");
			response.success = false;
			return response;
		}

		ea_t func_ea = BADADDR;
		char* endptr = nullptr;
		func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		func_t* pfn = get_func(func_ea);
		if (pfn == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to get function from the given address");
			cJSON_AddNumberToObject(response.result.get(), "address", func_ea);
			cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(func_ea)).c_str());
			response.success = false;
			return response;
		}

		hexrays_failure_t hf;
		mba_t* mba = gen_microcode(pfn, &hf, nullptr, DECOMP_WARNINGS);
		if (mba == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to generate microcode");
			cJSON_AddStringToObject(response.result.get(), "error_details", hf.desc().c_str());
			cJSON_AddNumberToObject(response.result.get(), "error_address", hf.errea);
			cJSON_AddStringToObject(response.result.get(), "error_address_hex", ("0x" + Tools::decToHex(hf.errea)).c_str());
			response.success = false;
			return response;
		}

		microcode_printer_t mcp;
		mba->print(mcp);
		std::string microcode = mcp.buffer.c_str();

		cJSON_AddNumberToObject(response.result.get(), "function_start_address", pfn->start_ea);
		cJSON_AddStringToObject(response.result.get(), "function_start_address_hex", ("0x" + Tools::decToHex(pfn->start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "requested_address", func_ea);
		cJSON_AddStringToObject(response.result.get(), "requested_address_hex", ("0x" + Tools::decToHex(func_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "microcode", microcode.c_str());
		cJSON_AddNumberToObject(response.result.get(), "microcode_length", microcode.length());

		response.success = true;
		return response;
	}

	static ResponseData handle_decompile_checked(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Function address parameter is required");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Only one function address parameter is allowed");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		ea_t func_ea = BADADDR;
		char* endptr = nullptr;
		func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		cJSON_AddNumberToObject(response.result.get(), "requested_address", func_ea);
		cJSON_AddStringToObject(response.result.get(), "requested_address_hex", ("0x" + Tools::decToHex(func_ea)).c_str());

		func_t* pfn = get_func(func_ea);
		if (pfn == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		hexrays_failure_t hf;
		cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_WARNINGS);
		cJSON_AddStringToObject(response.result.get(), "flag", cfunc != nullptr ? "true" : "false");

		response.success = true;
		return response;
	}

	static ResponseData handle_decompile_by_address(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty() || params[0].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing parameter passing");
			response.success = false;
			return response;
		}

		ea_t func_ea = BADADDR;
		char* endptr = nullptr;
		func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		func_t* pfn = get_func(func_ea);
		if (!pfn)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				("Address 0x" + std::to_string(func_ea) + " Function not found").c_str());
			response.success = false;
			return response;
		}

		DecompileResult decomp_result = decompile_func_impl(pfn);

		cJSON_AddBoolToObject(response.result.get(), "success", decomp_result.success);
		cJSON_AddNumberToObject(response.result.get(), "func_ea", decomp_result.func_ea);
		cJSON_AddStringToObject(response.result.get(), "func_ea_hex", ("0x" + Tools::decToHex(decomp_result.func_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "func_name", decomp_result.func_name.c_str());

		if (decomp_result.success)
		{
			cJSON_AddStringToObject(response.result.get(), "pseudocode", decomp_result.pseudocode.c_str());
			cJSON_AddNumberToObject(response.result.get(), "line_count",
				std::count(decomp_result.pseudocode.begin(), decomp_result.pseudocode.end(), '\n'));
			response.success = true;
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", decomp_result.error_msg.c_str());
			response.success = false;
		}

		return response;
	}

	static ResponseData handle_decompile_by_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty() || params[0].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing function name parameter");
			response.success = false;
			return response;
		}

		const std::string func_name = params[0];

		func_t* pfn = find_func_by_name(func_name);
		if (!pfn)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				("Function '" + func_name + "' not found").c_str());
			response.success = false;
			return response;
		}

		DecompileResult decomp_result = decompile_func_impl(pfn);

		cJSON_AddBoolToObject(response.result.get(), "success", decomp_result.success);
		cJSON_AddNumberToObject(response.result.get(), "func_ea", decomp_result.func_ea);
		cJSON_AddStringToObject(response.result.get(), "func_ea_hex", ("0x" + Tools::decToHex(decomp_result.func_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "func_name", decomp_result.func_name.c_str());

		if (decomp_result.success)
		{
			cJSON_AddStringToObject(response.result.get(), "pseudocode", decomp_result.pseudocode.c_str());
			cJSON_AddNumberToObject(response.result.get(), "line_count",
				std::count(decomp_result.pseudocode.begin(), decomp_result.pseudocode.end(), '\n'));
			response.success = true;
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", decomp_result.error_msg.c_str());
			response.success = false;
		}

		return response;
	}

	static ResponseData handle_disassemble_function(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Function address parameter required");
			response.success = false;
			return response;
		}

		ea_t func_addr = static_cast<ea_t>(Tools::hexToDec(params[0]));
		if (func_addr == 0 && params[0] != "0")
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		func_t* func = get_func(func_addr);
		if (func == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to find function at given address");
			response.success = false;
			return response;
		}

		ea_t start_ea = func->start_ea;
		ea_t end_ea = start_ea + calc_func_size(func);

		cJSON* disasm_array = cJSON_CreateArray();
		ea_t current_ea = start_ea;

		while (current_ea < end_ea)
		{
			if (!is_loaded(current_ea))
				break;

			int insn_len = get_item_size(current_ea);
			if (insn_len <= 0)
				break;

			qstring disasm_str = { 0 };
			if (!generate_disasm_line(&disasm_str, current_ea, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE))
			{
				current_ea += insn_len;
				continue;
			}

			uint8_t* bytes = new uint8_t[insn_len];
			if (bytes == nullptr)
			{
				current_ea += insn_len;
				continue;
			}
			memset(bytes, 0, insn_len);

			ssize_t read_bytes = get_bytes(bytes, insn_len, current_ea);
			if (read_bytes < 0)
				read_bytes = 0;
			else if (read_bytes > insn_len)
				read_bytes = insn_len;

			cJSON* insn_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(insn_obj, "address", current_ea);
			cJSON_AddStringToObject(insn_obj, "address_hex", ("0x" + Tools::decToHex(current_ea)).c_str());
			cJSON_AddStringToObject(insn_obj, "disassembly", disasm_str.c_str());
			cJSON_AddNumberToObject(insn_obj, "length", insn_len);
			cJSON_AddStringToObject(insn_obj, "bytes", Tools::binToHex(bytes, read_bytes).c_str());
			cJSON_AddItemToArray(disasm_array, insn_obj);

			delete[] bytes;
			current_ea += insn_len;
		}

		cJSON* func_info = cJSON_CreateObject();
		cJSON_AddNumberToObject(func_info, "start_address", start_ea);
		cJSON_AddStringToObject(func_info, "start_address_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
		cJSON_AddNumberToObject(func_info, "end_address", end_ea);
		cJSON_AddStringToObject(func_info, "end_address_hex", ("0x" + Tools::decToHex(end_ea)).c_str());
		cJSON_AddNumberToObject(func_info, "total_instructions", cJSON_GetArraySize(disasm_array));
		cJSON_AddNumberToObject(func_info, "total_size", end_ea - start_ea);
		cJSON_AddItemToObject(response.result.get(), "function_info", func_info);
		cJSON_AddItemToObject(response.result.get(), "disassembly", disasm_array);

		response.success = true;
		return response;
	}

	static ResponseData handle_disassembly_count(const std::vector<std::string>& params)
	{
		ResponseData response;
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(
				response.result.get(),
				"error",
				"The number of parameters is incorrect! Two parameters are required: [starting address, disassembly line count]"
			);
			response.success = false;
			return response;
		}
		if (params[0].empty() || params[1].empty())
		{
			cJSON_AddStringToObject(
				response.result.get(),
				"error",
				"Parameter cannot be empty! Parameter format: [Starting address, disassembly lines]"
			);
			response.success = false;
			return response;
		}

		ea_t start_ea = BADADDR;
		ea_t disasm_count = 0;
		bool is_param_valid = true;

		char* endptr = nullptr;
		start_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "The starting address format is incorrect! Support: Decimal (such as 4198400) or Hexadecimal (such as 0x401000)");
			is_param_valid = false;
			return response;
		}

		if (is_param_valid)
		{
			char* endptr = nullptr;
			disasm_count = static_cast<ea_t>(strtoull(params[1].c_str(), &endptr, 0));
			if (*endptr != '\0' || endptr == params[1].c_str())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Incorrect disassembly line count! Must be a positive integer (such as 10, 20)");
				is_param_valid = false;
				return response;
			}
		}

		if (is_param_valid && !is_mapped(start_ea))
		{
			cJSON_AddStringToObject(
				response.result.get(),
				"error",
				"The starting address is invalid! Address not mapped to memory (may be an unloaded or illegal address)"
			);
			is_param_valid = false;
		}

		if (!is_param_valid)
			return response;

		std::vector<InstructionInfo> insn_list;
		ea_t end_ea = BADADDR;

		bool is_complete = dasm_collect_results(start_ea, disasm_count, insn_list, end_ea);

		cJSON_AddBoolToObject(response.result.get(), "success", true);
		cJSON_AddNumberToObject(response.result.get(), "request_start_address", start_ea);
		cJSON_AddStringToObject(response.result.get(), "request_start_address_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "request_line_count", disasm_count);
		cJSON_AddNumberToObject(response.result.get(), "actual_line_count", insn_list.size());

		const char* start_addr_hex = insn_list.empty() ? "N/A" : insn_list[0].addr_hex.c_str();
		cJSON_AddStringToObject(response.result.get(), "actual_start_address_hex", start_addr_hex);

		char end_addr_hex_buf[32] = "N/A";
		if (!insn_list.empty())
			sprintf_s(end_addr_hex_buf, sizeof(end_addr_hex_buf), "0x%016llX", end_ea);
		cJSON_AddStringToObject(response.result.get(), "actual_end_address_hex", end_addr_hex_buf);

		cJSON* insns_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "instructions", insns_array);
		for (const auto& insn : insn_list)
		{
			cJSON* insn_obj = cJSON_CreateObject();
			cJSON_AddStringToObject(insn_obj, "address_hex", insn.addr_hex.c_str());
			cJSON_AddNumberToObject(insn_obj, "address_dec", insn.addr_dec);
			cJSON_AddStringToObject(insn_obj, "opcode_hex", insn.opcode_hex.c_str());
			cJSON_AddStringToObject(insn_obj, "disasm_text", insn.disasm_text.c_str());
			cJSON_AddItemToArray(insns_array, insn_obj);
		}

		if (!is_complete)
		{
			cJSON_AddStringToObject(
				response.result.get(),
				"note",
				"The target line count has not been completed! Stopped prematurely due to encountering unmapped memory"
			);
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_disassembly_range(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "The number of parameters is incorrect! Two parameters are required: [starting address, ending address]");
			response.success = false;
			return response;
		}
		if (params[0].empty() || params[1].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Parameter cannot be empty! Parameter format: [starting address, ending address]");
			response.success = false;
			return response;
		}

		ea_t start_ea = BADADDR;
		ea_t end_ea = BADADDR;
		bool is_param_valid = true;

		char* endptr = nullptr;
		start_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "The starting address format is incorrect! Support: Decimal (such as 4198400) or Hexadecimal (such as 0x401000)");
			is_param_valid = false;
			return response;
		}

		char* endptr2 = nullptr;
		end_ea = static_cast<ea_t>(strtoull(params[1].c_str(), &endptr2, 0));
		if (*endptr2 != '\0' || endptr2 == params[1].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "End address format error! Support: Decimal (such as 4198480) or Hexadecimal (such as 0x401050)");
			is_param_valid = false;
			return response;
		}

		if (is_param_valid)
		{
			if (start_ea >= end_ea)
			{
				cJSON_AddStringToObject(response.result.get(), "error",
					("The address range is invalid! Starting address (0x" + std::to_string(start_ea) + ") >= End address (0x" + std::to_string(end_ea) + ")").c_str());
				is_param_valid = false;
			}
			else if (!is_mapped(start_ea))
			{
				cJSON_AddStringToObject(response.result.get(), "error",
					("The starting address is invalid! 0x" + std::to_string(start_ea) + " Not in any segment (not mapped)").c_str());
				is_param_valid = false;
			}
			else if (!is_loaded(start_ea))
			{
				cJSON_AddStringToObject(response.result.get(), "error",
					("The segment where the starting address is located is not loaded! 0x" + std::to_string(start_ea) + " Belongs to segment, but segment is not loaded").c_str());
				is_param_valid = false;
			}
		}

		if (!is_param_valid)
			return response;

		std::vector<InstructionInfo> insn_list;
		ea_t final_ea = BADADDR;
		int processed_count = 0;
		bool is_range_complete = dasm_collect_range_results(start_ea, end_ea, insn_list, final_ea, processed_count);

		cJSON_AddBoolToObject(response.result.get(), "success", true);
		cJSON_AddNumberToObject(response.result.get(), "request_start_address", start_ea);
		cJSON_AddStringToObject(response.result.get(), "request_start_address_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "request_end_address", end_ea);
		cJSON_AddStringToObject(response.result.get(), "request_end_address_hex", ("0x" + Tools::decToHex(end_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "actual_processed_count", processed_count);

		const char* actual_start_hex = insn_list.empty() ? "N/A" : insn_list[0].addr_hex.c_str();
		cJSON_AddStringToObject(response.result.get(), "actual_start_address_hex", actual_start_hex);

		char actual_end_hex[32] = "N/A";
		if (final_ea != BADADDR)
			sprintf_s(actual_end_hex, sizeof(actual_end_hex), "0x%016llX", final_ea);
		cJSON_AddStringToObject(response.result.get(), "actual_end_address_hex", actual_end_hex);

		cJSON* insns_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "instructions", insns_array);
		for (const auto& insn : insn_list)
		{
			cJSON* insn_obj = cJSON_CreateObject();
			cJSON_AddStringToObject(insn_obj, "address_hex", insn.addr_hex.c_str());
			cJSON_AddNumberToObject(insn_obj, "address_dec", insn.addr_dec);
			cJSON_AddStringToObject(insn_obj, "opcode_hex", insn.opcode_hex.c_str());
			cJSON_AddStringToObject(insn_obj, "disasm_text", insn.disasm_text.c_str());
			cJSON_AddItemToArray(insns_array, insn_obj);
		}

		if (processed_count == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "No instructions processed! Reason: Invalid starting address (not mapped/loaded) or no valid instructions in the address range");
		}
		else if (is_range_complete)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "The specified address range has been completely disassembled");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "note", "Incomplete coverage of address range! Stopped prematurely due to encountering unmapped/unloaded memory");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_decompile_address_to_line(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Exactly 1 parameter (address) is required");
			response.success = false;
			return response;
		}

		if (params[0].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter cannot be empty");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t target_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));

		if (*endptr != '\0' || endptr == params[0].c_str() || target_ea == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format (support decimal/hex like 0x401000)");
			response.success = false;
			return response;
		}

		int line_num = ReverseHandler::get_ea_line(target_ea);
		if (line_num <= 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to get line number for the specified address");
			return response;
		}

		cJSON_AddNumberToObject(response.result.get(), "line_number", line_num);
		cJSON_AddNumberToObject(response.result.get(), "address", target_ea);
		cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(target_ea)).c_str());
		response.success = true;
		return response;
	}

	static ResponseData handle_decompile_line_to_address(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Exactly 2 parameters required: [function_address, line_number]");
			response.success = false;
			return response;
		}

		if (params[0].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Function address parameter cannot be empty");
			response.success = false;
			return response;
		}
		if (params[1].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Line number parameter cannot be empty");
			response.success = false;
			return response;
		}

		char* endptr_ea = nullptr;
		ea_t func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr_ea, 0));
		if (*endptr_ea != '\0' || endptr_ea == params[0].c_str() || func_ea == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid function address format (support decimal/hex like 0x401000)");
			response.success = false;
			return response;
		}

		char* endptr_line = nullptr;
		long target_line = strtol(params[1].c_str(), &endptr_line, 10);
		if (*endptr_line != '\0' || endptr_line == params[1].c_str() || target_line <= 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid line number (must be a positive integer)");
			response.success = false;
			return response;
		}

		ea_t result_ea = ReverseHandler::get_line_ea(func_ea, static_cast<int>(target_line));
		if (result_ea == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to get memory address for the specified line number (invalid function or line out of range)");
			response.success = false;
			return response;
		}

		cJSON_AddNumberToObject(response.result.get(), "line_number", target_line);
		cJSON_AddNumberToObject(response.result.get(), "function_address", func_ea);
		cJSON_AddStringToObject(response.result.get(), "function_address_hex", ("0x" + Tools::decToHex(func_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "memory_address", result_ea);
		cJSON_AddStringToObject(response.result.get(), "memory_address_hex", ("0x" + Tools::decToHex(result_ea)).c_str());
		response.success = true;

		return response;
	}

	static ResponseData handle_get_select_decompile(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			response.success = false;
			return response;
		}

		TWidget* current_view = get_current_viewer();
		if (current_view == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "get_current_viewer error");
			response.success = false;
			return response;
		}

		vdui_t* vu = get_widget_vdui(current_view);
		if (vu == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "get_widget_vdui error");
			response.success = false;
			return response;
		}

		ea_t start_ea = 0, end_ea = 0;
		read_range_selection(current_view, &start_ea, &end_ea);
		//msg("select range = 0x%llx | 0x%llx\n", start_ea, end_ea);

		func_t* pfn = get_func(start_ea);
		if (pfn == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No function found at selected address");
			response.success = false;
			return response;
		}
		//msg("start = %x \n", pfn->start_ea);

		hexrays_failure_t hf;
		cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_WARNINGS);
		if (cfunc == nullptr)
		{
			//msg("Decompilation failed at 0x%llx: %s\n", hf.errea, hf.desc().c_str());
			std::string err = "Decompilation failed at 0x" + Tools::decToHex(hf.errea) + ": " + hf.desc().c_str();
			cJSON_AddStringToObject(response.result.get(), "error", err.c_str());
			response.success = false;
			return response;
		}

		const strvec_t& pseudocode = cfunc->get_pseudocode();
		if (pseudocode.empty())
		{
			//msg("Warning: No pseudocode generated for the function\n");
			cJSON_AddStringToObject(response.result.get(), "warning", "No pseudocode generated for the function");
			cJSON_AddArrayToObject(response.result.get(), "filtered_pseudocode_lines");
			cJSON_AddNumberToObject(response.result.get(), "matched_line_count", 0);
			response.success = true;
			return response;
		}

		size_t pseudocode_size = pseudocode.size();
		if (pseudocode_size == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "warning", "Pseudocode size is zero");
			cJSON_AddArrayToObject(response.result.get(), "filtered_pseudocode_lines");
			cJSON_AddNumberToObject(response.result.get(), "matched_line_count", 0);
			response.success = true;
			return response;
		}

		struct line_ea_pair_t { int line; ea_t ea; };
		qvector<line_ea_pair_t> line_ea_mapping;

		struct line_ea_mapper_t : public ctree_visitor_t
		{
			cfunc_t* cfunc;
			const strvec_t& pseudocode;
			qvector<line_ea_pair_t>& mapping;

			line_ea_mapper_t(cfunc_t* cf, const strvec_t& ps, qvector<line_ea_pair_t>& map)
				: ctree_visitor_t(CV_FAST | CV_INSNS), cfunc(cf), pseudocode(ps), mapping(map) {}

			int idaapi visit_insn(cinsn_t* ins) override
			{
				int x = 0, y = 0;
				if (cfunc->find_item_coords(ins, &x, &y))
				{
					if (y >= 0 && (size_t)y < pseudocode.size())
					{
						mapping.push_back({ y, ins->ea });
					}
				}
				return 0;
			}
		};

		line_ea_mapper_t mapper(cfunc, pseudocode, line_ea_mapping);
		mapper.apply_to(&cfunc->body, nullptr);

		bool has_matched = false;

		cJSON* filtered_lines_arr = cJSON_CreateArray();

		for (size_t i = 0; i < pseudocode_size; ++i)
		{
			ea_t line_ea = BADADDR;
			for (const auto& pair : line_ea_mapping)
			{
				if (pair.line == (int)i)
				{
					line_ea = pair.ea;
					break;
				}
			}

			if (line_ea != BADADDR && line_ea >= start_ea && line_ea < end_ea)
			{
				qstring buf = { 0 };
				tag_remove(&buf, pseudocode[i].line);
				//msg("line = %d | address = 0x%llx string = %s\n", i + 1, line_ea, buf.c_str());
				has_matched = true;

				cJSON* line_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(line_obj, "line", (int)i + 1);
				cJSON_AddNumberToObject(line_obj, "address", line_ea);
				cJSON_AddStringToObject(line_obj, "address_hex", ("0x" + Tools::decToHex(line_ea)).c_str());
				cJSON_AddStringToObject(line_obj, "pseudocode", buf.c_str());
				cJSON_AddItemToArray(filtered_lines_arr, line_obj);
			}
		}

		cJSON_AddNumberToObject(response.result.get(), "start_ea", start_ea);
		cJSON_AddStringToObject(response.result.get(), "start_ea_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "end_ea", end_ea);
		cJSON_AddStringToObject(response.result.get(), "end_ea_hex", ("0x" + Tools::decToHex(end_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "function_start_ea", pfn->start_ea);
		cJSON_AddStringToObject(response.result.get(), "function_start_ea_hex", ("0x" + Tools::decToHex(pfn->start_ea)).c_str());
		cJSON_AddItemToObject(response.result.get(), "filtered_pseudocode_lines", filtered_lines_arr);
		cJSON_AddNumberToObject(response.result.get(), "matched_line_count", cJSON_GetArraySize(filtered_lines_arr));
		cJSON_AddBoolToObject(response.result.get(), "has_matched", has_matched);

		response.success = true;
		return response;
	}

	static ResponseData handle_get_select_disassembly(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected! This interface reads the selected range from the current IDA View.");
			response.success = false;
			return response;
		}

		TWidget* current_view = get_current_viewer();
		if (current_view == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to get current viewer widget");
			response.success = false;
			return response;
		}

		if (!is_idaview(current_view))
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Current widget is not an IDA View (disassembly view). Please switch to the disassembly view and select a range.");
			response.success = false;
			return response;
		}

		ea_t start_ea = 0, end_ea = 0;
		if (!read_range_selection(current_view, &start_ea, &end_ea) || start_ea >= end_ea)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to read valid selection range or invalid address range (start address >= end address). Please select a valid range in the disassembly view.");
			response.success = false;
			return response;
		}
		//msg("select address = 0x%llx - 0x%llx\n", start_ea, end_ea);

		std::vector<InstructionInfo> insn_list;
		ea_t final_ea = BADADDR;
		int processed_count = 0;
		bool is_range_complete = dasm_collect_range_results(start_ea, end_ea, insn_list, final_ea, processed_count);

		cJSON_AddNumberToObject(response.result.get(), "selected_start_address", start_ea);
		cJSON_AddStringToObject(response.result.get(), "selected_start_address_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "selected_end_address", end_ea);
		cJSON_AddStringToObject(response.result.get(), "selected_end_address_hex", ("0x" + Tools::decToHex(end_ea)).c_str());

		cJSON_AddNumberToObject(response.result.get(), "actual_processed_count", processed_count);
		const char* actual_start_hex = insn_list.empty() ? "N/A" : insn_list[0].addr_hex.c_str();
		cJSON_AddStringToObject(response.result.get(), "actual_start_address_hex", actual_start_hex);

		char actual_end_hex[32] = "N/A";
		if (final_ea != BADADDR)
			sprintf_s(actual_end_hex, sizeof(actual_end_hex), "0x%X", final_ea);
		cJSON_AddStringToObject(response.result.get(), "actual_end_address_hex", actual_end_hex);

		cJSON* insns_array = cJSON_CreateArray();
		for (const auto& insn : insn_list)
		{
			cJSON* insn_obj = cJSON_CreateObject();
			cJSON_AddStringToObject(insn_obj, "address_hex", insn.addr_hex.c_str());
			cJSON_AddNumberToObject(insn_obj, "address_dec", insn.addr_dec);
			cJSON_AddStringToObject(insn_obj, "opcode_hex", insn.opcode_hex.c_str());
			cJSON_AddStringToObject(insn_obj, "disasm_text", insn.disasm_text.c_str());
			cJSON_AddItemToArray(insns_array, insn_obj);
		}
		cJSON_AddItemToObject(response.result.get(), "instructions", insns_array);

		if (processed_count == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "No instructions processed! Reason: No valid instructions in the selected address range.");
		}
		else if (is_range_complete)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "The selected address range has been completely disassembled.");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "note", "Incomplete coverage of selected address range! Stopped prematurely due to encountering unmapped/unloaded memory.");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_get_select_hex(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected! This interface reads the selected range from the current IDA View (disassembly view).");
			response.success = false;
			return response;
		}

		TWidget* current_view = get_current_viewer();
		if (current_view == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to get current viewer widget. Please ensure IDA has an active view.");
			response.success = false;
			return response;
		}

		ea_t start_ea = 0, end_ea = 0;
		if (!read_range_selection(current_view, &start_ea, &end_ea) || start_ea >= end_ea)
		{
			//msg("read_range_selection failed or invalid range\n");
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to read valid selection range or invalid address range (start >= end). Please select a continuous address range in the disassembly view.");
			response.success = false;
			return response;
		}
		//msg("Selected hex range: 0x%llx - 0x%llx\n", start_ea, end_ea);

		std::vector<HexByteInfo> hex_byte_list;
		int actual_read_count = 0;
		bool is_range_complete = true;

		for (ea_t ea = start_ea; ea < end_ea; ++ea)
		{
			if (!is_mapped(ea))
			{
				//msg("Address 0x%llx is not mapped, stop reading\n", ea);
				is_range_complete = false;
				break;
			}
			if (!is_loaded(ea))
			{
				//msg("Address 0x%llx is mapped but not loaded, stop reading\n", ea);
				is_range_complete = false;
				break;
			}

			uint8_t byte_val = get_byte(ea);
			HexByteInfo byte_info;

			byte_info.address_hex = "0x" + Tools::decToHex(ea);
			byte_info.address_dec = ea;

			char byte_hex_buf[3];
			sprintf_s(byte_hex_buf, sizeof(byte_hex_buf), "%02X", byte_val);
			byte_info.byte_hex = byte_hex_buf;

			byte_info.ascii_char = (isprint(static_cast<unsigned char>(byte_val))) ? static_cast<char>(byte_val) : '.';

			hex_byte_list.push_back(byte_info);
			actual_read_count++;
		}

		cJSON_AddNumberToObject(response.result.get(), "selected_start_address", start_ea);
		cJSON_AddStringToObject(response.result.get(), "selected_start_address_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "selected_end_address", end_ea);
		cJSON_AddStringToObject(response.result.get(), "selected_end_address_hex", ("0x" + Tools::decToHex(end_ea)).c_str());

		cJSON_AddNumberToObject(response.result.get(), "actual_read_byte_count", actual_read_count);
		const char* actual_start_hex = hex_byte_list.empty() ? "N/A" : hex_byte_list[0].address_hex.c_str();
		cJSON_AddStringToObject(response.result.get(), "actual_start_address_hex", actual_start_hex);

		char actual_end_hex[32] = "N/A";
		if (!hex_byte_list.empty())
		{
			strcpy_s(actual_end_hex, sizeof(actual_end_hex), hex_byte_list.back().address_hex.c_str());
		}
		cJSON_AddStringToObject(response.result.get(), "actual_end_address_hex", actual_end_hex);

		cJSON* hex_bytes_array = cJSON_CreateArray();
		for (const auto& byte_info : hex_byte_list)
		{
			cJSON* byte_obj = cJSON_CreateObject();
			cJSON_AddStringToObject(byte_obj, "address_hex", byte_info.address_hex.c_str());
			cJSON_AddNumberToObject(byte_obj, "address_dec", byte_info.address_dec);
			cJSON_AddStringToObject(byte_obj, "byte_hex", byte_info.byte_hex.c_str());
			cJSON_AddStringToObject(byte_obj, "ascii_char", std::string(1, byte_info.ascii_char).c_str());
			cJSON_AddItemToArray(hex_bytes_array, byte_obj);
		}
		cJSON_AddItemToObject(response.result.get(), "hex_bytes", hex_bytes_array);

		std::string hex_batch_str;
		std::string ascii_batch_str;
		for (const auto& byte_info : hex_byte_list)
		{
			hex_batch_str += byte_info.byte_hex + " ";
			ascii_batch_str += byte_info.ascii_char;
		}
		cJSON_AddStringToObject(response.result.get(), "hex_batch", hex_batch_str.empty() ? "N/A" : hex_batch_str.c_str());
		cJSON_AddStringToObject(response.result.get(), "ascii_batch", ascii_batch_str.empty() ? "N/A" : ascii_batch_str.c_str());

		if (actual_read_count == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "No bytes read! Reason: No valid bytes in the selected range or address range is unmapped/unloaded.");
		}
		else if (is_range_complete)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "The selected address range has been completely read (hex bytes + ASCII).");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "note", "Incomplete coverage of selected range! Stopped due to unmapped/unloaded memory or unreadable bytes.");
		}

		response.success = true;
		return response;
	}
};

class MemoryHandle
{
private:
	static bool get_switch_info(ea_t addr, switch_info_t* si)
	{
		if (si == nullptr) return false;
		if (!is_switch_insn(addr))
		{
			return false;
		}

		return true;
	}

	static ea_t find_bytes_with_wildcard(ea_t start_ea, ea_t end_ea, const std::string &pattern)
	{
		if (pattern.length() % 2 != 0)
		{
			return 0;
		}

		size_t len = pattern.length() / 2;
		uchar *image = new uchar[len];
		uchar *mask = new uchar[len];
		bool valid = true;

		for (size_t i = 0; i < len; ++i)
		{
			std::string byte_str = pattern.substr(i * 2, 2);
			if (byte_str == "??")
			{
				image[i] = 0x00;
				mask[i] = 0x00;
			}
			else
			{
				try
				{
					image[i] = static_cast<uchar>(std::stoul(byte_str, nullptr, 16));
					mask[i] = 0xFF;
				}
				catch (...)
				{
					valid = false;
					break;
				}
			}
		}

		if (!valid)
		{
			delete[] image;
			delete[] mask;
			return 0;
		}

		int flags = 0;
		ea_t found_ea = bin_search(start_ea, end_ea, image, mask, len, flags);

		delete[] image;
		delete[] mask;
		return (found_ea != BADADDR) ? found_ea : 0;
	}

	static tinfo_t get_type_by_name(const char* type_name)
	{
		if (type_name == nullptr || *type_name == '\0')
		{
			msg("Error: Empty type name\n");
			return tinfo_t();
		}

		if (strcmp(type_name, "int8") == 0
			|| strcmp(type_name, "__int8") == 0
			|| strcmp(type_name, "int8_t") == 0
			|| strcmp(type_name, "char") == 0
			|| strcmp(type_name, "signed char") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_INT8))
			{
				return tif;
			}
		}
		else if (strcmp(type_name, "uint8") == 0
			|| strcmp(type_name, "__uint8") == 0
			|| strcmp(type_name, "uint8_t") == 0
			|| strcmp(type_name, "unsigned char") == 0
			|| strcmp(type_name, "byte") == 0
			|| strcmp(type_name, "BYTE") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_UINT8))
			{
				return tif;
			}
		}

		else if (strcmp(type_name, "int16") == 0
			|| strcmp(type_name, "__int16") == 0
			|| strcmp(type_name, "int16_t") == 0
			|| strcmp(type_name, "short") == 0
			|| strcmp(type_name, "short int") == 0
			|| strcmp(type_name, "signed short") == 0
			|| strcmp(type_name, "signed short int") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_INT16))
			{
				return tif;
			}
		}
		else if (strcmp(type_name, "uint16") == 0
			|| strcmp(type_name, "__uint16") == 0
			|| strcmp(type_name, "uint16_t") == 0
			|| strcmp(type_name, "unsigned short") == 0
			|| strcmp(type_name, "unsigned short int") == 0
			|| strcmp(type_name, "word") == 0
			|| strcmp(type_name, "WORD") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_UINT16))
			{
				return tif;
			}
		}

		else if (strcmp(type_name, "int32") == 0
			|| strcmp(type_name, "__int32") == 0
			|| strcmp(type_name, "int32_t") == 0
			|| strcmp(type_name, "int") == 0
			|| strcmp(type_name, "signed int") == 0
			|| strcmp(type_name, "long") == 0
			|| strcmp(type_name, "long int") == 0
			|| strcmp(type_name, "signed long") == 0
			|| strcmp(type_name, "signed long int") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_INT32))
			{
				return tif;
			}
		}
		else if (strcmp(type_name, "uint32") == 0
			|| strcmp(type_name, "__uint32") == 0
			|| strcmp(type_name, "uint32_t") == 0
			|| strcmp(type_name, "unsigned int") == 0
			|| strcmp(type_name, "unsigned long") == 0
			|| strcmp(type_name, "unsigned long int") == 0
			|| strcmp(type_name, "dword") == 0
			|| strcmp(type_name, "DWORD") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_UINT32))
			{
				return tif;
			}
		}

		else if (strcmp(type_name, "int64") == 0
			|| strcmp(type_name, "__int64") == 0
			|| strcmp(type_name, "int64_t") == 0
			|| strcmp(type_name, "long long") == 0
			|| strcmp(type_name, "long long int") == 0
			|| strcmp(type_name, "signed long long") == 0
			|| strcmp(type_name, "signed long long int") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_INT64))
			{
				return tif;
			}
		}
		else if (strcmp(type_name, "uint64") == 0
			|| strcmp(type_name, "__uint64") == 0
			|| strcmp(type_name, "uint64_t") == 0
			|| strcmp(type_name, "unsigned int64") == 0
			|| strcmp(type_name, "unsigned long long") == 0
			|| strcmp(type_name, "unsigned long long int") == 0
			|| strcmp(type_name, "qword") == 0
			|| strcmp(type_name, "QWORD") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_UINT64))
			{
				return tif;
			}
		}

		else if (strcmp(type_name, "int128") == 0
			|| strcmp(type_name, "__int128") == 0
			|| strcmp(type_name, "int128_t") == 0
			|| strcmp(type_name, "__int128_t") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_INT128))
			{
				return tif;
			}
		}
		else if (strcmp(type_name, "uint128") == 0
			|| strcmp(type_name, "__uint128") == 0
			|| strcmp(type_name, "uint128_t") == 0
			|| strcmp(type_name, "__uint128_t") == 0
			|| strcmp(type_name, "unsigned int128") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_UINT128))
			{
				return tif;
			}
		}

		else if (strcmp(type_name, "float") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_FLOAT))
			{
				return tif;
			}
		}
		else if (strcmp(type_name, "double") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_DOUBLE))
			{
				return tif;
			}
		}
		else if (strcmp(type_name, "long double") == 0
			|| strcmp(type_name, "ldouble") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_LDOUBLE))
			{
				return tif;
			}
		}

		else if (strcmp(type_name, "bool") == 0
			|| strcmp(type_name, "_Bool") == 0
			|| strcmp(type_name, "boolean") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_BOOL))
			{
				return tif;
			}
		}

		else if (strcmp(type_name, "void") == 0)
		{
			tinfo_t tif;
			if (tif.create_simple_type(BTF_VOID))
			{
				return tif;
			}
		}

		tinfo_t tif;
		til_t* idati = get_idati();

		if (tif.get_named_type(idati, type_name, BTF_STRUCT))
		{
			return tif;
		}

		if (tif.get_named_type(idati, type_name, BTF_TYPEDEF))
		{
			return tif;
		}

		if (tif.get_named_type(idati, type_name, BTF_ENUM))
		{
			return tif;
		}

		if (tif.get_named_type(idati, type_name, BTF_UNION))
		{
			return tif;
		}

		return tinfo_t();
	}

public:

	static ResponseData handle_get_entry_points(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for entry points request");
			response.success = false;
			return response;
		}

		size_t entry_count = get_entry_qty();
		cJSON* entry_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "entry_points", entry_array);
		cJSON_AddNumberToObject(response.result.get(), "total_count", entry_count);

		for (size_t i = 0; i < entry_count; ++i)
		{
			uval_t ordinal = get_entry_ordinal(i);
			if (ordinal == 0)
			{
				continue;
			}

			ea_t address = get_entry(ordinal);
			if (address == BADADDR)
			{
				continue;
			}

			qstring entry_name = { 0 };
			get_entry_name(&entry_name, ordinal);

			qstring entry_forwarder = { 0 };
			get_entry_forwarder(&entry_forwarder, ordinal);

			cJSON* entry_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(entry_obj, "ordinal", ordinal);
			cJSON_AddNumberToObject(entry_obj, "address", address);
			cJSON_AddStringToObject(entry_obj, "address_hex", ("0x" + Tools::decToHex(address)).c_str());
			cJSON_AddStringToObject(entry_obj, "name", entry_name.c_str());
			cJSON_AddStringToObject(entry_obj, "forwarder", entry_forwarder.c_str());
			cJSON_AddNumberToObject(entry_obj, "index", i);
			cJSON_AddItemToArray(entry_array, entry_obj);
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_get_defined_struct(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for defined structs request");
			response.success = false;
			return response;
		}

		int original_count = get_ordinal_count();
		cJSON* types_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "defined_types", types_array);
		cJSON_AddNumberToObject(response.result.get(), "total_count", original_count);

		for (int x = 0; x <= original_count; x++)
		{
			tinfo_t tif;
			bool get_success = tif.get_numbered_type(nullptr, x);
			if (!get_success)
			{
				continue;
			}

			cJSON* type_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(type_obj, "ordinal", x);
			cJSON_AddBoolToObject(type_obj, "get_success", true);

			qstring type_name = { 0 };
			if (!tif.get_type_name(&type_name))
			{
				type_name = "<unknown_type>";
			}
			cJSON_AddStringToObject(type_obj, "name", type_name.c_str());

			size_t type_size = tif.get_size();
			cJSON_AddNumberToObject(type_obj, "size_bytes", type_size);
			cJSON_AddStringToObject(type_obj, "size_hex", ("0x" + Tools::decToHex((long long)type_size)).c_str());

			bool is_union = tif.is_union();
			bool is_struct = tif.is_struct();
			bool is_enum = tif.is_enum();
			bool is_typedef = tif.is_typedef();
			bool is_ptr = tif.is_ptr();
			bool is_array = tif.is_array();

			cJSON_AddBoolToObject(type_obj, "is_union", is_union);
			cJSON_AddBoolToObject(type_obj, "is_struct", is_struct);
			cJSON_AddBoolToObject(type_obj, "is_enum", is_enum);
			cJSON_AddBoolToObject(type_obj, "is_typedef", is_typedef);
			cJSON_AddBoolToObject(type_obj, "is_ptr", is_ptr);
			cJSON_AddBoolToObject(type_obj, "is_array", is_array);

			qstring type_str = { 0 };
			tif.print(&type_str);
			cJSON_AddStringToObject(type_obj, "type_string", type_str.c_str());

			if (is_ptr)
			{
				tinfo_t pointed_type = tif.get_pointed_object();
				qstring pointed_name = { 0 };
				pointed_type.get_type_name(&pointed_name);
				cJSON_AddStringToObject(type_obj, "points_to", pointed_name.c_str());

				qstring pointed_type_str = { 0 };
				pointed_type.print(&pointed_type_str);
				cJSON_AddStringToObject(type_obj, "pointed_type_string", pointed_type_str.c_str());
			}

			cJSON_AddItemToArray(types_array, type_obj);
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_get_memory_bytes(const std::vector<std::string>& params)
	{
		ResponseData response;
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Expected exactly two parameters: [memory address (hex/dec), length (positive integer)]");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		size_t req_length = static_cast<size_t>(strtoull(params[1].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[1].c_str() || req_length == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid length (must be positive integer)");
			response.success = false;
			return response;
		}

		std::vector<unsigned char> buff(req_length);
		ssize_t actual_length = get_bytes(buff.data(), req_length, addr);
		if (actual_length < 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to read memory bytes");
			response.success = false;
			return response;
		}

		cJSON* bytes_array = cJSON_CreateArray();
		cJSON* bytes_hex_array = cJSON_CreateArray();
		for (ssize_t i = 0; i < actual_length; ++i)
		{
			cJSON_AddItemToArray(bytes_array, cJSON_CreateNumber(buff[i]));
			std::stringstream ss;
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buff[i]);
			std::string hex_str = ss.str();
			cJSON_AddItemToArray(bytes_hex_array, cJSON_CreateString(hex_str.c_str()));
		}

		cJSON_AddNumberToObject(response.result.get(), "address", addr);
		cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(addr)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "requested_length", req_length);
		cJSON_AddNumberToObject(response.result.get(), "actual_length", actual_length);
		cJSON_AddItemToObject(response.result.get(), "bytes", bytes_array);
		cJSON_AddItemToObject(response.result.get(), "bytes_hex", bytes_hex_array);

		response.success = true;
		return response;
	}

	static ResponseData handle_get_memory_byte(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Expected exactly one parameter: memory address (hex format, e.g., 0x123456 or dec)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			return response;
		}

		uint8_t byte_value = get_byte(addr);

		cJSON_AddNumberToObject(response.result.get(), "address", addr);
		cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(addr)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "byte_value", byte_value);
		cJSON_AddStringToObject(response.result.get(), "byte_hex", (Tools::decToHex(byte_value)).c_str());

		response.success = true;
		return response;
	}

	static ResponseData handle_get_memory_word(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Expected exactly one parameter: memory address (hex format, e.g., 0x123456 or dec)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		ushort ush = get_word(addr);

		cJSON_AddNumberToObject(response.result.get(), "address", addr);
		cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(addr)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "word_value", ush);
		cJSON_AddStringToObject(response.result.get(), "word_hex", (Tools::decToHex(ush)).c_str());

		response.success = true;
		return response;
	}

	static ResponseData handle_get_memory_dword(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Expected exactly one parameter: memory address (hex format, e.g., 0x123456 or dec)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		uint32 u32 = get_dword(addr);

		cJSON_AddNumberToObject(response.result.get(), "address", addr);
		cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(addr)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "dword_value", u32);
		cJSON_AddStringToObject(response.result.get(), "dword_hex", (Tools::decToHex(u32)).c_str());

		response.success = true;
		return response;
	}

	static ResponseData handle_get_memory_qword(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Expected exactly one parameter: memory address (hex format, e.g., 0x123456 or dec)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		uint64 u64 = get_qword(addr);

		cJSON_AddNumberToObject(response.result.get(), "address", addr);
		cJSON_AddStringToObject(response.result.get(), "address_hex", ("0x" + Tools::decToHex(addr)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "qword_value", u64);
		cJSON_AddStringToObject(response.result.get(), "qword_hex", (Tools::decToHex(u64)).c_str());

		response.success = true;
		return response;
	}

	static ResponseData handle_get_string_info(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for string info request");
			response.success = false;
			return response;
		}

		size_t str_count = get_strlist_qty();
		cJSON* strings_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "strings", strings_array);
		cJSON_AddNumberToObject(response.result.get(), "total_count", str_count);

		for (size_t index = 0; index < str_count; index++)
		{
			string_info_t st;
			if (!get_strlist_item(&st, index) || st.ea == BADADDR)
				continue;

			ea_t start_address = st.ea;
			ea_t string_size = st.type;
			ea_t end_address = start_address + string_size;

			cJSON* str_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(str_obj, "index", index);
			cJSON_AddNumberToObject(str_obj, "start_address", start_address);
			cJSON_AddStringToObject(str_obj, "start_address_hex", ("0x" + Tools::decToHex(start_address)).c_str());
			cJSON_AddNumberToObject(str_obj, "end_address", end_address);
			cJSON_AddStringToObject(str_obj, "end_address_hex", ("0x" + Tools::decToHex(end_address)).c_str());
			cJSON_AddNumberToObject(str_obj, "size", string_size);
			cJSON_AddItemToArray(strings_array, str_obj);
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_memory_search(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameters. Expected: [start_ea, end_ea, pattern]");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t start_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address format");
			response.success = false;
			return response;
		}

		ea_t end_ea = static_cast<ea_t>(strtoull(params[1].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[1].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid end address format");
			response.success = false;
			return response;
		}

		if (start_ea >= end_ea || start_ea == 0 || end_ea == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address range (start >= end or zero address)");
			response.success = false;
			return response;
		}

		std::string pattern = params[2];

		ea_t found_ea = find_bytes_with_wildcard(start_ea, end_ea, pattern);

		if (found_ea != 0)
		{
			response.success = true;
			cJSON_AddNumberToObject(response.result.get(), "found_address", found_ea);
			cJSON_AddStringToObject(response.result.get(), "found_address_hex", ("0x" + Tools::decToHex(found_ea)).c_str());
			cJSON_AddStringToObject(response.result.get(), "searched_pattern", pattern.c_str());
			cJSON_AddNumberToObject(response.result.get(), "search_start", start_ea);
			cJSON_AddStringToObject(response.result.get(), "search_start_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
			cJSON_AddNumberToObject(response.result.get(), "search_end", end_ea);
			cJSON_AddStringToObject(response.result.get(), "search_end_hex", ("0x" + Tools::decToHex(end_ea)).c_str());
		}
		else
		{
			if (pattern.length() % 2 != 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid pattern (must be even length)");
				response.success = false;
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Pattern not found in specified range");
				cJSON_AddStringToObject(response.result.get(), "searched_pattern", pattern.c_str());
				cJSON_AddNumberToObject(response.result.get(), "search_start", start_ea);
				cJSON_AddStringToObject(response.result.get(), "search_start_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
				cJSON_AddNumberToObject(response.result.get(), "search_end", end_ea);
				cJSON_AddStringToObject(response.result.get(), "search_end_hex", ("0x" + Tools::decToHex(end_ea)).c_str());
				response.success = false;
			}
		}

		return response;
	}

	static ResponseData handle_get_type_by_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Type name parameter is required");
			response.success = false;
			return response;
		}

		const char* type_name = params[0].c_str();
		tinfo_t tif = get_type_by_name(type_name);

		size_t type_size = tif.get_size();

		cJSON* type_info = cJSON_CreateObject();
		cJSON_AddStringToObject(type_info, "original_name", type_name);
		cJSON_AddNumberToObject(type_info, "size_bytes", type_size);

		cJSON_AddItemToObject(response.result.get(), "type_info", type_info);
		response.success = true;

		return response;
	}

	static ResponseData handle_xref_code_first_to(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address required");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		cJSON* xrefs_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "xrefs", xrefs_array);

		xrefblk_t xb_to;
		for (bool ok = xb_to.first_to(addr, XREF_CODE); ok; ok = xb_to.next_to())
		{
			cJSON* xref_obj = cJSON_CreateObject();

			ea_t from_ea = xb_to.from;
			ea_t to_ea = get_first_cref_from(from_ea);

			cJSON* basic_info = cJSON_CreateObject();
			cJSON_AddNumberToObject(basic_info, "from_address", from_ea);
			cJSON_AddNumberToObject(basic_info, "to_address", to_ea);

			cJSON_AddStringToObject(basic_info, "from_address_hex", ("0x" + Tools::decToHex(from_ea)).c_str());
			cJSON_AddStringToObject(basic_info, "to_address_hex", ("0x" + Tools::decToHex(to_ea)).c_str());

			cJSON_AddBoolToObject(basic_info, "is_code_ref", xb_to.iscode);
			cJSON_AddBoolToObject(basic_info, "is_user_defined", xb_to.user);
			cJSON_AddItemToObject(xref_obj, "basic_info", basic_info);

			cJSON* type_info = cJSON_CreateObject();
			cJSON_AddNumberToObject(type_info, "type_code", xb_to.type);
			cJSON_AddStringToObject(type_info, "type_char", std::string(1, xrefchar(xb_to.type)).c_str());
			cJSON_AddNumberToObject(type_info, "base_type_masked", xb_to.type & XREF_MASK);

			cref_t cref_type = (cref_t)(xb_to.type & XREF_MASK);
			const char* cref_desc = "Unknown";
			switch (cref_type)
			{
			case fl_U: cref_desc = "unknown (for compatibility with old versions, should not be used anymore)";
				break;
			case fl_CF: cref_desc = "Call Far (This xref creates a function at the referenced location)";
				break;
			case fl_CN: cref_desc = "Call Near (This xref creates a function at the referenced location)";
				break;
			case fl_JF: cref_desc = "Jump Far";
				break;
			case fl_JN: cref_desc = "Jump Near";
				break;
			case fl_USobsolete: cref_desc = "User specified (obsolete)";
				break;
			case fl_F: cref_desc = "Ordinary flow (used to specify execution flow to the next instruction)";
				break;
			default: cref_desc = "Undefined code reference type";
			}
			cJSON_AddStringToObject(type_info, "code_ref_type", cref_desc);

			cJSON* flag_info = cJSON_CreateObject();
			cJSON_AddBoolToObject(flag_info, "XREF_USER", (xb_to.type & XREF_USER) != 0);
			cJSON_AddBoolToObject(flag_info, "XREF_TAIL", (xb_to.type & XREF_TAIL) != 0);
			cJSON_AddBoolToObject(flag_info, "XREF_BASE", (xb_to.type & XREF_BASE) != 0);
			cJSON_AddBoolToObject(flag_info, "XREF_PASTEND", (xb_to.type & XREF_PASTEND) != 0);
			cJSON_AddItemToObject(type_info, "xref_flags", flag_info);
			cJSON_AddItemToObject(xref_obj, "type_details", type_info);

			cJSON* disasm_info = cJSON_CreateObject();
			qstring disasm_str;
			if (generate_disasm_line(&disasm_str, from_ea, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE) > 0)
			{
				cJSON_AddStringToObject(disasm_info, "disassembly", disasm_str.c_str());
			}
			else
			{
				cJSON_AddStringToObject(disasm_info, "disassembly", "Failed to retrieve");
			}
			cJSON_AddBoolToObject(disasm_info, "is_head_address", is_head(from_ea));
			cJSON_AddItemToObject(xref_obj, "from_address_details", disasm_info);

			cJSON* func_info = cJSON_CreateObject();
			func_t* f_from = get_func(from_ea);
			if (f_from != nullptr)
			{
				cJSON_AddNumberToObject(func_info, "function_start", f_from->start_ea);
				cJSON_AddStringToObject(func_info, "function_start_hex", ("0x" + Tools::decToHex(f_from->start_ea)).c_str());

				qstring func_name = { 0 };
				get_func_name(&func_name, f_from->start_ea);
				cJSON_AddStringToObject(func_info, "function_name", func_name.c_str() ? func_name.c_str() : "Unknown");
				cJSON_AddNumberToObject(func_info, "function_flags", f_from->flags);
			}
			else
			{
				cJSON_AddStringToObject(func_info, "status", "Not part of any function");
			}
			cJSON_AddItemToObject(xref_obj, "function_info", func_info);

			cJSON* seg_info = cJSON_CreateObject();
			segment_t* seg = getseg(from_ea);
			if (seg != nullptr)
			{
				cJSON_AddNumberToObject(seg_info, "segment_start", seg->start_ea);
				cJSON_AddStringToObject(seg_info, "segment_start_hex", ("0x" + Tools::decToHex(seg->start_ea)).c_str());

				qstring seg_name = { 0 };
				if (get_segm_name(&seg_name, seg) != -1)
				{
					cJSON_AddStringToObject(seg_info, "segment_name", seg_name.c_str());
				}
				else
				{
					cJSON_AddStringToObject(seg_info, "segment_name", "Unknown");
				}
				cJSON_AddNumberToObject(seg_info, "segment_type", seg->type);

				std::string perm_str = { 0 };
				if (seg->perm & SEGPERM_EXEC)
				{
					perm_str += "EXEC";
				}
				else if (seg->perm & SEGPERM_WRITE)
				{
					perm_str += (perm_str.empty() ? std::string("") : std::string(",")) + "WRITE";
				}
				else if (seg->perm & SEGPERM_READ)
				{
					perm_str += (perm_str.empty() ? std::string("") : std::string(",")) + "READ";
				}
				else
				{
					perm_str = "None";
				}

				cJSON_AddStringToObject(seg_info, "segment_perm", perm_str.c_str());
			}
			else
			{
				cJSON_AddStringToObject(seg_info, "status", "No segment found for this address");
			}
			cJSON_AddItemToObject(xref_obj, "segment_info", seg_info);

			cJSON* ref_flags = cJSON_CreateObject();
			if (f_from != nullptr)
			{
				cJSON_AddBoolToObject(ref_flags, "has_external_references", has_external_refs(f_from, from_ea));
			}
			else
			{
				cJSON_AddNullToObject(ref_flags, "has_external_references");
			}
			cJSON_AddBoolToObject(ref_flags, "has_jump_flow_xrefs", has_jump_or_flow_xref(from_ea));
			cJSON_AddItemToObject(xref_obj, "reference_flags", ref_flags);

			cJSON* outgoing_refs = cJSON_CreateObject();

			cJSON* cref_array = cJSON_CreateArray();
			ea_t cref = get_first_cref_from(from_ea);
			while (cref != BADADDR)
			{
				cJSON_AddItemToArray(cref_array, cJSON_CreateNumber(cref));
				cref = get_next_cref_from(from_ea, cref);
			}
			cJSON_AddItemToObject(outgoing_refs, "code_references", cref_array);

			/*
			cJSON* dref_array = cJSON_CreateArray();
			ea_t dref = get_first_dref_from(from_ea);
			while (dref != BADADDR)
			{
			cJSON_AddItemToArray(dref_array, cJSON_CreateNumber(dref));
			dref = get_next_dref_from(from_ea, dref);
			}
			cJSON_AddItemToObject(outgoing_refs, "data_references", dref_array);
			*/

			cJSON* fcref_array = cJSON_CreateArray();
			ea_t fcref = get_first_fcref_from(from_ea);
			while (fcref != BADADDR)
			{
				cJSON_AddItemToArray(fcref_array, cJSON_CreateNumber(fcref));
				fcref = get_next_fcref_from(from_ea, fcref);
			}
			cJSON_AddItemToObject(outgoing_refs, "far_code_references", fcref_array);

			cJSON_AddItemToObject(xref_obj, "outgoing_references", outgoing_refs);

			cJSON* incoming_refs = cJSON_CreateObject();

			cJSON* cref_to_array = cJSON_CreateArray();
			ea_t cref_to = get_first_cref_to(from_ea);
			while (cref_to != BADADDR)
			{
				cJSON_AddItemToArray(cref_to_array, cJSON_CreateNumber(cref_to));
				cref_to = get_next_cref_to(from_ea, cref_to);
			}
			cJSON_AddItemToObject(incoming_refs, "code_references_to", cref_to_array);

			/*
			cJSON* dref_to_array = cJSON_CreateArray();
			ea_t dref_to = get_first_dref_to(from_ea);
			while (dref_to != BADADDR)
			{
			cJSON_AddItemToArray(dref_to_array, cJSON_CreateNumber(dref_to));
			dref_to = get_next_dref_to(from_ea, dref_to);
			}
			cJSON_AddItemToObject(incoming_refs, "data_references_to", dref_to_array);
			*/

			cJSON* fcref_to_array = cJSON_CreateArray();
			ea_t fcref_to = get_first_fcref_to(from_ea);
			while (fcref_to != BADADDR)
			{
				cJSON_AddItemToArray(fcref_to_array, cJSON_CreateNumber(fcref_to));
				fcref_to = get_next_fcref_to(from_ea, fcref_to);
			}

			cJSON_AddItemToObject(incoming_refs, "far_code_references_to", fcref_to_array);
			cJSON_AddItemToObject(xref_obj, "incoming_references", incoming_refs);
			cJSON_AddItemToArray(xrefs_array, xref_obj);
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_xref_code_first_from(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address required");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		cJSON* xrefs_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "xrefs", xrefs_array);

		xrefblk_t xb_from;
		for (bool ok = xb_from.first_from(addr, XREF_CODE); ok; ok = xb_from.next_from())
		{
			cJSON* xref_obj = cJSON_CreateObject();

			ea_t from_ea = xb_from.from;
			ea_t to_ea = xb_from.to;

			cJSON* basic_info = cJSON_CreateObject();
			cJSON_AddNumberToObject(basic_info, "from_address", from_ea);
			cJSON_AddNumberToObject(basic_info, "to_address", to_ea);
			cJSON_AddStringToObject(basic_info, "from_address_hex", ("0x" + Tools::decToHex(from_ea)).c_str());
			cJSON_AddStringToObject(basic_info, "to_address_hex", ("0x" + Tools::decToHex(to_ea)).c_str());
			cJSON_AddBoolToObject(basic_info, "is_code_ref", xb_from.iscode);
			cJSON_AddBoolToObject(basic_info, "is_user_defined", xb_from.user);
			cJSON_AddItemToObject(xref_obj, "basic_info", basic_info);

			cJSON* type_info = cJSON_CreateObject();
			cJSON_AddNumberToObject(type_info, "type_code", xb_from.type);
			cJSON_AddStringToObject(type_info, "type_char", std::string(1, xrefchar(xb_from.type)).c_str());
			cJSON_AddNumberToObject(type_info, "base_type_masked", xb_from.type & XREF_MASK);

			cref_t cref_type = (cref_t)(xb_from.type & XREF_MASK);
			const char* cref_desc = "Unknown";
			switch (cref_type)
			{
			case fl_U: cref_desc = "unknown (for compatibility with old versions, should not be used anymore)"; break;
			case fl_CF: cref_desc = "Call Far (This xref creates a function at the referenced location)"; break;
			case fl_CN: cref_desc = "Call Near (This xref creates a function at the referenced location)"; break;
			case fl_JF: cref_desc = "Jump Far"; break;
			case fl_JN: cref_desc = "Jump Near"; break;
			case fl_USobsolete: cref_desc = "User specified (obsolete)"; break;
			case fl_F: cref_desc = "Ordinary flow (used to specify execution flow to the next instruction)"; break;
			default: cref_desc = "Undefined code reference type";
			}
			cJSON_AddStringToObject(type_info, "code_ref_type", cref_desc);

			cJSON* flag_info = cJSON_CreateObject();
			cJSON_AddBoolToObject(flag_info, "XREF_USER", (xb_from.type & XREF_USER) != 0);
			cJSON_AddBoolToObject(flag_info, "XREF_TAIL", (xb_from.type & XREF_TAIL) != 0);
			cJSON_AddBoolToObject(flag_info, "XREF_BASE", (xb_from.type & XREF_BASE) != 0);
			cJSON_AddBoolToObject(flag_info, "XREF_PASTEND", (xb_from.type & XREF_PASTEND) != 0);
			cJSON_AddItemToObject(type_info, "xref_flags", flag_info);
			cJSON_AddItemToObject(xref_obj, "type_details", type_info);

			cJSON* disasm_info = cJSON_CreateObject();
			qstring disasm_str = { 0 };
			if (generate_disasm_line(&disasm_str, from_ea, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE) > 0)
			{
				cJSON_AddStringToObject(disasm_info, "disassembly", disasm_str.c_str());
			}
			else
			{
				cJSON_AddStringToObject(disasm_info, "disassembly", "Failed to retrieve");
			}
			cJSON_AddBoolToObject(disasm_info, "is_head_address", is_head(from_ea));
			cJSON_AddItemToObject(xref_obj, "from_address_details", disasm_info);

			cJSON* func_info = cJSON_CreateObject();
			func_t* f_from = get_func(from_ea);
			if (f_from != nullptr)
			{
				cJSON_AddNumberToObject(func_info, "function_start", f_from->start_ea);
				cJSON_AddStringToObject(func_info, "function_start_hex", ("0x" + Tools::decToHex(f_from->start_ea)).c_str());
				qstring func_name = { 0 };
				get_func_name(&func_name, f_from->start_ea);
				cJSON_AddStringToObject(func_info, "function_name", func_name.c_str() ? func_name.c_str() : "Unknown");
				cJSON_AddNumberToObject(func_info, "function_flags", f_from->flags);
			}
			else
			{
				cJSON_AddStringToObject(func_info, "status", "Not part of any function");
			}
			cJSON_AddItemToObject(xref_obj, "function_info", func_info);

			cJSON* seg_info = cJSON_CreateObject();
			segment_t* seg = getseg(from_ea);
			if (seg != nullptr)
			{
				cJSON_AddNumberToObject(seg_info, "segment_start", seg->start_ea);
				cJSON_AddStringToObject(seg_info, "segment_start_hex", ("0x" + Tools::decToHex(seg->start_ea)).c_str());
				qstring seg_name = { 0 };
				if (get_segm_name(&seg_name, seg) != -1)
				{
					cJSON_AddStringToObject(seg_info, "segment_name", seg_name.c_str());
				}
				else
				{
					cJSON_AddStringToObject(seg_info, "segment_name", "Unknown");
				}
				cJSON_AddNumberToObject(seg_info, "segment_type", seg->type);

				std::string perm_str = { 0 };
				if (seg->perm & SEGPERM_EXEC) perm_str += (perm_str.empty() ? std::string("") : std::string(",")) + "EXEC";
				if (seg->perm & SEGPERM_WRITE) perm_str += (perm_str.empty() ? std::string("") : std::string(",")) + "WRITE";
				if (seg->perm & SEGPERM_READ) perm_str += (perm_str.empty() ? std::string("") : std::string(",")) + "READ";
				cJSON_AddStringToObject(seg_info, "permissions", perm_str.c_str());
				cJSON_AddStringToObject(seg_info, "segment_perm", perm_str.c_str());
			}
			else
			{
				cJSON_AddStringToObject(seg_info, "status", "No segment found for this address");
			}
			cJSON_AddItemToObject(xref_obj, "segment_info", seg_info);

			cJSON* ref_flags = cJSON_CreateObject();
			if (f_from != nullptr)
			{
				cJSON_AddBoolToObject(ref_flags, "has_external_references", has_external_refs(f_from, from_ea));
			}
			else
			{
				cJSON_AddNullToObject(ref_flags, "has_external_references");
			}
			cJSON_AddBoolToObject(ref_flags, "has_jump_flow_xrefs", has_jump_or_flow_xref(from_ea));
			cJSON_AddItemToObject(xref_obj, "reference_flags", ref_flags);

			cJSON* outgoing_refs = cJSON_CreateObject();
			cJSON* cref_array = cJSON_CreateArray();
			ea_t cref = get_first_cref_to(from_ea);
			while (cref != BADADDR)
			{
				cJSON_AddItemToArray(cref_array, cJSON_CreateNumber(cref));
				cref = get_next_cref_to(from_ea, cref);
			}
			cJSON_AddItemToObject(outgoing_refs, "code_references", cref_array);

			cJSON* fcref_array = cJSON_CreateArray();
			ea_t fcref = get_first_fcref_to(from_ea);
			while (fcref != BADADDR)
			{
				cJSON_AddItemToArray(fcref_array, cJSON_CreateNumber(fcref));
				fcref = get_next_fcref_to(from_ea, fcref);
			}
			cJSON_AddItemToObject(outgoing_refs, "far_code_references", fcref_array);
			cJSON_AddItemToObject(xref_obj, "outgoing_references", outgoing_refs);

			cJSON* incoming_refs = cJSON_CreateObject();
			cJSON* cref_to_array = cJSON_CreateArray();
			ea_t cref_to = get_first_cref_to(from_ea);
			while (cref_to != BADADDR)
			{
				cJSON_AddItemToArray(cref_to_array, cJSON_CreateNumber(cref_to));
				cref_to = get_next_cref_to(from_ea, cref_to);
			}
			cJSON_AddItemToObject(incoming_refs, "code_references_to", cref_to_array);

			cJSON* fcref_to_array = cJSON_CreateArray();
			ea_t fcref_to = get_first_fcref_to(from_ea);
			while (fcref_to != BADADDR)
			{
				cJSON_AddItemToArray(fcref_to_array, cJSON_CreateNumber(fcref_to));
				fcref_to = get_next_fcref_to(from_ea, fcref_to);
			}
			cJSON_AddItemToObject(incoming_refs, "far_code_references_to", fcref_to_array);
			cJSON_AddItemToObject(xref_obj, "incoming_references", incoming_refs);

			cJSON_AddItemToArray(xrefs_array, xref_obj);
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_xref_data_first_to(const std::vector<std::string>& params)
	{
		ResponseData response;

		ea_t addr;
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter required (hex format, e.g., 0x401000)");
			response.success = false;
			return response;
		}
		else
		{
			char* endptr = nullptr;
			addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
			if (*endptr != '\0' || endptr == params[0].c_str())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
				response.success = false;
				return response;
			}
		}

		if (addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address (BADADDR)");
			response.success = false;
			return response;
		}

		cJSON* root = cJSON_CreateObject();
		cJSON_AddNumberToObject(root, "analyzed_address", addr);

		cJSON* data_to_array = cJSON_CreateArray();
		xrefblk_t xb_data_to;
		for (bool ok = xb_data_to.first_to(addr, XREF_DATA); ok; ok = xb_data_to.next_to())
		{
			cJSON* xref_obj = cJSON_CreateObject();

			cJSON_AddNumberToObject(xref_obj, "from_address", xb_data_to.from);
			cJSON_AddStringToObject(xref_obj, "from_address_hex", ("0x" + Tools::decToHex(xb_data_to.from)).c_str());
			cJSON_AddBoolToObject(xref_obj, "is_user_defined", xb_data_to.user);
			cJSON_AddNumberToObject(xref_obj, "type_code", xb_data_to.type);
			cJSON_AddStringToObject(xref_obj, "type_char", std::string(1, xrefchar(xb_data_to.type)).c_str());
			cJSON_AddNumberToObject(xref_obj, "base_type_masked", xb_data_to.type & XREF_MASK);

			dref_t dref_type = (dref_t)(xb_data_to.type & XREF_MASK);
			const char* dref_desc = "Unknown";
			switch (dref_type)
			{
			case dr_O: dref_desc = "Offset (uses 'offset' of data rather than value)"; break;
			case dr_W: dref_desc = "Write access"; break;
			case dr_R: dref_desc = "Read access"; break;
			case dr_T: dref_desc = "Text (name used in manual operand)"; break;
			case dr_I: dref_desc = "Informational (e.g., Java base class reference)"; break;
			case dr_S: dref_desc = "Reference to enum member (symbolic constant)"; break;
			default: dref_desc = "Undefined data reference type";
			}
			cJSON_AddStringToObject(xref_obj, "data_ref_description", dref_desc);

			cJSON* flags_obj = cJSON_CreateObject();
			cJSON_AddBoolToObject(flags_obj, "XREF_USER", (xb_data_to.type & XREF_USER) != 0);
			cJSON_AddBoolToObject(flags_obj, "XREF_TAIL", (xb_data_to.type & XREF_TAIL) != 0);
			cJSON_AddBoolToObject(flags_obj, "XREF_BASE", (xb_data_to.type & XREF_BASE) != 0);
			cJSON_AddBoolToObject(flags_obj, "XREF_PASTEND", (xb_data_to.type & XREF_PASTEND) != 0);
			cJSON_AddItemToObject(xref_obj, "xref_flags", flags_obj);

			qstring disasm_str = { 0 };
			if (generate_disasm_line(&disasm_str, xb_data_to.from, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE) > 0)
			{
				cJSON_AddStringToObject(xref_obj, "disassembly", disasm_str.c_str());
			}
			else
			{
				cJSON_AddStringToObject(xref_obj, "disassembly", "Failed to retrieve");
			}

			cJSON* seg_obj = cJSON_CreateObject();
			segment_t* seg = getseg(xb_data_to.from);
			if (seg != nullptr)
			{
				qstring seg_name = { 0 };
				if (get_segm_name(&seg_name, seg) != -1)
				{
					cJSON_AddStringToObject(seg_obj, "name", seg_name.c_str());
				}
				else
				{
					cJSON_AddStringToObject(seg_obj, "name", "Unknown");
				}

				cJSON* perm_obj = cJSON_CreateObject();
				cJSON_AddBoolToObject(perm_obj, "EXEC", (seg->perm & SEGPERM_EXEC) != 0);
				cJSON_AddBoolToObject(perm_obj, "WRITE", (seg->perm & SEGPERM_WRITE) != 0);
				cJSON_AddBoolToObject(perm_obj, "READ", (seg->perm & SEGPERM_READ) != 0);
				cJSON_AddItemToObject(seg_obj, "permissions", perm_obj);
			}
			else
			{
				cJSON_AddStringToObject(seg_obj, "error", "No segment found");
			}
			cJSON_AddItemToObject(xref_obj, "segment_info", seg_obj);

			cJSON_AddItemToArray(data_to_array, xref_obj);
		}
		cJSON_AddItemToObject(root, "data_xrefs_to", data_to_array);

		cJSON* outgoing_refs = cJSON_CreateObject();
		cJSON* cref_array = cJSON_CreateArray();
		xrefblk_t xb_cref;
		for (bool ok = xb_cref.first_from(addr, XREF_CODE | XREF_NOFLOW); ok; ok = xb_cref.next_from())
		{
			cJSON* cref_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(cref_obj, "target_address", xb_cref.to);
			cJSON_AddStringToObject(cref_obj, "type_char", std::string(1, xrefchar(xb_cref.type)).c_str());
			cJSON_AddItemToArray(cref_array, cref_obj);
		}
		cJSON_AddItemToObject(outgoing_refs, "code_xrefs_from", cref_array);

		cJSON* dref_array = cJSON_CreateArray();
		xrefblk_t xb_dref;
		for (bool ok = xb_dref.first_from(addr, XREF_DATA); ok; ok = xb_dref.next_from())
		{
			cJSON* dref_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(dref_obj, "target_address", xb_dref.to);
			cJSON_AddStringToObject(dref_obj, "type_char", std::string(1, xrefchar(xb_dref.type)).c_str());
			cJSON_AddItemToArray(dref_array, dref_obj);
		}
		cJSON_AddItemToObject(outgoing_refs, "data_xrefs_from", dref_array);

		cJSON* fcref_array = cJSON_CreateArray();
		ea_t fcref = get_first_fcref_from(addr);
		while (fcref != BADADDR)
		{
			cJSON_AddNumberToObject(cJSON_CreateObject(), "target_address", fcref);
			cJSON_AddItemToArray(fcref_array, cJSON_CreateNumber(fcref));
			fcref = get_next_fcref_from(addr, fcref);
		}
		cJSON_AddItemToObject(outgoing_refs, "far_code_xrefs_from", fcref_array);
		cJSON_AddItemToObject(root, "outgoing_references", outgoing_refs);

		cJSON* switch_info = cJSON_CreateObject();
		switch_info_t si;
		if (get_switch_info(addr, &si))
		{
			casevec_t casevec;
			eavec_t targets;
			if (calc_switch_cases(&casevec, &targets, addr, si))
			{
				cJSON_AddNumberToObject(switch_info, "case_count", targets.size());
				cJSON* cases_array = cJSON_CreateArray();
				for (size_t i = 0; i < targets.size() && i < casevec.size(); i++)
				{
					cJSON* case_obj = cJSON_CreateObject();

					if (i < casevec.size() && !casevec[i].empty())
					{
						sval_t case_value = casevec[i][0];
						cJSON_AddNumberToObject(case_obj, "case_value", case_value);
					}
					else
					{
						cJSON_AddNumberToObject(case_obj, "case_value", 0);
					}

					cJSON_AddNumberToObject(case_obj, "target_address", targets[i]);
					cJSON_AddItemToArray(cases_array, case_obj);
				}
				cJSON_AddItemToObject(switch_info, "cases", cases_array);
			}
			else
			{
				cJSON_AddStringToObject(switch_info, "error", "Switch table found but failed to calculate cases");
			}
		}
		else
		{
			cJSON_AddStringToObject(switch_info, "status", "No switch table references found");
		}

		cJSON_AddItemToObject(root, "switch_analysis", switch_info);
		cJSON_AddItemToObject(response.result.get(), "analysis_result", root);
		response.success = true;
		return response;
	}

	static ResponseData handle_xref_data_first_from(const std::vector<std::string>& params)
	{
		ResponseData response;
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter required");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t addr = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format or BADADDR");
			response.success = false;
			return response;
		}

		cJSON* xrefs_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "outgoing_data_xrefs", xrefs_array);

		xrefblk_t xb_from;
		bool has_xrefs = false;

		for (bool ok = xb_from.first_from(addr, XREF_DATA); ok; ok = xb_from.next_from())
		{
			has_xrefs = true;
			cJSON* xref_obj = cJSON_CreateObject();

			ea_t from_ea = xb_from.from;
			ea_t to_ea = xb_from.to;

			cJSON* basic_info = cJSON_CreateObject();
			cJSON_AddNumberToObject(basic_info, "from_address", from_ea);
			cJSON_AddStringToObject(xref_obj, "from_address_hex", ("0x" + Tools::decToHex(xb_from.from)).c_str());
			cJSON_AddBoolToObject(basic_info, "is_user_defined", xb_from.user);
			cJSON_AddBoolToObject(basic_info, "is_code_origin", is_code(get_flags(from_ea)));
			cJSON_AddItemToObject(xref_obj, "basic_info", basic_info);

			cJSON* type_info = cJSON_CreateObject();
			cJSON_AddNumberToObject(type_info, "type_code", xb_from.type);
			cJSON_AddStringToObject(type_info, "type_char", std::string(1, xrefchar(xb_from.type)).c_str());
			cJSON_AddNumberToObject(type_info, "base_type_masked", xb_from.type & XREF_MASK);

			dref_t dref_type = (dref_t)(xb_from.type & XREF_MASK);
			const char* dref_desc = "Unknown data reference type";
			switch (dref_type)
			{
			case dr_O: dref_desc = "Offset (uses data offset, not value)"; break;
			case dr_W: dref_desc = "Write access (current address modifies target data)"; break;
			case dr_R: dref_desc = "Read access (current address reads target data)"; break;
			case dr_T: dref_desc = "Text (uses target name in manual operand)"; break;
			case dr_I: dref_desc = "Informational (e.g., Java base class reference)"; break;
			case dr_S: dref_desc = "Enum member (reference to symbolic constant)"; break;
			default:   dref_desc = "Undefined data reference type";
			}

			cJSON_AddStringToObject(type_info, "data_ref_type", dref_desc);
			cJSON_AddItemToObject(xref_obj, "type_info", type_info);

			cJSON* flags_info = cJSON_CreateObject();
			cJSON_AddBoolToObject(flags_info, "XREF_USER", (xb_from.type & XREF_USER) != 0);
			cJSON_AddBoolToObject(flags_info, "XREF_TAIL", (xb_from.type & XREF_TAIL) != 0);
			cJSON_AddBoolToObject(flags_info, "XREF_BASE", (xb_from.type & XREF_BASE) != 0);
			cJSON_AddBoolToObject(flags_info, "XREF_PASTEND", (xb_from.type & XREF_PASTEND) != 0);
			cJSON_AddItemToObject(xref_obj, "flags_info", flags_info);

			cJSON* from_details = cJSON_CreateObject();
			qstring disasm_str = { 0 };;
			if (generate_disasm_line(&disasm_str, from_ea, GENDSM_REMOVE_TAGS | GENDSM_FORCE_CODE) > 0)
			{
				cJSON_AddStringToObject(from_details, "disassembly", disasm_str.c_str());
			}
			else
			{
				cJSON_AddStringToObject(from_details, "disassembly", "Failed to retrieve");
			}

			flags64_t curr_flags = get_flags(from_ea);
			const char* item_type = "Other (e.g., gap, alignment)";
			if (is_code(curr_flags)) item_type = "Code (instruction)";
			else if (is_data(curr_flags)) item_type = "Data (e.g., db, dw, dd)";
			else if (is_unknown(curr_flags)) item_type = "Unknown (unanalyzed bytes)";
			cJSON_AddStringToObject(from_details, "item_type", item_type);
			cJSON_AddItemToObject(xref_obj, "from_address_details", from_details);

			cJSON* func_info = cJSON_CreateObject();
			func_t* curr_func = get_func(from_ea);
			if (curr_func != nullptr)
			{
				qstring func_name = { 0 };
				get_func_name(&func_name, curr_func->start_ea);
				cJSON_AddStringToObject(func_info, "function_name", func_name.c_str() ? func_name.c_str() : "Unknown");
				cJSON_AddNumberToObject(func_info, "function_start", curr_func->start_ea);
				cJSON_AddStringToObject(func_info, "function_start_hex", ("0x" + Tools::decToHex(curr_func->start_ea)).c_str());
				size_t frame_size = get_frame_size(curr_func);
				cJSON_AddNumberToObject(func_info, "frame_size", frame_size);
			}
			else
			{
				cJSON_AddStringToObject(func_info, "note", "Not part of any function (may be global data or unanalyzed code)");
			}
			cJSON_AddItemToObject(xref_obj, "function_info", func_info);

			cJSON* seg_info = cJSON_CreateObject();
			segment_t* from_seg = getseg(from_ea);
			segment_t* to_seg = getseg(to_ea);
			if (from_seg != nullptr && to_seg != nullptr)
			{
				qstring from_seg_name = { 0 }, to_seg_name = { 0 };
				get_segm_name(&from_seg_name, from_seg);
				get_segm_name(&to_seg_name, to_seg);

				cJSON_AddStringToObject(seg_info, "from_segment", from_seg_name.c_str());
				cJSON_AddNumberToObject(seg_info, "from_segment_start", from_seg->start_ea);
				cJSON_AddStringToObject(seg_info, "from_segment_start_hex", ("0x" + Tools::decToHex(from_seg->start_ea)).c_str());
				cJSON_AddStringToObject(seg_info, "to_segment", to_seg_name.c_str());
				cJSON_AddNumberToObject(seg_info, "to_segment_start", to_seg->start_ea);
				cJSON_AddStringToObject(seg_info, "from_segment_start_hex", ("0x" + Tools::decToHex(to_seg->start_ea)).c_str());
				cJSON_AddBoolToObject(seg_info, "is_cross_segment", (from_seg->start_ea != to_seg->start_ea));
			}
			else
			{
				cJSON_AddStringToObject(seg_info, "note", "One or both addresses have no valid segment");
			}
			cJSON_AddItemToObject(xref_obj, "segment_comparison", seg_info);

			cJSON* to_details = cJSON_CreateObject();
			flags64_t to_flags = get_flags(to_ea);
			if (is_data(to_flags))
			{
				size_t data_size = get_item_size(to_ea);
				const char* data_type_str = "Unknown";
				if (data_size == 1)
					data_type_str = "byte (dt_byte)";
				else if (data_size == 2)
					data_type_str = "word (dt_word)";
				else if (data_size == 4)
					data_type_str = "dword (dt_dword)";
				else if (data_size == 8)
					data_type_str = "qword (dt_qword)";
				else if (data_size == 10)
					data_type_str = "tbyte (dt_tbyte)";

				cJSON_AddStringToObject(to_details, "data_type", data_type_str);

				uval_t data_value = 0;
				if (data_size == 1)      data_value = get_byte(to_ea);
				else if (data_size == 2) data_value = get_word(to_ea);
				else if (data_size == 4) data_value = get_dword(to_ea);
				else if (data_size == 8) data_value = get_qword(to_ea);
				cJSON_AddNumberToObject(to_details, "data_value_hex", data_value);
				cJSON_AddNumberToObject(to_details, "data_value_dec", data_value);
				cJSON_AddNumberToObject(to_details, "data_size", data_size);
			}
			else if (is_code(to_flags))
			{
				cJSON_AddStringToObject(to_details, "note", "Target is code (instruction), not data");
			}
			else
			{
				cJSON_AddStringToObject(to_details, "note", "Target is not recognized data (unanalyzed or gap)");
			}

			ea_t first_in_ref = get_first_dref_to(to_ea);
			cJSON_AddBoolToObject(to_details, "has_incoming_refs", first_in_ref != BADADDR);
			cJSON_AddItemToObject(xref_obj, "target_data_details", to_details);
			cJSON_AddItemToArray(xrefs_array, xref_obj);
		}

		if (!has_xrefs)
		{
			cJSON_AddStringToObject(response.result.get(), "note",
				"No outgoing data references from the specified address (may be code with no data access)");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_xref_code_first_to_array(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter required (hex format, e.g., 0x401000)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t proc_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || proc_ea == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format or BADADDR");
			response.success = false;
			return response;
		}

		cJSON* xrefs_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "code_xrefs_to", xrefs_array);

		xrefblk_t xb;
		bool has_xrefs = false;

		for (bool res = xb.first_to(proc_ea, XREF_FAR); res; res = xb.next_to())
		{
			has_xrefs = true;
			cJSON* xref_obj = cJSON_CreateObject();

			cJSON_AddNumberToObject(xref_obj, "from_address", xb.from);
			cJSON_AddNumberToObject(xref_obj, "to_address", xb.to);
			cJSON_AddBoolToObject(xref_obj, "is_code_ref", xb.iscode);

			std::string dir_str = (proc_ea > xb.from) ? "Up (target address > from address)" : "Down (target address <= from address)";
			cJSON_AddStringToObject(xref_obj, "direction", dir_str.c_str());

			cJSON_AddItemToArray(xrefs_array, xref_obj);
		}

		if (!has_xrefs)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "No FAR code references to the specified address");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_xref_code_first_from_array(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter required (hex format, e.g., 0x401000)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t proc_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || proc_ea == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format or BADADDR");
			response.success = false;
			return response;
		}

		cJSON* xrefs_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "code_xrefs_from", xrefs_array);

		xrefblk_t xb;
		bool has_xrefs = false;
		for (bool res = xb.first_from(proc_ea, XREF_FAR); res; res = xb.next_from())
		{
			has_xrefs = true;
			cJSON* xref_obj = cJSON_CreateObject();

			cJSON_AddNumberToObject(xref_obj, "from_address", proc_ea);
			cJSON_AddNumberToObject(xref_obj, "to_address", xb.to);
			cJSON_AddBoolToObject(xref_obj, "is_code_ref", xb.iscode);

			std::string dir_str = (xb.to > proc_ea) ? "Down (target address > from address)": "Up (target address <= from address)";
			cJSON_AddStringToObject(xref_obj, "direction", dir_str.c_str());

			cJSON_AddItemToArray(xrefs_array, xref_obj);
		}

		if (!has_xrefs)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "No FAR code references from the specified address");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_xref_data_first_to_array(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter required (hex format, e.g., 0x401000)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t proc_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || proc_ea == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format or BADADDR");
			response.success = false;
			return response;
		}

		cJSON* xrefs_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "data_xrefs_to", xrefs_array);

		xrefblk_t xb;
		bool has_xrefs = false;
		for (bool res = xb.first_to(proc_ea, XREF_DATA); res; res = xb.next_to())
		{
			has_xrefs = true;
			cJSON* xref_obj = cJSON_CreateObject();

			cJSON_AddNumberToObject(xref_obj, "from_address", xb.from);
			cJSON_AddNumberToObject(xref_obj, "to_address", proc_ea);
			cJSON_AddBoolToObject(xref_obj, "is_code_origin", xb.iscode);
			std::string dir_str = (proc_ea > xb.from) ? "Up (target address > from address)": "Down (target address <= from address)";
			cJSON_AddStringToObject(xref_obj, "direction", dir_str.c_str());

			cJSON_AddItemToArray(xrefs_array, xref_obj);
		}

		if (!has_xrefs)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "No data references to the specified address");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_xref_data_first_from_array(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter required (hex format, e.g., 0x401000)");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		ea_t proc_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str() || proc_ea == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format or BADADDR");
			response.success = false;
			return response;
		}

		cJSON* xrefs_array = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "data_xrefs_from", xrefs_array);

		xrefblk_t xb;
		bool has_xrefs = false;
		for (bool res = xb.first_from(proc_ea, XREF_DATA); res; res = xb.next_from())
		{
			has_xrefs = true;
			cJSON* xref_obj = cJSON_CreateObject();

			cJSON_AddNumberToObject(xref_obj, "from_address", proc_ea);
			cJSON_AddNumberToObject(xref_obj, "to_address", xb.to);
			cJSON_AddBoolToObject(xref_obj, "is_code_origin", xb.iscode);

			std::string dir_str = (xb.to > proc_ea) ? "Down (target address > from address)": "Up (target address <= from address)";
			cJSON_AddStringToObject(xref_obj, "direction", dir_str.c_str());

			cJSON_AddItemToArray(xrefs_array, xref_obj);
		}

		if (!has_xrefs)
		{
			cJSON_AddStringToObject(response.result.get(), "note", "No data references from the specified address");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_xref_get_list_array(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address required (support 0xhex/decimal)");
			response.success = false;
			return response;
		}

		const std::string& addr_str = params[0];
		char* endptr = nullptr;
		ea_t target_addr = static_cast<ea_t>(strtoull(addr_str.c_str(), &endptr, 0));

		if (*endptr != '\0' || endptr == addr_str.c_str() || target_addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format or BADADDR");
			response.success = false;
			return response;
		}

		size_t xref_code_to = 0;
		size_t xref_code_from = 0;
		size_t xref_data_to = 0;
		size_t xref_data_from = 0;

		xrefblk_t xb_code_to;
		for (bool ok = xb_code_to.first_to(target_addr, XREF_CODE); ok; ok = xb_code_to.next_to()) {
			xref_code_to++;
		}

		xrefblk_t xb_code_from;
		for (bool ok = xb_code_from.first_from(target_addr, XREF_CODE); ok; ok = xb_code_from.next_from()) {
			xref_code_from++;
		}

		xrefblk_t xb_data_to;
		for (bool ok = xb_data_to.first_to(target_addr, XREF_DATA); ok; ok = xb_data_to.next_to()) {
			xref_data_to++;
		}

		xrefblk_t xb_data_from;
		for (bool ok = xb_data_from.first_from(target_addr, XREF_DATA); ok; ok = xb_data_from.next_from()) {
			xref_data_from++;
		}

		cJSON_AddNumberToObject(response.result.get(), "target_address_dec", target_addr);
		cJSON_AddStringToObject(response.result.get(), "target_address_hex", ("0x" + Tools::decToHex(target_addr)).c_str());
		cJSON* xref_counts = cJSON_CreateObject();
		cJSON_AddNumberToObject(xref_counts, "code_to", xref_code_to);
		cJSON_AddNumberToObject(xref_counts, "code_from", xref_code_from);
		cJSON_AddNumberToObject(xref_counts, "data_to", xref_data_to);
		cJSON_AddNumberToObject(xref_counts, "data_from", xref_data_from);
		cJSON_AddItemToObject(response.result.get(), "xref_counts", xref_counts);

		size_t total_xrefs = xref_code_to + xref_code_from + xref_data_to + xref_data_from;
		cJSON_AddNumberToObject(response.result.get(), "total_xrefs", total_xrefs);

		response.success = true;
		return response;
	}
};

class OtherHandle
{
private:
#define isARM() (PH.id == PLFM_ARM)
#define MAX_NAME_LEN 63
#define is64bit()  inf_is_64bit()

	static inline THREAD_SAFE bool isDummyType(type_t t)
	{
		return is_type_partial(t) || get_full_type(t) == ((is64bit() ? BT_INT64 : BT_INT32) | BTMT_UNKSIGN);
	}

	static void stripName(qstring* name, bool funcSuffixToo)
	{
		size_t len = name->length();
		if (funcSuffixToo)
		{
			if (len > 6 && !strncmp(name->c_str(), "__imp_", 6))
			{
				name->remove(0, 6);
				len -= 6;
			}
			while (len > 2 && !strncmp(name->c_str(), "j_", 2))
			{
				name->remove(0, 2);
				len -= 2;
			}
		}

		if (len > 2)
		{
			char last = name->at(len - 1);
			if (last >= '0' && last <= '9')
			{
				last = name->at(len - 2);
				if (last == '_')
				{
					name->remove_last(2);
				}
				else if (len > 3 && last >= '0' && last <= '9' && name->at(len - 3) == '_')
				{
					name->remove_last(3);
				}
			}
		}
	}

	static bool is_vars_name(const char* name)
	{
		static const char* badVarNames[] = {
			"inited", "started", "result", "data", "Mem", "Memory", "Block", "String", "ProcName", "ProcAddress", "LibFileName", "ModuleName", "LibraryA", "LibraryW"
		};

		if (*name == 0)
			return false;

		size_t nlen = qstrlen(name);
		if (nlen > 1 && nlen <= 4)
		{
			const char* n = name;
			if (n[0] == 'e' || (is64bit() && n[0] == 'r' && !qisdigit(n[1])))
			{
				n++;
				nlen--;
			}
			for (int32 i = 0; i < PH.regs_num; i++)
			{
				const char *r = PH.reg_names[i];
				size_t rlen = qstrlen(r);
				if (nlen >= rlen && strneq(n, r, rlen) &&
					(n[rlen] == 0 ||
					(qisdigit(n[rlen]) && n[rlen + 1] == 0) ||
						(qisdigit(n[rlen]) && qisdigit(n[rlen + 1]) && n[rlen + 2] == 0)))
					return false;
			}
		}

		if ((name[0] == 'F' || name[0] == 'B') && !qstrcmp(name + 1, "link"))
			return false;

		if (name[0] == 'l' && name[1] == 'p' && name[2] != 0)
			name += 2;

		for (size_t i = 0; i < qnumber(badVarNames); i++)
			if (!qstrcmp(name, badVarNames[i]))
				return false;
		return true;
	}

	template< class IsUniqueFunc >
	static qstring unique_name(const char* name, const char* separator, IsUniqueFunc isUnique)
	{
		qstring uName = name;
		for (int i = 1; i < 1000; i++)
		{
			if (isUnique(uName))
				return uName;
			uName = name;
			uName.cat_sprnt("%s%d", separator, i);
		}
		return uName;
	}

	static tinfo_t get_types_name(const char *name, bool funcType)
	{
		qstring newName = name;
		stripName(&newName, funcType);
		bool isPtr = false;
		bool isDblPtr = false;

		if (!funcType)
		{
			isPtr = true;
			if (newName.last() == '_')
			{
				isPtr = false;
				newName.remove_last();
			}
			else if (newName.length() > 2 && newName.at(0) == 'p' && newName.at(1) == '_')
			{
				isDblPtr = true;
				newName.remove(0, 2);
			}
		}

		const type_t *type;
		const p_list *fields;
		tinfo_t       t;
		if (get_named_type(NULL, newName.c_str(), NTF_TYPE, &type, &fields))
		{
			if (is_type_struct(*type))
				t = create_typedef(newName.c_str());
			else
				t.deserialize(NULL, &type, &fields);
		}
		else if (get_named_type(NULL, newName.c_str(), 0, &type, &fields) && is_type_func(*type))
		{
			t.deserialize(NULL, &type, &fields);
		}
		if (!t.empty() && isPtr)
		{
			t = make_pointer(t);
			if (isDblPtr)
				t = make_pointer(t);
		}
		return t;
	}

	static qstring findnext_udm_name(const tinfo_t &struc, uint64 offInBits, const char *format, ...)
	{
		qstring name = { 0 };
		va_list va;
		va_start(va, format);
		name.vsprnt(format, va);
		va_end(va);

		if (name.size() > MAX_NAME_LEN - 3)
			name.resize(MAX_NAME_LEN - 3);
		validate_name(&name, VNT_UDTMEM);

		return unique_name(name.c_str(), "_",
			[&struc, offInBits](const qstring &n)
		{
			udm_t m;
			m.name = n;
			return struc.find_udm(&m, STRMEM_NAME) < 0 || (m.offset == offInBits && struc.is_struct());
		});
	}

	static ea_t getEaName(ea_t address, qstring* name)
	{
		func_t* func = get_func(address);
		if (func == nullptr)
		{
			return 0;
		}

		ea_t ea = func->start_ea;

		flags64_t flg = get_flags(ea);
		if (is_tail(flg) && isARM())
		{
			ea = ea & ~1;
			flg = get_flags(ea);
		}

		if (!has_user_name(flg) && is_strlit(flg))
		{
			if (name)
			{
				opinfo_t oi;
				if (!get_opinfo(&oi, ea, 0, flg))
					oi.strtype = STRTYPE_C;
				if (get_strlit_contents(name, ea, (size_t)(get_item_end(ea) - ea), oi.strtype, NULL, STRCONV_ESCAPE) > 0)
				{
					if (name->size() > MAX_NAME_LEN)
						name->resize(MAX_NAME_LEN);
					if (!validate_name(name, VNT_IDENT))
					{
						return 0;
					}
				}
			}
			return ea;
		}

		if (has_user_name(flg) || has_auto_name(flg))
		{
			qstring n = { 0 };
			get_ea_name(&n, ea);
			if (!stristr(n.c_str(), VTBL_SUFFIX))
			{
				if (name)
				{
					*name = n;
					stripName(name, is_func(flg));
				}
				return ea;
			}
		}

		if (is_code(flg) && has_dummy_name(flg))
		{
			qstring n = get_name(ea);
			if (!strncmp(n.c_str(), "sub_", 4))
			{
				if (name)
				{
					*name = n;
				}
				return ea;
			}
		}
		return 0;
	}

	static ea_t renameEa(ea_t address, const qstring* name)
	{
		func_t* func = get_func(address);
		if (func == nullptr)
		{
			return 0;
		}

		ea_t ea = func->start_ea;

		if (!is_mapped(ea))
		{
			return 0;
		}
		qstring newName = name->c_str();
		if (newName.size() > MAX_NAME_LEN)
			newName.resize(MAX_NAME_LEN);
		if (!validate_name(&newName, VNT_IDENT))
		{
			return 0;
		}
		if (!has_cmt(get_flags(ea)) && newName != *name)
			set_cmt(ea, name->c_str(), true);

		if (!strncmp(newName.c_str(), "sub_", 4))
			newName.insert('p');

		if (!set_name(ea, newName.c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE))
		{
			return 0;
		}

		return ea;
	}

	static struct SwitchPseudocodeRequest : public exec_request_t
	{
		ea_t func_ea;
		bool success;
		std::string err_msg;

		ssize_t idaapi execute() override
		{
			success = false;

			func_t* f = get_func(func_ea);
			if (f == nullptr)
			{
				err_msg = "No function found at address 0x" + Tools::decToHex(func_ea);
				return 0;
			}

			vdui_t* vu = open_pseudocode(f->start_ea, OPF_REUSE);
			if (vu == nullptr || !vu->valid() || vu->cfunc == nullptr)
			{
				err_msg = "Failed to open pseudocode for function 0x" + Tools::decToHex(f->start_ea);
				return 0;
			}

			vu->switch_to(vu->cfunc, true);
			if (vu->toplevel != nullptr)
			{
				activate_widget(vu->toplevel, true);
			}

			success = true;
			return 1;
		}
	};

	static ea_t renameLocalVarByFuncAddr(ea_t func_ea, ssize_t varIdx, const char* new_name)
	{
		if (func_ea == BADADDR || new_name == nullptr || *new_name == '\0')
		{
			return 0;
		}

		func_t* func = get_func(func_ea);
		if (func == nullptr)
		{
			return 0;
		}

		vdui_t* vu = nullptr;
		TWidget* widget = get_current_widget();
		if (widget != nullptr)
		{
			vu = get_widget_vdui(widget);
			if (vu != nullptr && vu->valid() && vu->cfunc != nullptr)
			{
				if (vu->cfunc->entry_ea != func->start_ea)
				{
					vu = nullptr;
					return 0;
				}
			}
		}

		if (vu == nullptr)
		{
			return 0;

		}

		cfunc_t* cfunc = vu->cfunc;
		lvars_t* lvars = cfunc->get_lvars();

		if (lvars == nullptr || lvars->empty())
		{
			return 0;
		}
		if (varIdx < 0 || (size_t)varIdx >= lvars->size())
		{
			return 0;
		}
		lvar_t* var = &lvars->at(varIdx);

		qstring newName(new_name);
		if (newName.size() > MAX_NAME_LEN)
		{
			newName.resize(MAX_NAME_LEN);
		}

		if (!validate_name(&newName, VNT_IDENT))
		{
			return 0;
		}

		newName = unique_name(newName.c_str(), "_", [&lvars, &var](const qstring& n)
		{
			for (auto it = lvars->begin(); it != lvars->end(); it++)
			{
				if (it->name == n)
				{
					return (it == var);
				}
			}

			ea_t nnea = get_name_ea(BADADDR, n.c_str());
			return (nnea == BADADDR || !is_func(get_flags(nnea)));
		});

		bool res = true;
		qstring oldname = var->name;
		if (vu)
		{
			res = vu->rename_lvar(var, newName.c_str(), true);
		}
		else
		{
			var->name = newName;
			var->set_user_name();

			tinfo_t newType;
			if (!var->has_user_type())
			{
				tinfo_t t = get_types_name(newName.c_str(), false);
				if (!t.empty() && var->accepts_type(t))
				{
					var->set_lvar_type(t, true);
					newType = t;
				}
			}

			if (var->is_arg_var())
			{
				ssize_t argIdx = cfunc->argidx.index((int)varIdx);
				if (argIdx != -1)
				{
					tinfo_t funcType;
					if (get_tinfo(&funcType, func_ea))
					{
						func_type_data_t fi;
						if (funcType.get_func_details(&fi) && fi.size() > (size_t)argIdx)
						{
							if (!is_vars_name(fi[argIdx].name.c_str()))
							{
								fi[argIdx].name = newName;
								stripName(&fi[argIdx].name, false);
								if (!newType.empty() && isDummyType(fi[argIdx].type.get_decltype()))
								{
									fi[argIdx].type = newType;
								}

								tinfo_t newFType;
								if (newFType.create_func(fi))
								{
									apply_tinfo(func_ea, newFType, is_userti(func_ea) ? TINFO_DEFINITE : TINFO_GUESSED);
								}
							}
						}
					}
				}
			}
		}

		if (res)
		{
			return func_ea;
		}

		return 0;
	}

public:

	static ResponseData handle_set_assembly_comment(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() < 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing parameters. Usage: [address] [comment_content]");
			response.success = false;
			return response;
		}

		const std::string& addr_str = params[0];
		const std::string& comment = params[1];

		char* endptr = nullptr;
		ea_t target_addr = static_cast<ea_t>(strtoull(addr_str.c_str(), &endptr, 0));

		if (*endptr != '\0' || endptr == addr_str.c_str() || target_addr == BADADDR)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format or BADADDR");
			response.success = false;
			return response;
		}

		if (getseg(target_addr) == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Target address is not in any valid segment");
			response.success = false;
			return response;
		}

		qstring existing_comment_buf = { 0 };
		ssize_t comment_len = get_cmt(&existing_comment_buf, target_addr, true);

		if (comment_len >= 0 && !existing_comment_buf.empty())
		{
			cJSON_AddBoolToObject(response.result.get(), "set_success", false);
			cJSON_AddStringToObject(response.result.get(), "error", "Address already has a repeatable comment (skip adding duplicate)");
			cJSON_AddNumberToObject(response.result.get(), "target_address_dec", target_addr);
			cJSON_AddStringToObject(response.result.get(), "target_address_hex", ("0x" + Tools::decToHex(target_addr)).c_str());
			cJSON_AddStringToObject(response.result.get(), "existing_comment", existing_comment_buf.c_str());
			response.success = true;
			return response;
		}

		bool set_success = set_cmt(target_addr, comment.c_str(), true);

		if (set_success)
		{
			cJSON_AddBoolToObject(response.result.get(), "set_success", true);
			cJSON_AddNumberToObject(response.result.get(), "target_address_dec", target_addr);
			cJSON_AddStringToObject(response.result.get(), "target_address_hex", ("0x" + Tools::decToHex(target_addr)).c_str());
			cJSON_AddStringToObject(response.result.get(), "comment_content", comment.c_str());
			cJSON_AddStringToObject(response.result.get(), "comment_type", "repeatable_comment");

			if (comment.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "note", "Empty comment provided: no existing comment to delete");
			}
		}
		else
		{
			cJSON_AddBoolToObject(response.result.get(), "set_success", false);
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to set comment. Possible reasons: address is read-only, IDA analysis lock, or invalid comment format");
			cJSON_AddNumberToObject(response.result.get(), "target_address_dec", target_addr);
			cJSON_AddStringToObject(response.result.get(), "target_address_hex", ("0x" + Tools::decToHex(target_addr)).c_str());
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_set_function_comment(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() < 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing parameters. Required: [function_address, comment_content], optional: [is_global(true/false)]");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}
		if (params.size() > 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Max 3: [function_address, comment_content, is_global]");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		ea_t func_ea = BADADDR;
		char* endptr = nullptr;
		func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid function address format");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		qstring comment = params[1].c_str();
		bool is_global = true;
		if (params.size() >= 3)
		{
			std::string global_str = params[2];
			std::transform(global_str.begin(), global_str.end(), global_str.begin(), ::tolower);
			is_global = !(global_str == "false" || global_str == "0");
		}

		cJSON_AddNumberToObject(response.result.get(), "requested_address", func_ea);
		cJSON_AddStringToObject(response.result.get(), "requested_address_hex", ("0x" + Tools::decToHex(func_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "comment_content", comment.c_str());
		cJSON_AddBoolToObject(response.result.get(), "is_global", is_global);

		func_t* func = get_func(func_ea);
		if (func == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No function found at the specified address");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		bool set_success = set_func_cmt(func, comment.c_str(), is_global);
		refresh_idaview_anyway();

		cJSON_AddStringToObject(response.result.get(), "flag", set_success ? "true" : "false");
		if (!set_success)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to set function comment");
		}

		response.success = true;
		return response;
	}

	static ResponseData handle_get_function_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Required exactly 1 parameter: [function_address]");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		ea_t func_ea = BADADDR;
		char* endptr = nullptr;
		func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid function address format");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		cJSON_AddNumberToObject(response.result.get(), "requested_address", func_ea);
		cJSON_AddStringToObject(response.result.get(), "requested_address_hex", ("0x" + Tools::decToHex(func_ea)).c_str());

		qstring func_name = { 0 };
		ea_t actual_ea = getEaName(func_ea, &func_name);

		if (actual_ea == 0 || func_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to get function name (no valid name or function not found)");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			cJSON_AddStringToObject(response.result.get(), "function_name", "");
			response.success = true;
			return response;
		}

		cJSON_AddStringToObject(response.result.get(), "flag", "true");
		cJSON_AddStringToObject(response.result.get(), "function_name", func_name.c_str());
		cJSON_AddNumberToObject(response.result.get(), "actual_function_start_address", actual_ea);
		cJSON_AddStringToObject(response.result.get(), "actual_function_start_address_hex", ("0x" + Tools::decToHex(actual_ea)).c_str());

		response.success = true;
		return response;
	}

	static ResponseData handle_set_function_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Required exactly 2 parameters: [function_address, new_function_name]");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		ea_t func_ea = BADADDR;
		char* endptr = nullptr;
		func_ea = static_cast<ea_t>(strtoull(params[0].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[0].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid function address format");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		const qstring new_func_name = params[1].c_str();
		if (new_func_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "New function name cannot be empty");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = false;
			return response;
		}

		cJSON_AddNumberToObject(response.result.get(), "requested_address", func_ea);
		cJSON_AddStringToObject(response.result.get(), "requested_address_hex", ("0x" + Tools::decToHex(func_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "new_function_name", new_func_name.c_str());

		ea_t actual_ea = renameEa(func_ea, &new_func_name);

		if (actual_ea == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to rename function (invalid function/name or rename failed)");
			cJSON_AddStringToObject(response.result.get(), "flag", "false");
			response.success = true;
			return response;
		}

		cJSON_AddStringToObject(response.result.get(), "flag", "true");
		cJSON_AddNumberToObject(response.result.get(), "actual_function_start_address", actual_ea);
		cJSON_AddStringToObject(response.result.get(), "actual_function_start_address_hex", ("0x" + Tools::decToHex(actual_ea)).c_str());
		cJSON_AddStringToObject(response.result.get(), "final_function_name", new_func_name.c_str());

		response.success = true;
		return response;
	}

	static ResponseData handle_switch_pseudocode_to(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Function address parameter is required");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		uint64_t addr_val = strtoull(params[0].c_str(), &endptr, 0);
		if (*endptr != '\0' || endptr == params[0].c_str() || addr_val > UINT64_MAX)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}

		ea_t func_ea = static_cast<ea_t>(addr_val);

		SwitchPseudocodeRequest req;
		req.func_ea = func_ea;

		ssize_t exec_result = execute_sync(req, MFF_FAST);

		if (req.success && exec_result == 1)
		{
			cJSON_AddStringToObject(response.result.get(), "message", "Successfully switched to pseudocode");
			cJSON_AddStringToObject(response.result.get(), "function_address",
				("0x" + Tools::decToHex(func_ea)).c_str());
			response.success = true;
		}
		else
		{
			std::string err = req.err_msg.empty() ? "Failed to switch to pseudocode (unknown error)" : req.err_msg;
			cJSON_AddStringToObject(response.result.get(), "error", err.c_str());
			response.success = false;
		}

		return response;
	}

	static ResponseData handle_get_function_var_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Address parameter is required");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		uint64_t addr_val = strtoull(params[0].c_str(), &endptr, 0);
		if (*endptr != '\0' || endptr == params[0].c_str() || addr_val > UINT64_MAX)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format");
			response.success = false;
			return response;
		}
		ea_t ea = static_cast<ea_t>(addr_val);
		if (ea == BADADDR || !is_loaded(ea))
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid or unloaded memory address");
			response.success = false;
			return response;
		}

		func_t* func = get_func(ea);
		ea_t func_start = func ? func->start_ea : BADADDR;

		if (func == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				("No function found at address 0x" + Tools::decToHex(ea)).c_str());
			response.success = false;
			return response;
		}

		vdui_t* vu = nullptr;
		TWidget* widget = get_current_widget();
		if (widget != nullptr)
		{
			vu = get_widget_vdui(widget);
			if (vu != nullptr && vu->valid() && vu->cfunc != nullptr)
			{
				if (vu->cfunc->entry_ea != func_start)
				{
					vu = nullptr;
					cJSON_AddStringToObject(response.result.get(), "error", "The pseudocode of the current window does not belong to the objective function");
					response.success = false;
					return response;
				}
			}
		}

		if (vu == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "There is no valid pseudocode in the current window. Please switch to SwitchPseudoCodeTo first");
			response.success = false;
			return response;

		}

		cfunc_t* cfunc = vu->cfunc;
		lvars_t* lvars = cfunc->get_lvars();

		cJSON* variables = cJSON_CreateArray();
		cJSON_AddItemToObject(response.result.get(), "variables", variables);

		if (lvars == nullptr || lvars->empty())
		{
			cJSON_AddStringToObject(response.result.get(), "info",
				("No local variables found in function 0x" + Tools::decToHex(func_start)).c_str());
			response.success = true;
			return response;
		}

		for (size_t i = 0; i < lvars->size(); ++i)
		{
			lvar_t* var = &(*lvars)[i];
			if (var == nullptr) continue;

			qstring validatedName = var->name;
			if (!validate_name(&validatedName, VNT_IDENT))
				continue;

			stripName(&validatedName, false);
			if (validatedName.empty())
				continue;

			qstring locStr = { 0 };
			if (var->location.is_stkoff())
			{
				locStr.sprnt("stack offset: 0x%X", var->location.stkoff());
			}
			else if (var->location.is_reg1())
			{
				int reg_idx = var->location.reg1();
				if (reg_idx >= 0 && reg_idx < PH.regs_num)
				{
					const char* regName = PH.reg_names[reg_idx];
					locStr.sprnt("register: %s", regName ? regName : "unknown");
				}
				else
				{
					locStr = "register: invalid index";
				}
			}
			else
			{
				locStr = "location: unknown";
			}

			tinfo_t varType = var->type();
			qstring typeStr = varType.dstr();
			if (!varType.empty())
			{
				varType.print(&typeStr);
			}
			else
			{
				typeStr = "unknown type";
			}

			cJSON* varObj = cJSON_CreateObject();
			if (varObj != nullptr)
			{
				cJSON_AddStringToObject(varObj, "name", validatedName.c_str());
				cJSON_AddStringToObject(varObj, "location", locStr.c_str());
				cJSON_AddNumberToObject(varObj, "width_bytes", var->width);
				cJSON_AddStringToObject(varObj, "type", typeStr.c_str());
				cJSON_AddBoolToObject(varObj, "is_user_defined", var->has_user_name());
				cJSON_AddNumberToObject(varObj, "index", i);
				cJSON_AddItemToArray(variables, varObj);
			}
		}

		cJSON_AddStringToObject(response.result.get(), "function_address",
			("0x" + Tools::decToHex(func_start)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "found_variables_count",
			cJSON_GetArraySize(variables));

		response.success = true;
		return response;
	}

	static ResponseData handle_set_function_var_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() < 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing parameters. Required: function_address, var_index, new_name");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		uint64_t func_addr_val = strtoull(params[0].c_str(), &endptr, 0);
		if (*endptr != '\0' || endptr == params[0].c_str() || func_addr_val > UINT64_MAX)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid function address format");
			response.success = false;
			return response;
		}
		ea_t func_ea = static_cast<ea_t>(func_addr_val);

		if (func_ea == BADADDR || get_func(func_ea) == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				("Invalid function address: 0x" + Tools::decToHex(func_ea)).c_str());
			response.success = false;
			return response;
		}

		ssize_t var_idx;
		try
		{
			var_idx = std::stoll(params[1]);
		}
		catch (const std::invalid_argument&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid variable index format");
			response.success = false;
			return response;
		}
		catch (const std::out_of_range&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Variable index out of range");
			response.success = false;
			return response;
		}

		const char* new_name = params[2].c_str();
		if (new_name == nullptr || *new_name == '\0')
		{
			cJSON_AddStringToObject(response.result.get(), "error", "New variable name cannot be empty");
			response.success = false;
			return response;
		}

		ea_t result_ea = renameLocalVarByFuncAddr(func_ea, var_idx, new_name);
		if (result_ea != BADADDR && result_ea == func_ea)
		{
			cJSON_AddStringToObject(response.result.get(), "function_address",
				("0x" + Tools::decToHex(func_ea)).c_str());
			cJSON_AddNumberToObject(response.result.get(), "var_index", var_idx);
			cJSON_AddStringToObject(response.result.get(), "new_name", new_name);
			cJSON_AddStringToObject(response.result.get(), "message", "Local variable renamed successfully");
			response.success = true;
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				("Failed to rename variable. Possible reasons: invalid index, invalid name, or function not found"));
			cJSON_AddNumberToObject(response.result.get(), "var_index", var_idx);
			cJSON_AddStringToObject(response.result.get(), "attempted_name", new_name);
			response.success = false;
		}

		return response;
	}

	static ResponseData handle_get_struct_member_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() < 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing parameters: struct_name and offset required");
			response.success = false;
			return response;
		}

		qstring struct_name(params[0].c_str());
		if (struct_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Struct name cannot be empty");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		uint32 offset = static_cast<uint32>(strtoull(params[1].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[1].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid offset format");
			response.success = false;
			return response;
		}

		tinfo_t udt = get_types_name(struct_name.c_str(), false);
		if (udt.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("Failed to get type info for struct: ") + struct_name.c_str()).c_str());
			response.success = false;
			return response;
		}

		udt.remove_ptr_or_array();
		if (!udt.is_udt())
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("Type '") + struct_name.c_str() + "' is not a struct/union (UDT)").c_str());
			response.success = false;
			return response;
		}

		udm_t memb;
		memb.offset = offset;
		if (-1 == udt.find_udm(&memb, STRMEM_AUTO))
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("No member found at offset 0x") + Tools::decToHex(offset).c_str() +
					" in struct: " + struct_name.c_str()).c_str());
			response.success = false;
			return response;
		}

		cJSON* member_info = cJSON_CreateObject();

		cJSON_AddStringToObject(member_info, "struct_name", struct_name.c_str());
		cJSON_AddStringToObject(member_info, "member_name", memb.name.c_str());
		cJSON_AddNumberToObject(member_info, "offset_bits", memb.offset);
		cJSON_AddNumberToObject(member_info, "offset_bytes", memb.offset / 8);
		cJSON_AddNumberToObject(member_info, "size_bits", memb.size);
		cJSON_AddNumberToObject(member_info, "size_bytes", memb.size / 8);

		qstring type_str = { 0 };
		memb.type.print(&type_str);
		cJSON_AddStringToObject(member_info, "type", type_str.c_str());
		cJSON_AddNumberToObject(member_info, "effective_alignment_bytes", memb.effalign);
		cJSON_AddNumberToObject(member_info, "field_alignment_shift", memb.fda);

		cJSON* flags = cJSON_CreateObject();
		cJSON_AddBoolToObject(flags, "is_bitfield", memb.is_bitfield());
		cJSON_AddBoolToObject(flags, "is_zero_length_bitfield", memb.is_zero_bitfield());
		cJSON_AddBoolToObject(flags, "is_unaligned", memb.is_unaligned());
		cJSON_AddBoolToObject(flags, "is_baseclass_member", memb.is_baseclass());
		cJSON_AddBoolToObject(flags, "is_virtual_baseclass_member", memb.is_virtbase());
		cJSON_AddBoolToObject(flags, "is_vftable_member", memb.is_vftable());
		cJSON_AddBoolToObject(flags, "is_method_member", memb.is_method());
		cJSON_AddBoolToObject(flags, "is_gap", memb.is_gap());
		cJSON_AddBoolToObject(flags, "is_anonymous", memb.is_anonymous_udm());
		cJSON_AddItemToObject(member_info, "flags", flags);

		cJSON_AddItemToObject(response.result.get(), "member_info", member_info);
		response.success = true;

		return response;
	}

	static ResponseData handle_set_struct_member_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() < 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				"Missing parameters: struct_name, offset and new_member_name required");
			response.success = false;
			return response;
		}

		qstring struct_name(params[0].c_str());
		if (struct_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Struct name cannot be empty");
			response.success = false;
			return response;
		}

		char* endptr = nullptr;
		uint32 offset = static_cast<uint32>(strtoull(params[1].c_str(), &endptr, 0));
		if (*endptr != '\0' || endptr == params[1].c_str())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid offset format");
			response.success = false;
			return response;
		}

		qstring new_member_name(params[2].c_str());
		if (new_member_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "New member name cannot be empty");
			response.success = false;
			return response;
		}

		tinfo_t udt = get_types_name(struct_name.c_str(), false);
		if (udt.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("Failed to get type info for struct: ") + struct_name.c_str()).c_str());
			response.success = false;
			return response;
		}

		udt.remove_ptr_or_array();
		if (!udt.is_udt())
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("Type '") + struct_name.c_str() + "' is not a struct/union (UDT)").c_str());
			response.success = false;
			return response;
		}

		udm_t memb;
		memb.offset = offset;
		int midx = udt.find_udm(&memb, STRMEM_AUTO);
		if (midx == -1)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("No member found at offset 0x") + Tools::decToHex(offset).c_str() +
					" in struct: " + struct_name.c_str()).c_str());
			response.success = false;
			return response;
		}

		if (!strncmp(memb.name.c_str(), "VT_", 3) || memb.name == VTBL_MEMNAME)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("Cannot rename system-reserved member '") + memb.name.c_str() + "'").c_str());
			response.success = false;
			return response;
		}

		qstring newName = findnext_udm_name(udt, memb.offset, new_member_name.c_str());
		if (newName.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("Invalid member name: '") + new_member_name.c_str() + "'").c_str());
			response.success = false;
			return response;
		}

		qstring oldName = memb.name;
		if (udt.rename_udm(midx, newName.c_str()) != TERR_OK)
		{
			cJSON_AddStringToObject(response.result.get(), "error",
				(std::string("Failed to rename member '") + oldName.c_str() +
					"' to '" + newName.c_str() + "'").c_str());
			response.success = false;
			return response;
		}

		cJSON* result = cJSON_CreateObject();
		cJSON_AddStringToObject(result, "struct_name", struct_name.c_str());
		cJSON_AddNumberToObject(result, "offset_bytes", offset / 8);
		cJSON_AddStringToObject(result, "old_member_name", oldName.c_str());
		cJSON_AddStringToObject(result, "new_member_name", newName.c_str());
		cJSON_AddStringToObject(result, "status", "Member renamed successfully");
		cJSON_AddItemToObject(response.result.get(), "rename_result", result);

		response.success = true;
		return response;
	}

	static ResponseData handle_get_current_select(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected! This interface gets current widget and selection info.");
			response.success = false;
			return response;
		}

		TWidget* current_widget = get_current_viewer();
		if (current_widget == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to get current active widget");
			response.success = false;
			return response;
		}

		int widget_type = get_widget_type(current_widget);
		qstring widget_title = { 0 };
		get_widget_title(&widget_title, current_widget);

		ea_t start_ea = 0, end_ea = 0;
		read_range_selection(current_widget, &start_ea, &end_ea);
		ea_t ea = get_screen_ea();

		cJSON_AddNumberToObject(response.result.get(), "screen_ea", ea);
		cJSON_AddStringToObject(response.result.get(), "screen_ea_hex", ("0x" + Tools::decToHex(ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "selection_start_ea", start_ea);
		cJSON_AddStringToObject(response.result.get(), "selection_start_ea_hex", ("0x" + Tools::decToHex(start_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "selection_end_ea", end_ea);
		cJSON_AddStringToObject(response.result.get(), "selection_end_ea_hex", ("0x" + Tools::decToHex(end_ea)).c_str());
		cJSON_AddNumberToObject(response.result.get(), "widget_type_code", widget_type);
		const char* title_str = widget_title.empty() ? "Unknown" : widget_title.c_str();
		cJSON_AddStringToObject(response.result.get(), "widget_title", title_str);
		bool has_valid_selection = (start_ea != 0 || end_ea != 0) && (start_ea < end_ea);
		cJSON_AddBoolToObject(response.result.get(), "has_valid_selection", has_valid_selection);

		response.success = true;
		return response;
	}
};

class RequestHandler
{
public:
	ResponseData handle_request(const RequestData& data)
	{
		switch (data.type)
		{
		case RequestType::Info_GetBasicInfo:
			return DebuggerHandler::handle_get_basic_info(data.params);

		case RequestType::Info_GetImageInfo:
			return DebuggerHandler::handle_get_image_info(data.params);

		case RequestType::Function_GetFunction:
			return FunctionHandler::handle_get_function(data.params);

		case RequestType::Function_GetFunctionInfo:
			return FunctionHandler::handle_get_function_info(data.params);

		case RequestType::Function_GetFunctionCount:
			return FunctionHandler::handle_get_function_count(data.params);

		case RequestType::Function_GetFunctionByAddr:
			return FunctionHandler::handle_get_function_by_addr(data.params);

		case RequestType::Function_GetFunctionByName:
			return FunctionHandler::handle_get_function_by_name(data.params);

		case RequestType::Function_FindFunctionByName:
			return FunctionHandler::handle_find_function_by_name(data.params);

		case RequestType::Function_GetImportFunctions:
			return FunctionHandler::handle_get_import_functions(data.params);

		case RequestType::Segment_GetSegmentCount:
			return SegmentHandler::handle_get_segment_count(data.params);

		case RequestType::Segment_GetSegment:
			return SegmentHandler::handle_get_segment(data.params);

		case RequestType::Segment_GetSegmentFromAddr:
			return SegmentHandler::handle_get_segment_from_addr(data.params);

		case RequestType::Reverse_GetMicroCode:
			return ReverseHandler::handle_get_micro_code(data.params);

		case RequestType::Reverse_DeompileChecked:
			return ReverseHandler::handle_decompile_checked(data.params);

		case RequestType::Reverse_DecompileFunctionFromAddr:
			return ReverseHandler::handle_decompile_by_address(data.params);

		case RequestType::Reverse_DecompileFunctionFromName:
			return ReverseHandler::handle_decompile_by_name(data.params);

		case RequestType::Reverse_DisassembleFunction:
			return ReverseHandler::handle_disassemble_function(data.params);

		case RequestType::Reverse_DisassemblyCount:
			return ReverseHandler::handle_disassembly_count(data.params);

		case RequestType::Reverse_DisassemblyRange:
			return ReverseHandler::handle_disassembly_range(data.params);

		case RequestType::Reverse_DecompileAddressToLine:
			return ReverseHandler::handle_decompile_address_to_line(data.params);

		case RequestType::Reverse_DecompileLineToAddress:
			return ReverseHandler::handle_decompile_line_to_address(data.params);

		case RequestType::Reverse_GetSelectDecompile:
			return ReverseHandler::handle_get_select_decompile(data.params);

		case RequestType::Reverse_GetSelectDisassembly:
			return ReverseHandler::handle_get_select_disassembly(data.params);

		case RequestType::Reverse_GetSelectHex:
			return ReverseHandler::handle_get_select_hex(data.params);

		case RequestType::Memory_GetEntryPoints:
			return MemoryHandle::handle_get_entry_points(data.params);

		case RequestType::Memory_GetDefinedStruct:
			return MemoryHandle::handle_get_defined_struct(data.params);

		case RequestType::Memory_GetMemoryBytes:
			return MemoryHandle::handle_get_memory_bytes(data.params);

		case RequestType::Memory_GetMemoryByte:
			return MemoryHandle::handle_get_memory_byte(data.params);

		case RequestType::Memory_GetMemoryWord:
			return MemoryHandle::handle_get_memory_word(data.params);

		case RequestType::Memory_GetMemoryDword:
			return MemoryHandle::handle_get_memory_dword(data.params);

		case RequestType::Memory_GetMemoryQword:
			return MemoryHandle::handle_get_memory_qword(data.params);

		case RequestType::Memory_GetStringInfo:
			return MemoryHandle::handle_get_string_info(data.params);

		case RequestType::Memory_MemorySearch:
			return MemoryHandle::handle_memory_search(data.params);

		case RequestType::Memory_GetTypeByName:
			return MemoryHandle::handle_get_type_by_name(data.params);

		case RequestType::Memory_XrefCodeFirstTo:
			return MemoryHandle::handle_xref_code_first_to(data.params);

		case RequestType::Memory_XrefCodeFirstFrom:
			return MemoryHandle::handle_xref_code_first_from(data.params);

		case RequestType::Memory_XrefDataFirstTo:
			return MemoryHandle::handle_xref_data_first_to(data.params);

		case RequestType::Memory_XrefDataFirstFrom:
			return MemoryHandle::handle_xref_data_first_from(data.params);

		case RequestType::Memory_XrefCodeToArray:
			return MemoryHandle::handle_xref_code_first_to_array(data.params);

		case RequestType::Memory_XrefCodeFromArray:
			return MemoryHandle::handle_xref_code_first_from_array(data.params);

		case RequestType::Memory_XrefDataToArray:
			return MemoryHandle::handle_xref_data_first_to_array(data.params);

		case RequestType::Memory_XrefDataFromArray:
			return MemoryHandle::handle_xref_data_first_from_array(data.params);

		case RequestType::Memory_XrefGetListArray:
			return MemoryHandle::handle_xref_get_list_array(data.params);

		case RequestType::Other_SetAssemblyComment:
			return OtherHandle::handle_set_assembly_comment(data.params);

		case RequestType::Other_SetFunctionComment:
			return OtherHandle::handle_set_function_comment(data.params);

		case RequestType::Other_GetFunctionName:
			return OtherHandle::handle_get_function_name(data.params);

		case RequestType::Other_SetFunctionName:
			return OtherHandle::handle_set_function_name(data.params);

		case RequestType::Other_GetFunctionVarName:
			return OtherHandle::handle_get_function_var_name(data.params);

		case RequestType::Other_SetFunctionVarName:
			return OtherHandle::handle_set_function_var_name(data.params);

		case RequestType::Other_SwitchPseudoCodeTo:
			return OtherHandle::handle_switch_pseudocode_to(data.params);

		case RequestType::Other_GetStructMemberName:
			return OtherHandle::handle_get_struct_member_name(data.params);

		case RequestType::Other_SetStructMemberName:
			return OtherHandle::handle_set_struct_member_name(data.params);

		case RequestType::Other_GetCurrentSelect:
			return OtherHandle::handle_get_current_select(data.params);

		default:
			ResponseData response;
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown request type");
			return response;
		}
	}
};

static std::unique_ptr<ServerContext> g_server;

static DWORD WINAPI server_thread_func(LPVOID param)
{
	while (g_server->running)
	{
		mg_mgr_poll(&g_server->mgr, 100);
	}

	return 0;
}

static void handle_post_request(struct mg_http_message* http_msg, struct mg_connection* connection)
{
	CJsonPtr req_json(cJSON_ParseWithLength(http_msg->body.buf, http_msg->body.len));
	if (!req_json)
	{
		const char* error = cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "Unknown parse error";
		mg_http_reply(connection, 400, "Content-Type: application/json\r\n",
			"{\"status\": \"error\", \"error\": \"Invalid JSON: %s\"}", error);
		return;
	}

	RequestData req_data = RequestParser::parse(req_json.get());
	if (req_data.type == RequestType::Unknown)
	{
		mg_http_reply(connection, 400, "Content-Type: application/json\r\n",
			"{\"status\": \"error\", \"error\": \"Invalid or unsupported request parameters\"}");
		return;
	}

	ResponseData resp_data = g_server->handler->handle_request(req_data);

	CJsonPtr resp_json(cJSON_CreateObject());
	cJSON_AddStringToObject(resp_json.get(), "status", resp_data.success ? "success" : "error");
	cJSON_AddItemToObject(resp_json.get(), "result", resp_data.result.release());
	cJSON_AddNumberToObject(resp_json.get(), "timestamp", static_cast<double>(mg_millis()));

	char* resp_str = cJSON_PrintUnformatted(resp_json.get());
	if (resp_str)
	{
		mg_http_reply(connection, resp_data.success ? 200 : 400,
			"Content-Type: application/json\r\n", "%s", resp_str);
		free(resp_str);
	}
	else
	{
		mg_http_reply(connection, 500, "Content-Type: application/json\r\n",
			"{\"status\": \"error\", \"error\": \"Failed to generate response\"}");
	}
}

static void ev_handler(struct mg_connection* connection, int ev, void* ev_data)
{
	if (ev == MG_EV_HTTP_MSG)
	{
		struct mg_http_message* http_msg = static_cast<struct mg_http_message*>(ev_data);

		if (mg_strcmp(http_msg->method, mg_str("GET")) != 0 &&
			mg_strcmp(http_msg->method, mg_str("POST")) != 0)
		{
			mg_http_reply(connection, 405,
				"Content-Type: application/json\r\nAllow: GET, POST\r\n",
				"{\"status\": \"error\", \"error\": \"Method not allowed. Use GET or POST.\"}");
			return;
		}

		if (mg_strcmp(http_msg->method, mg_str("GET")) == 0 &&
			mg_strcmp(http_msg->uri, mg_str("/")) == 0)
		{
			const char* plugin_version = PLUGIN_VERSION;
			const char* author = "WangRui";
			const char* description = "IDA Pro Moles Interface";
			const char* compile_date = __DATE__;
			const char* compile_time = __TIME__;
			const char* supported_apis = "Info, Module, Function, Segment, Reverse, Memory, Other";

			mg_http_reply(connection, 200, "Content-Type: application/json\r\n",
				"{"
				"\"status\": \"success\","
				"\"plugin_info\": {"
				"\"version\": \"%s\","
				"\"author\": \"%s\","
				"\"description\": \"%s\","
				"\"compile_date\": \"%s\","
				"\"compile_time\": \"%s\","
				"\"github\": \"https://github.com/lyshark/ida-moles\""
				"}",
				plugin_version,
				author,
				description,
				compile_date,
				compile_time,
				supported_apis
			);
			return;
		}

		if (mg_strcmp(http_msg->method, mg_str("POST")) == 0 &&
			mg_strcmp(http_msg->uri, mg_str("/")) == 0)
		{
			handle_post_request(http_msg, connection);
		}
		else
		{
			mg_http_reply(connection, 404, "Content-Type: application/json\r\n",
				"{\"status\": \"error\", \"error\": \"Resource not found\"}");
		}
	}
}

static bool start_server()
{
	if (g_server->running)
	{
		msg("HTTP server is already running on %s\n", g_server->listen_addr.c_str());
		return true;
	}

	struct mg_connection* listener = mg_http_listen(&g_server->mgr,
		g_server->listen_addr.c_str(), ev_handler, nullptr);

	if (!listener)
	{
		char err_msg[256];
		strerror_s(err_msg, sizeof(err_msg), MG_SOCKET_ERRNO);
		msg("Failed to start server on %s: %s\n", g_server->listen_addr.c_str(), err_msg);
		return false;
	}

	g_server->running = true;
	bool thread_created = false;

	g_server->thread = ThreadUtils::create_thread(server_thread_func);
	thread_created = (g_server->thread != nullptr);

	if (!thread_created)
	{
		g_server->running = false;
		msg("Failed to create server thread\n");
		return false;
	}

	msg("Server started successfully on %s\n", g_server->listen_addr.c_str());
	return true;
}

plugmod_t* idaapi init_plugin()
{
#if IDA_SDK_VERSION < 910
	msg("This plugin requires IDA 9.1 or higher! Current SDK version: %d\n", IDA_SDK_VERSION);
	return PLUGIN_SKIP;
#endif

	msg("IDA Moles Server plugin initializing...\n");

	if (!init_hexrays_plugin(0))
	{
		msg("Error: Failed to initialize Hex-Rays (mismatched SDK/Decompiler version)\n");
		return PLUGIN_SKIP;
	}

	g_server = std::make_unique<ServerContext>();
	g_server->listen_addr = "http://0.0.0.0:8000";
	g_server->handler = new RequestHandler();

	start_server();
	return PLUGIN_KEEP;
}

void idaapi term_plugin()
{
	if (g_server->running)
	{
		msg("Stopping Moles server...\n");
		g_server->running = false;
		ThreadUtils::join_thread(g_server->thread);
		msg("Server stopped\n");
	}

	if (g_server->handler)
	{
		delete g_server->handler;
		g_server->handler = nullptr;
	}

	term_hexrays_plugin();
	g_decompiled_code.clear();

	g_server.reset();
	msg("Plugin terminated!\n");
}

bool idaapi run_plugin(size_t arg)
{
	if (!g_server->running)
	{
		return start_server();
	}
	else
	{
		msg("Moles server is already running on %s\n", g_server->listen_addr.c_str());
		return true;
	}
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_UNL,
	init_plugin,
	term_plugin,
	run_plugin,
	"IDA Moles",
	"Provides Automate interface to IDA Pro Moles functionality",
	"IDA Moles"
};
