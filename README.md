# IDA-Moles Static Reverse Analysis Component

<img src="https://github.com/user-attachments/assets/60f86fb4-04fb-45d7-88ab-f64e5e7516d0" alt="ladyida" width="12%">

IDA Moles is a professional reverse analysis interface tool specifically designed for IDA Pro 9.1 and compatible with Python 3.8 and above. Centered around standardized call logic, this tool efficiently controls IDA Pro to perform various reverse operations including disassembly, decompilation, and memory analysis. It features comprehensive core capabilities such as efficient decompilation control, advanced debugging, memory analysis, function parsing, MCP server extension, and automated batch processing. Not only does it enable basic reverse operations like pseudocode acquisition, breakpoint setting, memory layout analysis, and function information parsing, but it also supports custom MCP server interface development to meet customized requirements. Furthermore, it allows for automation of reverse analysis workflows and batch processing of large sample sets through its programming interface, significantly enhancing the efficiency and flexibility of reverse analysis to meet the demands of complex reverse analysis scenarios.

## Quick Installation

1. First, users need to quickly install and deploy via `PIP`. Open the command prompt or terminal and execute the following command to install the latest version of the `IDA Moles` development toolkit.

```bash
CMD> pip install idamoles
CMD> pip show idamoles
Name: IDAMoles
Version: 1.0.7
Summary: 
IDA Moles is a reverse analysis interface for IDA Pro 9.1. 
It controls decompilation, debugging, and other operations via standardized calls, 
returning POST-formatted results. 
It supports custom MCP server development to enhance reverse analysis efficiency and flexibility.
Home-page: http://moles.lyshark.com
Author: lyshark
Author-email: me@lyshark.com
License: MIT Licence
Location: C:\Users\admin\site-packages
```

2. Now begin installing the IDAMoles driver files. Locate the `D://IDA Professional 9.1` directory and execute the installation command to complete the plugin deployment.

```bash
CMD> python
Python 3.13.7 (tags/v3.13.7:bcee1c3, Aug 14 2025, 14:15:11) 
[MSC v.1944 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>>
>>> from IDAMoles import *
>>> config = Config(address="127.0.0.1",port=8000)
>>> config.set_ida_path("D://IDA Professional 9.1")
The IDA path has been set to: d:\idapro9.1\plugins
>>>
>>> config.open_ida_with_program("C://win32.exe",auto_mode=True,force_new=True)
SUCCESS: IDA has been started and the program has been loaded:C://win32.exe
```

Simply configure the IDA Pro path and install the plugin to complete the environment setup and load the target program for analysis.

## Interface Specification

This component is developed based on the IDA 9.1 standard C++ SDK development toolkit. Despite lacking effective reference documentation and technical support, the author successfully implemented over 50 core features within one month by understanding IDA reverse analysis principles. These features are systematically categorized into six major modules based on their functional attributes:

 - Info (Information Parsing)
 - Function (Function Analysis)
 - Segment (Segment Processing)
 - Reverse (Reverse Analysis)
 - Memory (Memory Operations)
 - Other (General Utilities)

Each module encompasses dozens of interface capabilities. These interfaces not only cover core scenarios such as binary analysis, code reverse engineering, and memory parsing but also establish the underlying technical foundation required for AI intelligent analysis, providing solid and extensible technical support for the implementation of advanced capabilities like intelligent analysis and automated reverse engineering.

### Information Parsing

The Information Parsing module is responsible for extracting basic metadata from the target program, quickly acquiring core attributes such as file structure, load base address, compilation information, and runtime environment. It provides a global view and environmental basis for subsequent reverse analysis, serving as the starting point for automated analysis workflows.

#### get_basic_info

Call the GetBasicInfo interface of the server-side Info class to obtain basic information about the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Info(config)

    print(info_page.get_basic_info())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "basic_version_info": {
      "database_version": 910,
      "processor_name": "metapc",
      "raw_genflags": 3,
      "auto_analysis_enabled": true,
      "is_idb_readonly": false,
      "current_view_is_graph": false
    },
    "bitness_attr_info": {
      "app_bitness": 32,
      "is_16bit": false,
      "is_32bit": true,
      "is_64bit": false,
      "is_dll": false,
      "is_kernel_mode": false,
      "is_big_endian": false
    },
    "file_system_info": {
      "file_type": "Portable Executable (PE)",
      "file_type_code": 11,
      "os_type": "Windows 16-bit",
      "app_type": "Unknown application type",
      "assembler_type": "Intel Syntax",
      "database_change_count": 10
    },
    "analysis_config_info": {
      "raw_analysis_flags": 3758096375,
      "trace_exec_flow": true,
      "create_jump_tables": true,
      "create_stack_vars": true,
      "trace_stack_pointer": true
    },
    "inftag_info": {
      "INF_VERSION": "910",
      "INF_PROCNAME": "N/A",
      "INF_GENFLAGS": "0x3",
      "INF_LFLAGS": "0x203",
      "INF_DATABASE_CHANGE_COUNT": "10",
      "INF_FILETYPE": "11",
      "INF_OSTYPE": "2",
      "INF_APPTYPE": "260",
      "INF_ASMTYPE": "0",
      "INF_SPECSEGS": "0",
      "INF_AF": "0xdffffff7",
      "UNKNOWN_TAG_11": "0xf",
      "INF_BASEADDR": "0x0",
      "UNKNOWN_TAG_13": "0xffffffffffffffff",
      "UNKNOWN_TAG_14": "0x1",
      "UNKNOWN_TAG_15": "0x401534",
      "INF_START_EA": "0x401534",
      "UNKNOWN_TAG_17": "0xffffffffffffffff",
      "UNKNOWN_TAG_18": "0x401000",
      "INF_MIN_EA": "0x401000",
      "INF_MAX_EA": "0x405000",
      "UNKNOWN_TAG_21": "0x401000",
      "UNKNOWN_TAG_22": "0x405000",
      "UNKNOWN_TAG_23": "0x401000",
      "UNKNOWN_TAG_24": "0x405000",
      "UNKNOWN_TAG_25": "0x10",
      "UNKNOWN_TAG_26": "0x0",
      "UNKNOWN_TAG_27": "0xff00000000000000",
      "UNKNOWN_TAG_28": "0xff00000000800000",
      "UNKNOWN_TAG_29": "0x0",
      "UNKNOWN_TAG_30": "0x2",
      "UNKNOWN_TAG_31": "0x2",
      "UNKNOWN_TAG_32": "0x10",
      "UNKNOWN_TAG_33": "0xf",
      "UNKNOWN_TAG_34": "0xf",
      "UNKNOWN_TAG_35": "0x6",
      "UNKNOWN_TAG_36": "0xea3be67",
      "UNKNOWN_TAG_37": "0x6400007",
      "UNKNOWN_TAG_38": "0x4",
      "UNKNOWN_TAG_39": "0x7",
      "UNKNOWN_TAG_40": "0x10",
      "UNKNOWN_TAG_41": "0x28",
      "UNKNOWN_TAG_42": "0x46",
      "UNKNOWN_TAG_43": "0x50",
      "UNKNOWN_TAG_44": "0x774",
      "UNKNOWN_TAG_45": "0x1",
      "UNKNOWN_TAG_46": "0x3",
      "UNKNOWN_TAG_47": "0x0",
      "UNKNOWN_TAG_48": "0x1",
      "UNKNOWN_TAG_49": "0x13",
      "UNKNOWN_TAG_50": "0xa",
      "UNKNOWN_TAG_51": "0x0",
      "UNKNOWN_TAG_52": "0x0",
      "UNKNOWN_TAG_53": "0x0",
      "UNKNOWN_TAG_54": "0x0",
      "UNKNOWN_TAG_55": "0x7",
      "UNKNOWN_TAG_56": "0x0",
      "UNKNOWN_TAG_57": "0x1",
      "UNKNOWN_TAG_58": "0x33",
      "UNKNOWN_TAG_59": "0x4",
      "UNKNOWN_TAG_60": "0x1",
      "UNKNOWN_TAG_61": "0x4",
      "UNKNOWN_TAG_62": "0x0",
      "UNKNOWN_TAG_63": "0x2",
      "UNKNOWN_TAG_64": "0x4",
      "UNKNOWN_TAG_65": "0x8",
      "UNKNOWN_TAG_66": "0x8",
      "UNKNOWN_TAG_67": "0x0",
      "UNKNOWN_TAG_68": "0x0",
      "UNKNOWN_TAG_69": "0x0",
      "UNKNOWN_TAG_70": "0x0",
      "UNKNOWN_TAG_71": "0x0",
      "UNKNOWN_TAG_72": "0x0",
      "UNKNOWN_TAG_73": "0x0",
      "UNKNOWN_TAG_74": "0x0",
      "UNKNOWN_TAG_75": "0x0",
      "UNKNOWN_TAG_76": "0x0",
      "INF_IDA_VERSION": "N/A",
      "UNKNOWN_TAG_78": "0x0",
      "UNKNOWN_TAG_79": "0x0",
      "UNKNOWN_TAG_80": "0x0",
      "UNKNOWN_TAG_81": "0x0",
      "UNKNOWN_TAG_82": "0x0",
      "UNKNOWN_TAG_83": "0x0",
      "UNKNOWN_TAG_84": "0x0",
      "UNKNOWN_TAG_85": "0x0",
      "UNKNOWN_TAG_86": "0x0",
      "UNKNOWN_TAG_87": "0x0",
      "UNKNOWN_TAG_88": "0x38e",
      "UNKNOWN_TAG_89": "0x69abc696",
      "UNKNOWN_TAG_90": "0x58",
      "UNKNOWN_TAG_91": "0x1",
      "UNKNOWN_TAG_92": "0xad2851a2",
      "INF_IMAGEBASE": "0x400000",
      "UNKNOWN_TAG_94": "0x0",
      "INF_FSIZE": "104960 bytes",
      "UNKNOWN_TAG_96": "0x0",
      "INF_INPUT_FILE_PATH": "N/A"
    },
    "input_file_hash": {
      "md5": "4bfd4d3d1868ddf4869df158d9eadbcb",
      "crc32": "AD2851A2",
      "sha256": "9145169db07de87fa73973a069dc89feca9a785c3a7ea00cf87c082393992ab2"
    },
    "statistical_info": {
      "database_filename": "win32.exe",
      "file_extension": "exe",
      "dbctx_count": 1,
      "supported_encoding_count": 4,
      "program_segment_count": 5,
      "recognized_function_count": 73,
      "imported_module_count": 8,
      "function_chunk_count": 73,
      "hidden_range_count": 0,
      "ida_assigned_symbol_count": 3,
      "memory_mapping_count": 0,
      "thread_count": 0
    }
  },
  "timestamp": 22921484
}
```

#### get_image_info

Call the GetImageInfo interface of the server-side Info class to obtain image-related information about the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Info(config)

    print(info_page.get_image_info())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "omin_ea": 4198400,
    "omax_ea": 4214784,
    "image_size": 16384,
    "omin_ea_hex": "0x401000",
    "omax_ea_hex": "0x405000",
    "image_size_hex": "0x4000"
  },
  "timestamp": 23367984
}
```

### Function Analysis

The Function Analysis module focuses on the smallest unit of program execution flow, implementing function enumeration, address location, name retrieval, boundary identification, and import table parsing. It precisely establishes an indexing system for all functions within the program, providing key support for code understanding, vulnerability location, and logic restoration.

#### get_functions

Call the GetFunction interface of the server-side Function class to obtain a list of all functions in the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_functions())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "functions": [
      {
        "index": 0,
        "name": "_WinMain@16",
        "start_address": 4198400,
        "start_address_hex": "0x401000",
        "end_address": 4198672,
        "end_address_hex": "0x401110",
        "is_entry": true,
        "is_tail": false,
        "bitness": 32,
        "total_size": 272,
        "visible": true,
        "returns": true,
        "flags": {
          "raw_value": 4198672,
          "FUNC_NORET": false,
          "FUNC_FAR": false,
          "FUNC_LIB": false,
          "FUNC_STATICDEF": false,
          "FUNC_FRAME": true,
          "FUNC_THUNK": false,
          "FUNC_SP_READY": false,
          "FUNC_PROLOG_OK": true
        },
        "frame_info": {
          "frame_netnode": 21520,
          "local_vars_size": 0,
          "saved_regs_size": 4096,
          "args_size": 0,
          "frame_delta": 44,
          "color": 0
        }
      },
      {
        "index": 1,
        "name": "sub_401110",
        "start_address": 4198672,
        "start_address_hex": "0x401110",
        "end_address": 4198813,
        "end_address_hex": "0x40119D",
        "is_entry": true,
        "is_tail": false,
        "bitness": 32,
        "total_size": 141,
        "visible": true,
        "returns": true,
        "flags": {
          "raw_value": 4198813,
          "FUNC_NORET": true,
          "FUNC_FAR": false,
          "FUNC_LIB": true,
          "FUNC_STATICDEF": true,
          "FUNC_FRAME": true,
          "FUNC_THUNK": true,
          "FUNC_SP_READY": false,
          "FUNC_PROLOG_OK": true
        },
        "frame_info": {
          "frame_netnode": 21520,
          "local_vars_size": 0,
          "saved_regs_size": 4368,
          "args_size": 0,
          "frame_delta": 52,
          "color": 0
        }
      }
    ]
  },
  "timestamp": 23582281
}
```

#### get_function_info

Receive a function start address parameter, validate the address format, then call the GetFunctionInfo interface of the server-side Function class to obtain detailed information about the function at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_info("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "function_info": {
      "start_address": 4198400,
      "start_address_hex": "0x401000",
      "end_address": 4198672,
      "end_address_hex": "0x401110",
      "size": 272,
      "size_hex": "0x110",
      "frame_id": 21520,
      "frame_id_hex": "0x5410",
      "local_vars_size_bytes": 0,
      "saved_regs_size_bytes": 4096,
      "purged_args_size_bytes": 0,
      "frame_ptr_delta": 44,
      "sp_change_count": 4,
      "reg_var_count": 0,
      "reg_arg_count": 0,
      "tail_count": 0,
      "tail_owner": 21520,
      "tail_owner_hex": "0x5410",
      "tail_ref_count": 0,
      "is_far_func": false,
      "returns": true,
      "sp_analyzed": false,
      "need_prolog_analysis": false,
      "name": "_WinMain@16"
    }
  },
  "timestamp": 23974296
}
```

#### get_import_functions

Call the GetImportFunctions interface of the server-side Function class to obtain a list of imported functions in the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_import_functions())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "import_modules": [
      {
        "module_index": 0,
        "module_name": "USER32",
        "functions": [
          {
            "address": 4202552,
            "address_hex": "0x402038",
            "name": "DefWindowProcW",
            "ordinal": 0
          },
          {
            "address": 4202556,
            "address_hex": "0x40203C",
            "name": "BeginPaint",
            "ordinal": 0
          },
          {
            "address": 4202560,
            "address_hex": "0x402040",
            "name": "DestroyWindow",
            "ordinal": 0
          }
        ]
      }
    ]
  },
  "timestamp": 24135515
}
```

#### get_function_count

Call the GetFunctionCount interface of the server-side Function class to obtain the total number of functions in the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_count())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "total_functions": 73
  },
  "timestamp": 24214328
}
```

#### get_function_by_addr

Receive a function start address parameter, validate the address format, then call the GetFunctionByAddr interface of the server-side Function class to obtain function information by address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_by_addr("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "function": {
      "name": "_WinMain@16",
      "start_address": 4198400,
      "start_address_hex": "0x401000",
      "end_address": 4198672,
      "end_address_hex": "0x401110",
      "is_entry": true,
      "is_tail": false,
      "bitness": 32,
      "total_size": 272,
      "visible": true,
      "returns": true,
      "flags": {
        "raw_value": 4198672,
        "FUNC_NORET": false,
        "FUNC_FAR": false,
        "FUNC_LIB": false,
        "FUNC_STATICDEF": false,
        "FUNC_FRAME": true,
        "FUNC_THUNK": false,
        "FUNC_SP_READY": false,
        "FUNC_PROLOG_OK": true
      },
      "frame_info": {
        "frame_netnode": 21520,
        "local_vars_size": 0,
        "saved_regs_size": 4096,
        "args_size": 0,
        "frame_delta": 44,
        "color": 0
      }
    }
  },
  "timestamp": 24295312
}
```

#### get_function_by_name

Receive a function name parameter, validate it is not empty, then call the GetFunctionByName interface of the server-side Function class to obtain function information by name.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_by_name("_WinMain@16"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "function": {
      "index": 0,
      "name": "_WinMain@16",
      "start_address": 4198400,
      "start_address_hex": "0x401000",
      "end_address": 4198672,
      "end_address_hex": "0x401110",
      "is_entry": true,
      "is_tail": false,
      "bitness": 32,
      "total_size": 272,
      "visible": true,
      "returns": true,
      "flags": {
        "raw_value": 4198672,
        "FUNC_NORET": false,
        "FUNC_FAR": false,
        "FUNC_LIB": false,
        "FUNC_STATICDEF": false,
        "FUNC_FRAME": true,
        "FUNC_THUNK": false,
        "FUNC_SP_READY": false,
        "FUNC_PROLOG_OK": true
      },
      "frame_info": {
        "frame_netnode": 21520,
        "local_vars_size": 0,
        "saved_regs_size": 4096,
        "args_size": 0,
        "frame_delta": 44,
        "color": 0
      }
    }
  },
  "timestamp": 24542015
}
```

#### find_function_by_name

Receive a search keyword parameter, validate it is not empty, then call the FindFunctionByName interface of the server-side Function class to perform fuzzy search for functions containing the keyword.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.find_function_by_name("WinMain"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "functions": [
      {
        "index": 0,
        "name": "_WinMain@16",
        "start_address": 4198400,
        "start_address_hex": "0x401000",
        "end_address": 4198672,
        "end_address_hex": "0x0",
        "is_entry": true,
        "is_tail": false,
        "bitness": 32,
        "total_size": 272,
        "visible": true,
        "returns": true,
        "flags": {
          "raw_value": 4198672,
          "FUNC_NORET": false,
          "FUNC_FAR": false,
          "FUNC_LIB": false,
          "FUNC_STATICDEF": false,
          "FUNC_FRAME": true,
          "FUNC_THUNK": false,
          "FUNC_SP_READY": false,
          "FUNC_PROLOG_OK": true
        },
        "frame_info": {
          "frame_netnode": 21520,
          "local_vars_size": 0,
          "saved_regs_size": 4096,
          "args_size": 0,
          "frame_delta": 44,
          "color": 0
        }
      },
      {
        "index": 54,
        "name": "_get_wide_winmain_command_line",
        "start_address": 4202094,
        "start_address_hex": "0x401E6E",
        "end_address": 4202100,
        "end_address_hex": "0x0",
        "is_entry": true,
        "is_tail": false,
        "bitness": 32,
        "total_size": 6,
        "visible": false,
        "returns": true,
        "flags": {
          "raw_value": 4202100,
          "FUNC_NORET": false,
          "FUNC_FAR": false,
          "FUNC_LIB": true,
          "FUNC_STATICDEF": false,
          "FUNC_FRAME": true,
          "FUNC_THUNK": false,
          "FUNC_SP_READY": true,
          "FUNC_PROLOG_OK": true
        },
        "frame_info": {
          "frame_netnode": 21696,
          "local_vars_size": 0,
          "saved_regs_size": 7790,
          "args_size": 0,
          "frame_delta": 0,
          "color": 0
        }
      }
    ],
    "match_count": 2
  },
  "timestamp": 24607906
}
```

### Segment Processing

The Segment Processing module focuses on program memory segments, supporting capabilities such as segment table reading, segment attribute parsing, and address ownership determination. It can quickly identify key regions like code segments, data segments, and read-only segments, providing a structural foundation for memory layout analysis, data extraction, and instruction location.

#### get_segments

Call the GetSegment interface of the server-side Segment class to obtain a list of all segments in the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Segment(config)

    print(info_page.get_segments())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "segments": [
      {
        "index": 0,
        "name": ".text",
        "start_address": 4198400,
        "start_address_hex": "0x401000",
        "end_address": 0,
        "end_address_hex": "0x0",
        "total_size": 4290768896,
        "type": 255,
        "selector": 0,
        "bitness": 0,
        "permissions": 0,
        "class": "CODE"
      },
      {
        "index": 1,
        "name": ".idata",
        "start_address": 4202496,
        "start_address_hex": "0x402000",
        "end_address": 0,
        "end_address_hex": "0x0",
        "total_size": 4290764800,
        "type": 255,
        "selector": 0,
        "bitness": 0,
        "permissions": 0,
        "class": "DATA"
      },
      {
        "index": 2,
        "name": ".rdata",
        "start_address": 4202752,
        "start_address_hex": "0x402100",
        "end_address": 0,
        "end_address_hex": "0x0",
        "total_size": 4290764544,
        "type": 255,
        "selector": 0,
        "bitness": 0,
        "permissions": 0,
        "class": "DATA"
      },
      {
        "index": 3,
        "name": ".data",
        "start_address": 4206592,
        "start_address_hex": "0x403000",
        "end_address": 0,
        "end_address_hex": "0x0",
        "total_size": 4290760704,
        "type": 255,
        "selector": 0,
        "bitness": 0,
        "permissions": 0,
        "class": "DATA"
      },
      {
        "index": 4,
        "name": ".gfids",
        "start_address": 4210688,
        "start_address_hex": "0x404000",
        "end_address": 0,
        "end_address_hex": "0x0",
        "total_size": 4290756608,
        "type": 255,
        "selector": 0,
        "bitness": 0,
        "permissions": 0,
        "class": "DATA"
      }
    ],
    "total_segments": 5,
    "description": "Segments information based on template"
  },
  "timestamp": 24864687
}
```

#### get_segment_count

Call the GetSegmentCount interface of the server-side Segment class to obtain the total number of segments in the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Segment(config)

    print(info_page.get_segment_count())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "total_segments": 5,
    "description": "Total number of segments in the current disassembled file"
  },
  "timestamp": 24996453
}
```

#### get_segment_from_addr

Receive an address parameter, validate the address format, then call the GetSegmentFromAddr interface of the server-side Segment class to obtain information about the segment containing the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Segment(config)

    print(info_page.get_segment_from_addr("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "parsed_address": 4198400,
    "parsed_address_hex": "0x401000",
    "segment_name": ".text",
    "address": 4198400,
    "address_hex": "0x401000",
    "segment_start": 4198400,
    "segment_start_hex": "0x401000",
    "segment_end": 0,
    "segment_end_hex": "0x0",
    "description": "Segment containing the specified address"
  },
  "timestamp": 25144109
}
```

### Reverse Analysis

The Reverse Analysis module integrates core capabilities such as disassembly, pseudocode restoration, instruction sequence extraction, and code line-address conversion. It enables the transformation from machine instructions to high-level semantics, significantly reducing the cost of manually reading assembly code. It serves as the core engine for deep reverse engineering and logic restoration.

#### disassembly_function

Receive an address parameter, validate the address format, then call the DisassembleFunction interface of the server-side Reverse class to disassemble the function at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.disassembly_function("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "function_info": {
      "start_address": 4198400,
      "start_address_hex": "0x401000",
      "end_address": 4198672,
      "end_address_hex": "0x401110",
      "total_instructions": 100,
      "total_size": 272
    },
    "disassembly": [
      {
        "address": 4198400,
        "address_hex": "0x401000",
        "disassembly": "push    ebp",
        "length": 1,
        "bytes": "55"
      },
      {
        "address": 4198401,
        "address_hex": "0x401001",
        "disassembly": "mov     ebp, esp",
        "length": 2,
        "bytes": "8bec"
      },
      {
        "address": 4198403,
        "address_hex": "0x401003",
        "disassembly": "sub     esp, 24h",
        "length": 3,
        "bytes": "83ec24"
      }
    ]
  },
  "timestamp": 25281343
}
```

#### disassembly_count

Receive address and line count parameters, validate the address format and check that the line count is within the range of 1-1024, then call the DisassemblyCount interface of the server-side Reverse class to disassemble the specified number of instructions starting from the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.disassembly_count("0x401000","3"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "success": true,
    "request_start_address": 4198400,
    "request_start_address_hex": "0x401000",
    "request_line_count": 3,
    "actual_line_count": 3,
    "actual_start_address_hex": "0x401000",
    "actual_end_address_hex": "0x0000000000401006",
    "instructions": [
      {
        "address_hex": "0x401000",
        "address_dec": 4198400,
        "opcode_hex": "55 ",
        "disasm_text": "push    ebp"
      },
      {
        "address_hex": "0x401001",
        "address_dec": 4198401,
        "opcode_hex": "8B EC ",
        "disasm_text": "mov     ebp, esp"
      },
      {
        "address_hex": "0x401003",
        "address_dec": 4198403,
        "opcode_hex": "83 EC 24 ",
        "disasm_text": "sub     esp, 24h"
      }
    ]
  },
  "timestamp": 25588203
}
```

#### disassembly_range

Receive start and end address parameters, validate the address format, then call the DisassemblyRange interface of the server-side Reverse class to disassemble instructions within the specified address range.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.disassembly_range("0x401000","0x401020"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "success": true,
    "request_start_address": 4198400,
    "request_start_address_hex": "0x401000",
    "request_end_address": 4198432,
    "request_end_address_hex": "0x401020",
    "actual_processed_count": 12,
    "actual_start_address_hex": "0x401000",
    "actual_end_address_hex": "0x0000000000401020",
    "instructions": [
      {
        "address_hex": "0x401000",
        "address_dec": 4198400,
        "opcode_hex": "55 ",
        "disasm_text": "push    ebp"
      },
      {
        "address_hex": "0x401001",
        "address_dec": 4198401,
        "opcode_hex": "8B EC ",
        "disasm_text": "mov     ebp, esp"
      },
      {
        "address_hex": "0x401003",
        "address_dec": 4198403,
        "opcode_hex": "83 EC 24 ",
        "disasm_text": "sub     esp, 24h"
      },
      {
        "address_hex": "0x401006",
        "address_dec": 4198406,
        "opcode_hex": "A1 04 30 40 00 ",
        "disasm_text": "mov     eax, ___security_cookie"
      },
      {
        "address_hex": "0x40100B",
        "address_dec": 4198411,
        "opcode_hex": "33 C5 ",
        "disasm_text": "xor     eax, ebp"
      },
      {
        "address_hex": "0x40100D",
        "address_dec": 4198413,
        "opcode_hex": "89 45 FC ",
        "disasm_text": "mov     [ebp+var_4], eax"
      },
      {
        "address_hex": "0x401010",
        "address_dec": 4198416,
        "opcode_hex": "56 ",
        "disasm_text": "push    esi"
      },
      {
        "address_hex": "0x401011",
        "address_dec": 4198417,
        "opcode_hex": "8B 35 80 20 40 00 ",
        "disasm_text": "mov     esi, ds:LoadStringW"
      },
      {
        "address_hex": "0x401017",
        "address_dec": 4198423,
        "opcode_hex": "57 ",
        "disasm_text": "push    edi"
      },
      {
        "address_hex": "0x401018",
        "address_dec": 4198424,
        "opcode_hex": "8B 7D 08 ",
        "disasm_text": "mov     edi, [ebp+hInstance]"
      },
      {
        "address_hex": "0x40101B",
        "address_dec": 4198427,
        "opcode_hex": "6A 64 ",
        "disasm_text": "push    64h ; 'd'; cchBufferMax"
      },
      {
        "address_hex": "0x40101D",
        "address_dec": 4198429,
        "opcode_hex": "68 48 34 ",
        "disasm_text": "push    offset WindowName; lpBuffer"
      }
    ],
    "note": "The specified address range has been completely disassembled"
  },
  "timestamp": 25678687
}
```

#### decompile_checked

Receive an address parameter, validate the address format, then call the DecompileChecked interface of the server-side Reverse class to perform decompilation validation for the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_checked("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "requested_address": 4198400,
    "requested_address_hex": "0x401000",
    "flag": "true"
  },
  "timestamp": 25813265
}
```

#### decompile_micro_code

Receive an address parameter, validate the address format, then call the GetMicroCode interface of the server-side Reverse class to obtain the microcode decompilation result for the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_micro_code("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "function_start_address": 4198400,
    "function_start_address_hex": "0x401000",
    "requested_address": 4198400,
    "requested_address_hex": "0x401000",
    "microcode": "\u0001\u00130. 0 \u0002\u0013\u0001\u0003; STKD=30 MINREF=3C/END=60 ARGS: OFF=64/MINREF=164/END=164/SHADOW=0\u0002\u0003\n\n\u0001\u00130. 0 \u0002\u0013\u0001\u0003; SAVEDREGS: ebp.4,esi.4,edi.4,ebx.4\u0002\u0003\n\n\u0001\u00130. 0 \u0002\u0013\u0001\u0003; 1WAY-BLOCK 0 FAKE OUTBOUNDS: 1 [START=401000 END=401000] MINREFS: STK=60/ARG=164, MAXBSP: 0\u0002\u0003\n\n\u0001\u00130. 0 \u0002\u0013\u0001\u0003; DEF: (eax.4,esi.4,sp+38.8,sp+44.4,arg+0.4,arg+C.4)\u0002\u0003\n\n\u0001\u00130"
  },
  "timestamp": 25935843
}
```

#### decompile_from_addr

Receive an address parameter, validate the address format, then call the DecompileFunctionFromAddr interface of the server-side Reverse class to decompile the corresponding function by address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_from_addr("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "success": true,
    "func_ea": 4198400,
    "func_ea_hex": "0x401000",
    "func_name": "_WinMain@16",
    "pseudocode": "int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)\n{\n  HWND Window; // eax\n  HWND v5; // esi\n  HACCEL hAccTable; // [esp+8h] [ebp-24h]\n  tagMSG Msg; // [esp+Ch] [ebp-20h] BYREF\n\n  LoadStringW(hInstance, 0x67u, &WindowName, 100);\n  LoadStringW(hInstance, 0x6Du, &ClassName, 100);\n  sub_401110(hInstance);\n  ::hInstance = hInstance;\n  Window = CreateWindowExW(0, &ClassName, &WindowName, 0xCF0000u, 0x80000000, 0, 0x80000000, 0, 0, 0, hInstance, 0);\n  v5 = Window;\n  if ( !Window )\n    return 0;\n  ShowWindow(Window, nShowCmd);\n  UpdateWindow(v5);\n  hAccTable = LoadAcceleratorsW(hInstance, (LPCWSTR)0x6D);\n  while ( GetMessageW(&Msg, 0, 0, 0) )\n  {\n    if ( !TranslateAcceleratorW(Msg.hwnd, hAccTable, &Msg) )\n    {\n      TranslateMessage(&Msg);\n      DispatchMessageW(&Msg);\n    }\n  }\n  return Msg.wParam;\n}\n",
    "line_count": 28
  },
  "timestamp": 26053203
}
```

#### decompile_from_name

Receive a function name parameter, validate it is not empty, then call the DecompileFunctionFromName interface of the server-side Reverse class to decompile the corresponding function by name.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_from_name("_WinMain@16"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "success": true,
    "func_ea": 4198400,
    "func_ea_hex": "0x401000",
    "func_name": "_WinMain@16",
    "pseudocode": "int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)\n{\n  HWND Window; // eax\n  HWND v5; // esi\n  HACCEL hAccTable; // [esp+8h] [ebp-24h]\n  tagMSG Msg; // [esp+Ch] [ebp-20h] BYREF\n\n  LoadStringW(hInstance, 0x67u, &WindowName, 100);\n  LoadStringW(hInstance, 0x6Du, &ClassName, 100);\n  sub_401110(hInstance);\n  ::hInstance = hInstance;\n  Window = CreateWindowExW(0, &ClassName, &WindowName, 0xCF0000u, 0x80000000, 0, 0x80000000, 0, 0, 0, hInstance, 0);\n  v5 = Window;\n  if ( !Window )\n    return 0;\n  ShowWindow(Window, nShowCmd);\n  UpdateWindow(v5);\n  hAccTable = LoadAcceleratorsW(hInstance, (LPCWSTR)0x6D);\n  while ( GetMessageW(&Msg, 0, 0, 0) )\n  {\n    if ( !TranslateAcceleratorW(Msg.hwnd, hAccTable, &Msg) )\n    {\n      TranslateMessage(&Msg);\n      DispatchMessageW(&Msg);\n    }\n  }\n  return Msg.wParam;\n}\n",
    "line_count": 28
  },
  "timestamp": 26105687
}
```

#### decompile_line_to_address

Receive address and line number parameters, validate the address format and check that the line number is not empty, then call the DecompileLineToAddress interface of the server-side Reverse class to map the line number of decompiled code to the corresponding memory address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_line_to_address("0x401000","8"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "line_number": 8,
    "function_address": 4198400,
    "function_address_hex": "0x401000",
    "memory_address": 4198437,
    "memory_address_hex": "0x401025"
  },
  "timestamp": 26320421
}
```

#### decompile_address_to_line

Receive an address parameter, validate the address format, then call the DecompileAddressToLine interface of the server-side Reverse class to map the specified address to the line number of decompiled code.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_address_to_line("0x401025"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "line_number": 8,
    "address": 4198437,
    "address_hex": "0x401025"
  },
  "timestamp": 26457390
}
```

#### get_select_decompile

Call the GetSelectDecompile interface of the server-side Reverse class to obtain the decompiled code for the currently selected region.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.get_select_decompile())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "start_ea": 4198502,
    "start_ea_hex": "0x401066",
    "end_ea": 4198535,
    "end_ea_hex": "0x401087",
    "function_start_ea": 4198400,
    "function_start_ea_hex": "0x401000",
    "filtered_pseudocode_lines": [
      {
        "line": 12,
        "address": 4198502,
        "address_hex": "0x401066",
        "pseudocode": "  Window = CreateWindowExW(0, &ClassName, &WindowName, 0xCF0000u, 0x80000000, 0, 0x80000000, 0, 0, 0, hInstance, 0);"
      },
      {
        "line": 13,
        "address": 4198508,
        "address_hex": "0x40106C",
        "pseudocode": "  v5 = Window;"
      },
      {
        "line": 14,
        "address": 4198512,
        "address_hex": "0x401070",
        "pseudocode": "  if ( !Window )"
      },
      {
        "line": 16,
        "address": 4198522,
        "address_hex": "0x40107A",
        "pseudocode": "  ShowWindow(Window, nShowCmd);"
      },
      {
        "line": 17,
        "address": 4198529,
        "address_hex": "0x401081",
        "pseudocode": "  UpdateWindow(v5);"
      }
    ],
    "matched_line_count": 5,
    "has_matched": true
  },
  "timestamp": 26635062
}
```

#### get_select_disassembly

Call the GetSelectDisassembly interface of the server-side Reverse class to obtain the disassembled instructions for the currently selected region.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.get_select_disassembly())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "selected_start_address": 4198582,
    "selected_start_address_hex": "0x4010B6",
    "selected_end_address": 4198598,
    "selected_end_address_hex": "0x4010C6",
    "actual_processed_count": 5,
    "actual_start_address_hex": "0x4010B6",
    "actual_end_address_hex": "0x4010C6",
    "instructions": [
      {
        "address_hex": "0x4010B6",
        "address_dec": 4198582,
        "opcode_hex": "8D 45 E0 ",
        "disasm_text": "lea     eax, [ebp+Msg]"
      },
      {
        "address_hex": "0x4010B9",
        "address_dec": 4198585,
        "opcode_hex": "50 ",
        "disasm_text": "push    eax; lpMsg"
      },
      {
        "address_hex": "0x4010BA",
        "address_dec": 4198586,
        "opcode_hex": "FF 75 DC ",
        "disasm_text": "push    [ebp+hAccTable]; hAccTable"
      },
      {
        "address_hex": "0x4010BD",
        "address_dec": 4198589,
        "opcode_hex": "FF 75 E0 ",
        "disasm_text": "push    [ebp+Msg.hwnd]; hWnd"
      },
      {
        "address_hex": "0x4010C0",
        "address_dec": 4198592,
        "opcode_hex": "FF 15 70 20 40 00 ",
        "disasm_text": "call    ds:TranslateAcceleratorW"
      }
    ],
    "note": "The selected address range has been completely disassembled."
  },
  "timestamp": 26719015
}
```

#### get_select_hex

Call the GetSelectHex interface of the server-side Reverse class to obtain the hexadecimal data for the currently selected region.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.get_select_hex())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "selected_start_address": 4198688,
    "selected_start_address_hex": "0x401120",
    "selected_end_address": 4198698,
    "selected_end_address_hex": "0x40112A",
    "actual_read_byte_count": 10,
    "actual_start_address_hex": "0x401120",
    "actual_end_address_hex": "0x401129",
    "hex_bytes": [
      {
        "address_hex": "0x401120",
        "address_dec": 4198688,
        "byte_hex": "6A",
        "ascii_char": "j"
      },
      {
        "address_hex": "0x401121",
        "address_dec": 4198689,
        "byte_hex": "6B",
        "ascii_char": "k"
      },
      {
        "address_hex": "0x401122",
        "address_dec": 4198690,
        "byte_hex": "51",
        "ascii_char": "Q"
      },
      {
        "address_hex": "0x401123",
        "address_dec": 4198691,
        "byte_hex": "C7",
        "ascii_char": "."
      },
      {
        "address_hex": "0x401124",
        "address_dec": 4198692,
        "byte_hex": "45",
        "ascii_char": "E"
      },
      {
        "address_hex": "0x401125",
        "address_dec": 4198693,
        "byte_hex": "CC",
        "ascii_char": "."
      },
      {
        "address_hex": "0x401126",
        "address_dec": 4198694,
        "byte_hex": "30",
        "ascii_char": "0"
      },
      {
        "address_hex": "0x401127",
        "address_dec": 4198695,
        "byte_hex": "00",
        "ascii_char": "."
      },
      {
        "address_hex": "0x401128",
        "address_dec": 4198696,
        "byte_hex": "00",
        "ascii_char": "."
      },
      {
        "address_hex": "0x401129",
        "address_dec": 4198697,
        "byte_hex": "00",
        "ascii_char": "."
      }
    ],
    "hex_batch": "6A 6B 51 C7 45 CC 30 00 00 00 ",
    "ascii_batch": "jkQ.E.0...",
    "note": "The selected address range has been completely read (hex bytes + ASCII)."
  },
  "timestamp": 26822062
}
```

### Memory Operations

The Memory Operations module provides capabilities such as memory data reading, structure parsing, string extraction, memory search, and cross-reference querying. It supports precise data reading by byte/word/dword and tracks reference relationships between code and data, enabling complete observation of program runtime state.

#### get_entry_points

Call the GetEntryPoints interface of the server-side Memory class to obtain all entry point address information for the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_entry_points())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "entry_points": [
      {
        "ordinal": 4199684,
        "address": 4199684,
        "address_hex": "0x401504",
        "name": "start",
        "forwarder": "",
        "index": 0
      }
    ],
    "total_count": 1
  },
  "timestamp": 35475343
}
```

#### get_defined_struct

Call the GetDefinedStruct interface of the server-side Memory class to obtain information about all defined structures in the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_defined_struct())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "defined_types": [
      {
        "ordinal": 1,
        "get_success": true,
        "name": "_GUID",
        "size_bytes": 16,
        "size_hex": "0x10",
        "is_union": false,
        "is_struct": true,
        "is_enum": false,
        "is_typedef": false,
        "is_ptr": false,
        "is_array": false,
        "type_string": "_GUID"
      },
      {
        "ordinal": 2,
        "get_success": true,
        "name": "GUID",
        "size_bytes": 16,
        "size_hex": "0x10",
        "is_union": false,
        "is_struct": true,
        "is_enum": false,
        "is_typedef": true,
        "is_ptr": false,
        "is_array": false,
        "type_string": "GUID"
      },
      {
        "ordinal": 3,
        "get_success": true,
        "name": "_EH4_SCOPETABLE_RECORD",
        "size_bytes": 12,
        "size_hex": "0xC",
        "is_union": false,
        "is_struct": true,
        "is_enum": false,
        "is_typedef": false,
        "is_ptr": false,
        "is_array": false,
        "type_string": "_EH4_SCOPETABLE_RECORD"
      }
    ],
    "total_count": 79
  },
  "timestamp": 35726906
}
```

#### get_memory_byte

Receive an address parameter, validate the address format, then call the GetMemoryByte interface of the server-side Memory class to obtain 1 byte of memory data at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_byte("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "address": 4198400,
    "address_hex": "0x401000",
    "byte_value": 85,
    "byte_hex": "55"
  },
  "timestamp": 35917234
}
```

#### get_memory_word

Receive an address parameter, validate the address format, then call the GetMemoryWord interface of the server-side Memory class to obtain 2 bytes (Word) of memory data at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_word("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "address": 4198400,
    "address_hex": "0x401000",
    "word_value": 35669,
    "word_hex": "8B55"
  },
  "timestamp": 36064421
}
```

#### get_memory_dword

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_dword("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "address": 4198400,
    "address_hex": "0x401000",
    "dword_value": 2213317461,
    "dword_hex": "83EC8B55"
  },
  "timestamp": 36239218
}
```

#### get_memory_qword

Receive an address parameter, validate the address format, then call the GetMemoryQword interface of the server-side Memory class to obtain 8 bytes (Qword) of memory data at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_qword("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "address": 4198400,
    "address_hex": "0x401000",
    "qword_value": 10040244221420278000,
    "qword_hex": "-74A9E3137C1374AB"
  },
  "timestamp": 36541093
}
```

#### get_memory_bytes

Receive address and length parameters, validate the address format and check that the length is positive, then call the GetMemoryBytes interface of the server-side Memory class to obtain memory data of the specified length starting from the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_bytes("0x401000","5"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "address": 4198400,
    "address_hex": "0x401000",
    "requested_length": 5,
    "actual_length": 5,
    "bytes": [
      85,
      139,
      236,
      131,
      236
    ],
    "bytes_hex": [
      "55",
      "8b",
      "ec",
      "83",
      "ec"
    ]
  },
  "timestamp": 36614296
}
```

#### get_string_info

Call the GetStringInfo interface of the server-side Memory class to obtain all string-related information in the program.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_string_info())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "strings": [
      {
        "index": 0,
        "start_address": 4203052,
        "start_address_hex": "0x40222C",
        "end_address": 4203143,
        "end_address_hex": "0x402287",
        "size": 91
      },
      {
        "index": 1,
        "start_address": 4203176,
        "start_address_hex": "0x4022A8",
        "end_address": 4203185,
        "end_address_hex": "0x4022B1",
        "size": 9
      },
      {
        "index": 2,
        "start_address": 4203196,
        "start_address_hex": "0x4022BC",
        "end_address": 4203205,
        "end_address_hex": "0x4022C5",
        "size": 9
      }
    ],
    "total_count": 94
  },
  "timestamp": 36942859
}
```

#### get_memory_search

Receive start address, end address, and search pattern parameters, validate the address format and check that the search pattern is not empty, then call the MemorySearch interface of the server-side Memory class to search for the specified content within the specified address range.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_search("0x401000","0x402000","688033"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "found_address": 4198431,
    "found_address_hex": "0x40101F",
    "searched_pattern": "688033",
    "search_start": 4198400,
    "search_start_hex": "0x401000",
    "search_end": 4202496,
    "search_end_hex": "0x402000"
  },
  "timestamp": 37278640
}
```

#### get_type_by_name

Receive a type name parameter, validate it is not empty, then call the GetTypeByName interface of the server-side Memory class to obtain the corresponding type definition information by name.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_type_by_name("_GUID"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "type_info": {
      "original_name": "_GUID",
      "size_bytes": 16
    }
  },
  "timestamp": 37370109
}
```

#### xref_code_first_to

Receive an address parameter, validate the address format, then call the XrefCodeFirstTo interface of the server-side Memory class to obtain the first code cross-reference pointing to this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_first_to("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "xrefs": [
      {
        "basic_info": {
          "from_address": 4199565,
          "to_address": 4199570,
          "from_address_hex": "0x40148D",
          "to_address_hex": "0x401492",
          "is_code_ref": false,
          "is_user_defined": true
        },
        "type_details": {
          "type_code": 16,
          "type_char": "P",
          "base_type_masked": 16,
          "code_ref_type": "Call Far (This xref creates a function at the referenced location)",
          "xref_flags": {
            "XREF_USER": false,
            "XREF_TAIL": false,
            "XREF_BASE": false,
            "XREF_PASTEND": false
          }
        },
        "from_address_details": {
          "disassembly": "call    _WinMain@16",
          "is_head_address": true
        },
        "function_info": {
          "function_start": 4199324,
          "function_start_hex": "0x40139C",
          "function_name": "?__scrt_common_main_seh@@YAHXZ",
          "function_flags": 4199684
        },
        "segment_info": {
          "segment_start": 4198400,
          "segment_start_hex": "0x401000",
          "segment_name": ".text",
          "segment_type": 255,
          "segment_perm": "None"
        },
        "reference_flags": {
          "has_external_references": false,
          "has_jump_flow_xrefs": true
        },
        "outgoing_references": {
          "code_references": [
            4199570,
            4198400
          ],
          "far_code_references": [
            4198400
          ]
        },
        "incoming_references": {
          "code_references_to": [
            4199560
          ],
          "far_code_references_to": []
        }
      }
    ]
  },
  "timestamp": 37865437
}
```

#### xref_code_first_from

Receive an address parameter, validate the address format, then call the XrefCodeFirstFrom interface of the server-side Memory class to obtain the first code cross-reference originating from this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_first_from("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "xrefs": [
      {
        "basic_info": {
          "from_address": 4198400,
          "to_address": 0,
          "from_address_hex": "0x401000",
          "to_address_hex": "0x0",
          "is_code_ref": true,
          "is_user_defined": true
        },
        "type_details": {
          "type_code": 16,
          "type_char": "P",
          "base_type_masked": 16,
          "code_ref_type": "Call Far (This xref creates a function at the referenced location)",
          "xref_flags": {
            "XREF_USER": false,
            "XREF_TAIL": false,
            "XREF_BASE": false,
            "XREF_PASTEND": false
          }
        },
        "from_address_details": {
          "disassembly": "push    ebp",
          "is_head_address": false
        },
        "function_info": {
          "function_start": 4198400,
          "function_start_hex": "0x401000",
          "function_name": "_WinMain@16",
          "function_flags": 4198638
        },
        "segment_info": {
          "segment_start": 4198400,
          "segment_start_hex": "0x401000",
          "segment_name": ".text",
          "segment_type": 255,
          "permissions": "",
          "segment_perm": ""
        },
        "reference_flags": {
          "has_external_references": true,
          "has_jump_flow_xrefs": false
        },
        "outgoing_references": {
          "code_references": [
            4199565
          ],
          "far_code_references": [
            4199565
          ]
        },
        "incoming_references": {
          "code_references_to": [
            4199565
          ],
          "far_code_references_to": [
            4199565
          ]
        }
      }
    ]
  },
  "timestamp": 37980640
}
```

#### xref_data_first_to

Receive an address parameter, validate the address format, then call the XrefDataFirstTo interface of the server-side Memory class to obtain the first data cross-reference pointing to this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_first_to("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "analysis_result": {
      "analyzed_address": 4198400,
      "data_xrefs_to": [],
      "outgoing_references": {
        "code_xrefs_from": [],
        "data_xrefs_from": [],
        "far_code_xrefs_from": []
      },
      "switch_analysis": {
        "status": "No switch table references found"
      }
    }
  },
  "timestamp": 38080250
}
```

#### xref_data_first_from

Receive an address parameter, validate the address format, then call the XrefDataFirstFrom interface of the server-side Memory class to obtain the first data cross-reference originating from this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_first_from("0x401007"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "outgoing_data_xrefs": [
      {
        "from_address_hex": "0x401007",
        "basic_info": {
          "from_address": 4198407,
          "is_user_defined": true,
          "is_code_origin": true
        },
        "type_info": {
          "type_code": 32,
          "type_char": "?",
          "base_type_masked": 0,
          "data_ref_type": "Undefined data reference type"
        },
        "flags_info": {
          "XREF_USER": true,
          "XREF_TAIL": false,
          "XREF_BASE": false,
          "XREF_PASTEND": false
        },
        "from_address_details": {
          "disassembly": "mov     esi, ds:LoadStringW",
          "item_type": "Code (instruction)"
        },
        "function_info": {
          "function_name": "_WinMain@16",
          "function_start": 4198400,
          "function_start_hex": "0x401000",
          "frame_size": 60
        },
        "segment_comparison": {
          "note": "One or both addresses have no valid segment"
        },
        "target_data_details": {
          "note": "Target is not recognized data (unanalyzed or gap)",
          "has_incoming_refs": false
        }
      }
    ]
  },
  "timestamp": 38226593
}
```

#### xref_code_to_array

Receive an address parameter, validate the address format, then call the XrefCodeToArray interface of the server-side Memory class to obtain a list of all code cross-references pointing to this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_to_array("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "code_xrefs_to": [
      {
        "from_address": 4199565,
        "to_address": 0,
        "is_code_ref": false,
        "direction": "Down (target address <= from address)"
      }
    ]
  },
  "timestamp": 38309062
}
```

#### xref_code_from_array

Receive an address parameter, validate the address format, then call the XrefCodeFromArray interface of the server-side Memory class to obtain a list of all code cross-references originating from this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_from_array("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "code_xrefs_from": [],
    "note": "No FAR code references from the specified address"
  },
  "timestamp": 38380906
}
```

#### xref_data_to_array

Receive an address parameter, validate the address format, then call the XrefDataToArray interface of the server-side Memory class to obtain a list of all data cross-references pointing to this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_to_array("0x402080"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "data_xrefs_to": [
      {
        "from_address": 4198407,
        "to_address": 4202624,
        "is_code_origin": true,
        "direction": "Up (target address > from address)"
      }
    ]
  },
  "timestamp": 38484250
}
```

#### xref_data_from_array

Receive an address parameter, validate the address format, then call the XrefDataFromArray interface of the server-side Memory class to obtain a list of all data cross-references originating from this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_from_array("0x402080"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "data_xrefs_from": [],
    "note": "No data references from the specified address"
  },
  "timestamp": 38516921
}
```

#### xref_get_list_array

Receive an address parameter, validate the address format, then call the XrefGetListArray interface of the server-side Memory class to obtain all cross-reference lists related to this address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_get_list_array("0x402080"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "target_address_dec": 4202624,
    "target_address_hex": "0x402080",
    "xref_counts": {
      "code_to": 2,
      "code_from": 0,
      "data_to": 1,
      "data_from": 0
    },
    "total_xrefs": 3
  },
  "timestamp": 38595187
}
```

### General Utilities

The General Utilities module provides convenient operations such as comment editing, symbol renaming, variable modification, and structure member management. These capabilities optimize IDA display effects, improve analysis efficiency, and make reverse engineering results easier to preserve, share, and reuse. They are essential auxiliary capabilities for engineering analysis.

#### set_assembly_comment

Receive address and comment parameters, validate the address format and check that the comment is not empty, then call the SetAssemblyComment interface of the server-side Other class to add a comment to the assembly instruction at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_assembly_commnet("0x401000","new comm"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "set_success": true,
    "target_address_dec": 4198400,
    "target_address_hex": "0x401000",
    "comment_content": "new comm",
    "comment_type": "repeatable_comment"
  },
  "timestamp": 38946781
}
```

#### set_function_comment

Receive address and comment parameters, validate the address format and check that the comment is not empty, then call the SetFunctionComment interface of the server-side Other class to add a comment to the function at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_function_comment("0x401000","new comm"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "requested_address": 4198400,
    "requested_address_hex": "0x401000",
    "comment_content": "new comm",
    "is_global": true,
    "flag": "true"
  },
  "timestamp": 39185687
}
```

#### get_function_name

Receive an address parameter, validate the address format, then call the GetFunctionName interface of the server-side Other class to obtain the name of the function to which the specified address belongs.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.get_function_name("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "requested_address": 4198400,
    "requested_address_hex": "0x401000",
    "flag": "true",
    "function_name": "_WinMain@16",
    "actual_function_start_address": 4198400,
    "actual_function_start_address_hex": "0x401000"
  },
  "timestamp": 39246453
}
```

#### set_function_name

Receive address and function name parameters, validate the address format and check that the name is not empty, then call the SetFunctionName interface of the server-side Other class to modify the name of the function to which the specified address belongs.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_function_name("0x401000","MyFunc"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "requested_address": 4198400,
    "requested_address_hex": "0x401000",
    "new_function_name": "MyFunc",
    "flag": "true",
    "actual_function_start_address": 4198400,
    "actual_function_start_address_hex": "0x401000",
    "final_function_name": "MyFunc"
  },
  "timestamp": 39369609
}
```

#### switch_pseudocode_to

Receive an address parameter, validate the address format, then call the SwitchPseudoCodeTo interface of the server-side Other class to switch the pseudocode window to the specified address and decompile.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.switch_pseudocode_to("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "message": "Successfully switched to pseudocode",
    "function_address": "0x401000"
  },
  "timestamp": 39529218
}
```

#### get_function_var_name

Receive an address parameter, validate the address format, then call the GetFunctionVarName interface of the server-side Other class to obtain the variable names of the function to which the specified address belongs.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    info_page.switch_pseudocode_to("0x401000")
    print(info_page.get_function_var_name("0x401000"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "variables": [
      {
        "name": "hInstance",
        "location": "stack offset: 0x5C",
        "width_bytes": 4,
        "type": "HINSTANCE",
        "is_user_defined": false,
        "index": 0
      },
      {
        "name": "hPrevInstance",
        "location": "stack offset: 0x60",
        "width_bytes": 4,
        "type": "HINSTANCE",
        "is_user_defined": false,
        "index": 1
      },
      {
        "name": "lpCmdLine",
        "location": "stack offset: 0x64",
        "width_bytes": 4,
        "type": "LPSTR",
        "is_user_defined": false,
        "index": 2
      },
      {
        "name": "nShowCmd",
        "location": "stack offset: 0x68",
        "width_bytes": 4,
        "type": "int",
        "is_user_defined": false,
        "index": 3
      },
      {
        "name": "Window",
        "location": "register: r8",
        "width_bytes": 4,
        "type": "HWND",
        "is_user_defined": false,
        "index": 4
      },
      {
        "name": "v5",
        "location": "register: zf",
        "width_bytes": 4,
        "type": "HWND",
        "is_user_defined": false,
        "index": 5
      },
      {
        "name": "Msg",
        "location": "stack offset: 0x38",
        "width_bytes": 28,
        "type": "tagMSG",
        "is_user_defined": true,
        "index": 7
      },
      {
        "name": "hInstancea",
        "location": "stack offset: 0x5C",
        "width_bytes": 4,
        "type": "HACCEL",
        "is_user_defined": true,
        "index": 8
      }
    ],
    "function_address": "0x401000",
    "found_variables_count": 8
  },
  "timestamp": 39635265
}
```

#### set_function_var_name

Receive address, UID, and variable name parameters, validate the address format and check that the UID and variable name are not empty, then call the SetFunctionVarName interface of the server-side Other class to modify the variable name with the specified UID in the function at the specified address.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    info_page.switch_pseudocode_to("0x401000")
    print(info_page.set_function_var_name("0x401000","4","new_var"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "function_address": "0x401000",
    "var_index": 4,
    "new_name": "new_var",
    "message": "Local variable renamed successfully"
  },
  "timestamp": 39949484
}
```

#### get_struct_member_name

Receive struct name and offset parameters, check that the struct name is not empty and the offset is a non-negative integer, then call the GetStructMemberName interface of the server-side Other class to obtain the member name at the specified offset in the specified struct.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.get_struct_member_name("_GUID", 0))
    print(info_page.get_struct_member_name("_GUID", 1))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "member_info": {
      "struct_name": "_GUID",
      "member_name": "Data1",
      "offset_bits": 0,
      "offset_bytes": 0,
      "size_bits": 32,
      "size_bytes": 4,
      "type": "unsigned int",
      "effective_alignment_bytes": 1,
      "field_alignment_shift": 255,
      "flags": {
        "is_bitfield": false,
        "is_zero_length_bitfield": false,
        "is_unaligned": false,
        "is_baseclass_member": false,
        "is_virtual_baseclass_member": false,
        "is_vftable_member": false,
        "is_method_member": false,
        "is_gap": false,
        "is_anonymous": false
      }
    }
  },
  "timestamp": 40099000
}
```

#### set_struct_member_name

Receive struct name, offset, and new member name parameters, check that the struct name is not empty, the offset is a non-negative integer, and the new name is not empty, then call the SetStructMemberName interface of the server-side Other class to modify the member name at the specified offset in the specified struct.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_struct_member_name("_GUID", 0,"new_data"))
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "rename_result": {
      "struct_name": "_GUID",
      "offset_bytes": 0,
      "old_member_name": "Data1",
      "new_member_name": "new_data",
      "status": "Member renamed successfully"
    }
  },
  "timestamp": 40172734
}
```

#### get_current_select

Call the GetCurrentSelect interface of the server-side Other class to obtain information about the currently selected region.

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.get_current_select())
```

Output JSON format:

```json
{
  "status": "success",
  "result": {
    "screen_ea": 4198438,
    "screen_ea_hex": "0x401026",
    "selection_start_ea": 4198400,
    "selection_start_ea_hex": "0x401000",
    "selection_end_ea": 4198439,
    "selection_end_ea_hex": "0x401027",
    "widget_type_code": 27,
    "widget_title": "IDA View-A",
    "has_valid_selection": true
  },
  "timestamp": 40213890
}
```
