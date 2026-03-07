# IDA-Moles 静态逆向分析组件

<img src="https://github.com/user-attachments/assets/60f86fb4-04fb-45d7-88ab-f64e5e7516d0" alt="ladyida" width="12%">

IDA Moles 是一款专业逆向分析接口工具，专为 IDA Pro 9.1 打造，并适配 Python 3.8 及以上版本，该工具以标准化调用逻辑为核心，能高效控制 IDA Pro 执行反汇编、反编译、内存分析等各类逆向操作，拥有高效反编译控制、高级调试、内存分析、函数解析、MCP 服务器扩展及自动化批量处理等全方位核心功能，不仅能实现伪代码获取、断点设置、内存布局分析、函数信息解析等基础逆向操作，还支持自定义 MCP 服务器接口开发以满足定制化需求，更可通过编程接口实现逆向分析流程的自动化与大量样本的批量处理，可显著提升逆向分析的效率与灵活性，满足各类复杂的逆向分析场景需求。

## 快速安装

1、首先用户需要通过`PIP`快速安装部署，打开命令提示符或终端，执行以下命令安装最新版本的`IDA Moles`开发工具包。

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

2、至此开始安装IDAMoles驱动文件，通过找到`D://IDA Professional 9.1`目录，并执行安装命令完成插件的部署。

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
>>> config.install_moles()
Download progress: 100.00%
[*] Install Moles Success
>>>
>>> config.open_ida_with_program("C://win32.exe",auto_mode=True,force_new=True)
SUCCESS: IDA has been started and the program has been loaded:C://win32.exe
```

仅需简单配置 IDA Pro 路径、安装插件即可完成环境搭建并加载目标程序开展分析工作。

## 接口规范

该组件基于 IDA 9.1 标准 C++ SDK 开发工具包进行研发，在缺乏有效参考文档与技术支持的前提下，业余时间花费1个月，作者通过理解IDA逆向分析原理与技术攻坚，成功实现了 50 余项核心功能，并按照功能属性系统性归档为六大模块：

 - Info（信息解析）
 - Function（函数分析）
 - Segment（段处理）
 - Reverse（逆向分析）
 - Memory（内存操作）
 - Other（通用辅助）

每个模块下均涵盖数十项接口能力，这些接口不仅覆盖了二进制分析、代码逆向、内存解析等核心场景，更构建起 AI 智能分析所需的底层技术基座，为后续智能化分析、自动化逆向等高阶能力的落地提供了坚实且可扩展的技术支撑。

### 信息解析

信息解析模块负责对目标程序进行基础元数据提取，快速获取文件结构、加载基址、编译信息、运行环境等核心属性，为后续逆向分析提供全局视图与环境依据，是自动化分析流程的起点。

#### get_basic_info

调用服务端 Info 类的 GetBasicInfo 接口，获取程序的基础信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Info(config)

    print(info_page.get_basic_info())
```

输出JSON格式：

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

调用服务端 Info 类的 GetImageInfo 接口，获取程序的镜像（Image）相关信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Info(config)

    print(info_page.get_image_info())
```

输出JSON格式：

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

### 函数分析

函数分析模块聚焦程序执行流的最小单元，实现函数枚举、地址定位、名称检索、边界识别与导入表解析，精准建立程序内所有函数的索引体系，为代码理解、漏洞定位与逻辑还原提供关键支撑。

#### get_functions

调用服务端 Function 类的 GetFunction 接口，获取程序中所有函数的列表信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_functions())
```

输出JSON格式：

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

接收函数起始地址参数，验证地址格式后，调用服务端 Function 类的 GetFunctionInfo 接口，获取指定地址函数的详细信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_info("0x401000"))
```

输出JSON格式：

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

调用服务端 Function 类的 GetImportFunctions 接口，获取程序中导入函数的列表信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_import_functions())
```

输出JSON格式：

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

调用服务端 Function 类的 GetFunctionCount 接口，获取程序中函数的总数。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_count())
```

输出JSON格式：

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

接收函数起始地址参数，验证地址格式后，调用服务端 Function 类的 GetFunctionByAddr 接口，根据地址获取对应函数信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_by_addr("0x401000"))
```

输出JSON格式：

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

接收函数名称参数，校验非空后，调用服务端 Function 类的 GetFunctionByName 接口，根据名称获取对应函数信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.get_function_by_name("_WinMain@16"))
```

输出JSON格式：

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

接收搜索关键词参数，校验非空后，调用服务端 Function 类的 FindFunctionByName 接口，模糊搜索包含关键词的函数信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Function(config)

    print(info_page.find_function_by_name("WinMain"))
```

输出JSON格式：

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

### 段处理

段处理模块围绕程序内存区段展开，支持段表读取、段属性解析、地址归属判断等能力，可快速识别代码段、数据段、只读段等关键区域，为内存布局分析、数据提取与指令定位提供结构基础。

#### get_segments

调用服务端 Segment 类的 GetSegment 接口，获取程序中所有段（Segment）的列表信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Segment(config)

    print(info_page.get_segments())
```

输出JSON格式：

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

调用服务端 Segment 类的 GetSegmentCount 接口，获取程序中段的总数。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Segment(config)

    print(info_page.get_segment_count())
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Segment 类的 GetSegmentFromAddr 接口，获取指定地址所属段的信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Segment(config)

    print(info_page.get_segment_from_addr("0x401000"))
```

输出JSON格式：

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

### 逆向分析

逆向分析模块集成反汇编、伪代码还原、指令序列提取、代码行与地址互转等核心能力，实现从机器指令到高级语义的转换，大幅降低人工阅读汇编代码的成本，是深度逆向与逻辑还原的核心引擎。

#### disassembly_function

接收地址参数，验证地址格式后，调用服务端 Reverse 类的 DisassembleFunction 接口，对指定地址的函数进行反汇编。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.disassembly_function("0x401000"))
```

输出JSON格式：

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

接收地址和行数参数，验证地址格式并校验行数在 1-1024 范围内后，调用服务端 Reverse 类的 DisassemblyCount 接口，反汇编指定地址开始的指定行数指令。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.disassembly_count("0x401000","3"))
```

输出JSON格式：

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

接收起始和结束地址参数，验证地址格式后，调用服务端 Reverse 类的 DisassemblyRange 接口，反汇编指定地址范围内的指令。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.disassembly_range("0x401000","0x401020"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Reverse 类的 DecompileChecked 接口，对指定地址进行反编译校验。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_checked("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Reverse 类的 GetMicroCode 接口，获取指定地址的微代码反编译结果。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_micro_code("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Reverse 类的 DecompileFunctionFromAddr 接口，根据地址反编译对应函数。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_from_addr("0x401000"))
```

输出JSON格式：

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

接收函数名称参数，校验非空后，调用服务端 Reverse 类的 DecompileFunctionFromName 接口，根据名称反编译对应函数。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_from_name("_WinMain@16"))
```

输出JSON格式：

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

接收地址和行号参数，验证地址格式并校验行号非空后，调用服务端 Reverse 类的 DecompileLineToAddress 接口，将反编译代码的行号映射到对应内存地址。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_line_to_address("0x401000","8"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Reverse 类的 DecompileAddressToLine 接口，将指定地址映射到反编译代码的行号。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.decompile_address_to_line("0x401025"))
```

输出JSON格式：

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

调用服务端 Reverse 类的 GetSelectDecompile 接口，获取当前选中区域的反编译代码。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.get_select_decompile())
```

输出JSON格式：

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

调用服务端 Reverse 类的 GetSelectDisassembly 接口，获取当前选中区域的反汇编指令。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.get_select_disassembly())
```

输出JSON格式：

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

调用服务端 Reverse 类的 GetSelectHex 接口，获取当前选中区域的十六进制数据。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Reverse(config)

    print(info_page.get_select_hex())
```

输出JSON格式：

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

### 内存操作

内存操作模块提供内存数据读取、结构体解析、字符串提取、内存搜索与交叉引用查询等能力，支持按字节/字/双字精准读取数据，并追踪代码与数据间的引用关系，实现对程序运行时状态的完整观测。

#### get_entry_points

调用服务端 Memory 类的 GetEntryPoints 接口，获取程序的所有入口点地址信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_entry_points())
```

输出JSON格式：

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

调用服务端 Memory 类的 GetDefinedStruct 接口，获取程序中已定义的所有结构体信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_defined_struct())
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 GetMemoryByte 接口，获取指定地址的 1 字节内存数据。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_byte("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 GetMemoryWord 接口，获取指定地址的 2 字节（Word）内存数据。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_word("0x401000"))
```

输出JSON格式：

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

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 GetMemoryQword 接口，获取指定地址的 8 字节（Qword）内存数据。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_qword("0x401000"))
```

输出JSON格式：

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

接收地址和长度参数，验证地址格式并校验长度为正数后，调用服务端 Memory 类的 GetMemoryBytes 接口，获取指定地址开始的指定长度内存数据。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_bytes("0x401000","5"))
```

输出JSON格式：

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

调用服务端 Memory 类的 GetStringInfo 接口，获取程序中所有字符串相关信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_string_info())
```

输出JSON格式：

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

接收起始地址、结束地址和搜索参数，验证地址格式并校验搜索参数非空后，调用服务端 Memory 类的 MemorySearch 接口，在指定地址范围内搜索指定内容。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_memory_search("0x401000","0x402000","688033"))
```

输出JSON格式：

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

接收类型名称参数，校验非空后，调用服务端 Memory 类的 GetTypeByName 接口，根据名称获取对应的类型定义信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.get_type_by_name("_GUID"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefCodeFirstTo 接口，获取指向该地址的第一条代码交叉引用。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_first_to("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefCodeFirstFrom 接口，获取从该地址出发的第一条代码交叉引用。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_first_from("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefDataFirstTo 接口，获取指向该地址的第一条数据交叉引用。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_first_to("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefDataFirstFrom 接口，获取从该地址出发的第一条数据交叉引用。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_first_from("0x401007"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefCodeFromArray 接口，获取所有从该地址出发的代码交叉引用列表。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_to_array("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefCodeFromArray 接口，获取所有从该地址出发的代码交叉引用列表。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_code_from_array("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefDataToArray 接口，获取所有指向该地址的交叉引用列表。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_to_array("0x402080"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefDataFromArray 接口，获取所有从该地址出发的数据交叉引用列表。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_data_from_array("0x402080"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Memory 类的 XrefGetListArray 接口，获取该地址相关的所有交叉引用列表。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Memory(config)

    print(info_page.xref_get_list_array("0x402080"))
```

输出JSON格式：

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

### 通用辅助

通用辅助模块提供注释编辑、符号重命名、变量修改、结构成员管理等便捷操作，用于优化 IDA 展示效果、提升分析效率，让逆向成果更易沉淀、共享与二次利用，是工程化分析必不可少的辅助能力。

#### set_assembly_comment

接收地址和注释参数，验证地址格式并校验注释非空后，调用服务端 Other 类的 SetAssemblyComment 接口，为指定地址的汇编指令添加注释。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_assembly_commnet("0x401000","new comm"))
```

输出JSON格式：

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

接收地址和注释参数，验证地址格式并校验注释非空后，调用服务端 Other 类的 SetFunctionComment 接口，为指定地址的函数添加注释。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_function_comment("0x401000","new comm"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Other 类的 GetFunctionName 接口，获取指定地址所属函数的名称。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.get_function_name("0x401000"))
```

输出JSON格式：

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

接收地址和函数名称参数，验证地址格式并校验名称非空后，调用服务端 Other 类的 SetFunctionName 接口，修改指定地址所属函数的名称。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_function_name("0x401000","MyFunc"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Other 类的 SwitchPseudoCodeTo 接口，切换伪代码窗口到指定地址位置并反编译。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.switch_pseudocode_to("0x401000"))
```

输出JSON格式：

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

接收地址参数，验证地址格式后，调用服务端 Other 类的 GetFunctionVarName 接口，获取指定地址所属函数的变量名称。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    info_page.switch_pseudocode_to("0x401000")
    print(info_page.get_function_var_name("0x401000"))
```

输出JSON格式：

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

接收地址、UID 和变量名称参数，验证地址格式并校验 UID 和变量名称非空后，调用服务端 Other 类的 SetFunctionVarName 接口，修改指定地址函数中指定 UID 的变量名称。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    info_page.switch_pseudocode_to("0x401000")
    print(info_page.set_function_var_name("0x401000","4","new_var"))
```

输出JSON格式：

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

接收结构体名称和偏移量参数，校验结构体名称非空且偏移量为非负整数后，调用服务端 Other 类的 GetStructMemberName 接口，获取指定结构体中指定偏移量的成员名称。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.get_struct_member_name("_GUID", 0))
    print(info_page.get_struct_member_name("_GUID", 1))
```

输出JSON格式：

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

接收结构体名称、偏移量和新成员名称参数，校验结构体名称非空、偏移量为非负整数且新名称非空后，调用服务端 Other 类的 SetStructMemberName 接口，修改指定结构体中指定偏移量的成员名称。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.set_struct_member_name("_GUID", 0,"new_data"))
```

输出JSON格式：

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

调用服务端 Other 类的 GetCurrentSelect 接口，获取当前选中区域的相关信息。

```python
from IDAMoles import *

if __name__ == '__main__':
    config=Config(address="127.0.0.1",port=8000)
    client = BaseHttpClient(config)

    info_page = Other(config)

    print(info_page.get_current_select())
```

输出JSON格式：

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

## FastMCP + CherryStudio

人工干预下的智能化分析工具。










## OpenClaw + IDA-Moles

龙虾+IDA Moles 构建 7*24小时的逆向分析助理。








































