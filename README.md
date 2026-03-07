# IDA-Moles 静态逆向分析组件

IDA Moles 是一款专业逆向分析接口工具，专为 IDA Pro 9.1 打造，并适配 Python 3.8 及以上版本，该工具以标准化调用逻辑为核心，能高效控制 IDA Pro 执行反汇编、反编译、内存分析等各类逆向操作，拥有高效反编译控制、高级调试、内存分析、函数解析、MCP 服务器扩展及自动化批量处理等全方位核心功能，不仅能实现伪代码获取、断点设置、内存布局分析、函数信息解析等基础逆向操作，还支持自定义 MCP 服务器接口开发以满足定制化需求，更可通过编程接口实现逆向分析流程的自动化与大量样本的批量处理，可显著提升逆向分析的效率与灵活性，满足各类复杂的逆向分析场景需求。

## 快速安装

1、首先用户需要通过`PIP`快速安装部署，打开命令提示符或终端，执行以下命令安装最新版本的`IDA Moles`开发工具包。

```bash
CMD> pip install idamoles
Collecting idamoles
  Downloading idamoles-1.0.7-py3-none-any.whl.metadata (1.8 kB)
Downloading idamoles-1.0.7-py3-none-any.whl (19 kB)
Installing collected packages: idamoles
Successfully installed idamoles-1.0.7

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
```

仅需简单配置 IDA Pro 路径、安装插件即可完成环境搭建并加载目标程序开展分析工作。

## 接口规范

该组件基于 IDA 9.1 标准 SDK 开发工具包进行研发，在缺乏有效参考文档与技术支持的前提下，作者通过理解逆向分析原理与技术攻坚，成功实现了 50+ 余项核心功能，并按照功能属性系统性归档为六大模块：

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

调用服务端 Info 类的 GetBasicInfo 接口，获取程序的基础信息，请求前会检查服务端可用性。

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

调用服务端 Info 类的 GetImageInfo 接口，获取程序的镜像（Image）相关信息，请求前会检查服务端可用性。

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

调用服务端 Function 类的 GetFunction 接口，获取程序中所有函数的列表信息，请求前会检查服务端可用性。

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

接收函数起始地址参数，验证地址格式后，调用服务端 Function 类的 GetFunctionInfo 接口，获取指定地址函数的详细信息，请求前会检查服务端可用性。

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

调用服务端 Function 类的 GetImportFunctions 接口，获取程序中导入函数的列表信息，请求前会检查服务端可用性。

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

调用服务端 Function 类的 GetFunctionCount 接口，获取程序中函数的总数，请求前会检查服务端可用性。

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

接收函数起始地址参数，验证地址格式后，调用服务端 Function 类的 GetFunctionByAddr 接口，根据地址获取对应函数信息，请求前会检查服务端可用性。

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

接收函数名称参数，校验非空后，调用服务端 Function 类的 GetFunctionByName 接口，根据名称获取对应函数信息，请求前会检查服务端可用性。

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

接收搜索关键词参数，校验非空后，调用服务端 Function 类的 FindFunctionByName 接口，模糊搜索包含关键词的函数信息，请求前会检查服务端可用性。

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

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```

#### 

```python

```

输出JSON格式：

```json

```




### 逆向分析

逆向分析模块集成反汇编、伪代码还原、指令序列提取、代码行与地址互转等核心能力，实现从机器指令到高级语义的转换，大幅降低人工阅读汇编代码的成本，是深度逆向与逻辑还原的核心引擎。

### 内存操作

内存操作模块提供内存数据读取、结构体解析、字符串提取、内存搜索与交叉引用查询等能力，支持按字节/字/双字精准读取数据，并追踪代码与数据间的引用关系，实现对程序运行时状态的完整观测。

### 通用辅助

通用辅助模块提供注释编辑、符号重命名、变量修改、结构成员管理等便捷操作，用于优化 IDA 展示效果、提升分析效率，让逆向成果更易沉淀、共享与二次利用，是工程化分析必不可少的辅助能力。
















## FastMCP + CherryStudio

人工干预下的智能化分析工具。










## OpenClaw + IDA-Moles

龙虾+IDA Moles 构建 7*24小时的逆向分析助理。








































