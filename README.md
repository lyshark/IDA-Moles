# IDA-Moles 静态逆向分析组件

IDA Moles 是一款发布于 2025 年 12 月 28 日、当前版本为 1.0.7 的专业逆向分析接口工具，专为 IDA Pro 9.1 打造，并适配 Python 3.8 及以上版本，该工具以标准化调用逻辑为核心，能高效控制 IDA Pro 执行反汇编、反编译、内存分析等各类逆向操作，拥有高效反编译控制、高级调试、内存分析、函数解析、MCP 服务器扩展及自动化批量处理等全方位核心功能，不仅能实现伪代码获取、断点设置、内存布局分析、函数信息解析等基础逆向操作，还支持自定义 MCP 服务器接口开发以满足定制化需求，更可通过编程接口实现逆向分析流程的自动化与大量样本的批量处理，可显著提升逆向分析的效率与灵活性，满足各类复杂的逆向分析场景需求。

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

### 函数分析

### 段处理

### 逆向分析

### 内存操作

### 通用辅助

















## FastMCP + CherryStudio

人工干预下的智能化分析工具。










## OpenClaw + IDA-Moles

龙虾+IDA Moles 构建 7*24小时的逆向分析助理。








































