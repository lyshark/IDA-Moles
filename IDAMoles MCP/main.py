import json
from fastmcp import FastMCP
from core import *
from typing import Union, Optional

# 初始化FastMCP实例
mcp = FastMCP("IDA Moles MCP")

# 配置服务器连接信息
config = Config(address="127.0.0.1", port=8000)

# ------------------------------ Info类接口 ------------------------------
@mcp.tool()
def get_basic_info() -> str:
    """
    获取基础信息（如程序基本属性等）
    返回值：包含基础信息的JSON字符串
    """
    info_handler = Info(config)
    return info_handler.get_basic_info()


@mcp.tool()
def get_image_info() -> str:
    """
    获取镜像文件的详细信息（架构、格式、入口点等）
    返回值：包含镜像信息的JSON字符串
    """
    info_handler = Info(config)
    return info_handler.get_image_info()


# ------------------------------ Function类接口 ------------------------------
@mcp.tool()
def get_all_functions() -> str:
    """
    获取镜像中所有函数的列表信息
    返回值：包含所有函数基本信息的JSON字符串
    """
    func_handler = Function(config)
    return func_handler.get_functions()


@mcp.tool()
def get_function_details(func_start_addr: Union[int, str]) -> str:
    """
    获取指定地址函数的详细信息（参数、返回值、交叉引用等）
    参数：
        func_start_addr: 函数起始地址（整数或十六进制字符串，如0x401000）
    返回值：包含函数详情的JSON字符串，错误时返回错误信息
    """
    func_handler = Function(config)
    return func_handler.get_function_info(func_start_addr)


@mcp.tool()
def get_import_functions() -> str:
    """
    获取镜像中的导入函数列表（从外部库导入的函数）
    返回值：包含导入函数信息的JSON字符串
    """
    func_handler = Function(config)
    return func_handler.get_import_functions()


@mcp.tool()
def get_function_count() -> str:
    """
    获取镜像中的函数总数
    返回值：包含函数计数的JSON字符串
    """
    func_handler = Function(config)
    return func_handler.get_function_count()


@mcp.tool()
def get_function_by_address(func_start_addr: Union[int, str]) -> str:
    """
    通过地址查找函数信息
    参数：
        func_start_addr: 函数起始地址（整数或十六进制字符串，如0x401000）
    返回值：包含函数信息的JSON字符串，错误时返回错误信息
    """
    func_handler = Function(config)
    return func_handler.get_function_by_addr(func_start_addr)


@mcp.tool()
def get_function_by_name(func_name: str) -> str:
    """
    通过函数名查找函数信息
    参数：
        func_name: 函数名称（非空字符串）
    返回值：包含函数信息的JSON字符串，错误时返回错误信息
    """
    func_handler = Function(config)
    return func_handler.get_function_by_name(func_name)


@mcp.tool()
def find_function_by_keyword(keyword: str) -> str:
    """
    通过关键字搜索函数（模糊匹配）
    参数：
        keyword: 搜索关键字（非空字符串）
    返回值：包含匹配函数列表的JSON字符串，错误时返回错误信息
    """
    func_handler = Function(config)
    return func_handler.find_function_by_name(keyword)


# ------------------------------ Segment类接口 ------------------------------
@mcp.tool()
def get_all_segments() -> str:
    """
    获取镜像中所有段信息（代码段、数据段、地址范围等）
    返回值：包含所有段信息的JSON字符串
    """
    seg_handler = Segment(config)
    return seg_handler.get_segments()


@mcp.tool()
def get_segment_count() -> str:
    """
    获取镜像中的段总数
    返回值：包含段计数的JSON字符串
    """
    seg_handler = Segment(config)
    return seg_handler.get_segment_count()


@mcp.tool()
def get_segment_from_address(address: Union[int, str]) -> str:
    """
    获取指定地址所属的段信息
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
    返回值：包含段信息的JSON字符串，错误时返回错误信息
    """
    seg_handler = Segment(config)
    return seg_handler.get_segment_from_addr(address)


# ------------------------------ Reverse类接口 ------------------------------
@mcp.tool()
def disassemble_function(address: Union[int, str]) -> str:
    """
    对指定地址的函数进行反汇编
    参数：
        address: 函数起始地址（整数或十六进制字符串，如0x401000）
    返回值：包含汇编指令的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.disassembly_function(address)


@mcp.tool()
def disassemble_by_line_count(address: Union[int, str], line_count: Union[int, str]) -> str:
    """
    从指定地址开始反汇编指定行数的指令
    参数：
        address: 起始地址（整数或十六进制字符串，如0x401000）
        line_count: 反汇编行数（1-1024之间的整数）
    返回值：包含汇编指令的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.disassembly_count(address, line_count)


@mcp.tool()
def disassemble_address_range(start_address: Union[int, str], end_address: Union[int, str]) -> str:
    """
    对指定地址范围内的指令进行反汇编
    参数：
        start_address: 起始地址（整数或十六进制字符串）
        end_address: 结束地址（整数或十六进制字符串，需大于起始地址）
    返回值：包含汇编指令的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.disassembly_range(start_address, end_address)


@mcp.tool()
def decompile_checked_function(address: Union[int, str]) -> str:
    """
    对已检查的函数进行反编译（特定场景下使用）
    参数：
        address: 函数地址（整数或十六进制字符串，如0x401000）
    返回值：包含伪代码的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.decompile_checked(address)


@mcp.tool()
def get_micro_code(address: Union[int, str]) -> str:
    """
    获取指定地址的微代码信息
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
    返回值：包含微代码的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.decompile_micro_code(address)


@mcp.tool()
def decompile_function_by_address(address: Union[int, str]) -> str:
    """
    通过地址对函数进行反编译
    参数：
        address: 函数起始地址（整数或十六进制字符串，如0x401000）
    返回值：包含伪代码的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.decompile_from_addr(address)


@mcp.tool()
def decompile_function_by_name(func_name: str) -> str:
    """
    通过函数名对函数进行反编译
    参数：
        func_name: 函数名称（非空字符串）
    返回值：包含伪代码的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.decompile_from_name(func_name)


@mcp.tool()
def decompile_line_to_address(address: str, line: str) -> str:
    """
    将反编译代码的行号映射到内存地址
    参数：
        address: 函数地址（整数或十六进制字符串，如0x401000）
        line: 反编译代码的行号（非空字符串）
    返回值：包含映射地址的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.decompile_line_to_address(address, line)


@mcp.tool()
def decompile_address_to_line(address: str) -> str:
    """
    将内存地址映射到反编译代码的行号
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
    返回值：包含行号信息的JSON字符串，错误时返回错误信息
    """
    reverse_handler = Reverse(config)
    return reverse_handler.decompile_address_to_line(address)


@mcp.tool()
def get_selected_decompile() -> str:
    """
    获取当前选中的反编译代码
    返回值：包含选中反编译代码的JSON字符串
    """
    reverse_handler = Reverse(config)
    return reverse_handler.get_select_decompile()


@mcp.tool()
def get_selected_disassembly() -> str:
    """
    获取当前选中的汇编代码
    返回值：包含选中汇编代码的JSON字符串
    """
    reverse_handler = Reverse(config)
    return reverse_handler.get_select_disassembly()


@mcp.tool()
def get_selected_hex() -> str:
    """
    获取当前选中区域的十六进制数据
    返回值：包含十六进制数据的JSON字符串
    """
    reverse_handler = Reverse(config)
    return reverse_handler.get_select_hex()


# ------------------------------ Memory类接口 ------------------------------
@mcp.tool()
def get_entry_points() -> str:
    """
    获取程序的所有入口点信息
    返回值：包含入口点信息的JSON字符串
    """
    memory_handler = Memory(config)
    return memory_handler.get_entry_points()


@mcp.tool()
def get_defined_structures() -> str:
    """
    获取已定义的数据结构信息
    返回值：包含数据结构信息的JSON字符串
    """
    memory_handler = Memory(config)
    return memory_handler.get_defined_struct()


@mcp.tool()
def get_memory_byte(address: Union[int, str]) -> str:
    """
    读取指定地址的1字节数据
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
    返回值：包含字节数据的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.get_memory_byte(str(address))


@mcp.tool()
def get_memory_word(address: Union[int, str]) -> str:
    """
    读取指定地址的2字节数据（字）
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
    返回值：包含字数据的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.get_memory_word(str(address))


@mcp.tool()
def get_memory_dword(address: Union[int, str]) -> str:
    """
    读取指定地址的4字节数据（双字）
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
    返回值：包含双字数据的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.get_memory_dword(str(address))


@mcp.tool()
def get_memory_qword(address: Union[int, str]) -> str:
    """
    读取指定地址的8字节数据（四字）
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
    返回值：包含四字数据的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.get_memory_qword(str(address))


@mcp.tool()
def get_memory_bytes(address: Union[int, str], byte_len: Union[int, str]) -> str:
    """
    读取指定地址开始的连续字节数据
    参数：
        address: 内存起始地址（整数或十六进制字符串，如0x401000）
        byte_len: 读取长度（正整数）
    返回值：包含字节数据的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.get_memory_bytes(str(address), str(byte_len))


@mcp.tool()
def get_string_info() -> str:
    """
    获取程序中的字符串信息
    返回值：包含字符串信息的JSON字符串
    """
    memory_handler = Memory(config)
    return memory_handler.get_string_info()


@mcp.tool()
def search_memory_range(start_address: Union[int, str], end_address: Union[int, str], param: str) -> str:
    """
    在指定地址范围内搜索数据
    参数：
        start_address: 搜索起始地址（整数或十六进制字符串）
        end_address: 搜索结束地址（整数或十六进制字符串，需大于起始地址）
        param: 搜索参数（非空字符串）
    返回值：包含搜索结果的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.get_memory_search(str(start_address), str(end_address), param)


@mcp.tool()
def get_type_by_name(type_name: str) -> str:
    """
    通过类型名获取类型信息
    参数：
        type_name: 类型名称（非空字符串）
    返回值：包含类型信息的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.get_type_by_name(type_name)


@mcp.tool()
def get_first_code_xref_to(address: Union[int, str]) -> str:
    """
    获取指向指定地址的第一个代码交叉引用
    参数：
        address: 目标地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用信息的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_code_first_to(str(address))


@mcp.tool()
def get_first_code_xref_from(address: Union[int, str]) -> str:
    """
    获取从指定地址出发的第一个代码交叉引用
    参数：
        address: 源地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用信息的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_code_first_from(str(address))


@mcp.tool()
def get_first_data_xref_to(address: Union[int, str]) -> str:
    """
    获取指向指定地址的第一个数据交叉引用
    参数：
        address: 目标地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用信息的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_data_first_to(str(address))


@mcp.tool()
def get_first_data_xref_from(address: Union[int, str]) -> str:
    """
    获取从指定地址出发的第一个数据交叉引用
    参数：
        address: 源地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用信息的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_data_first_from(str(address))


@mcp.tool()
def get_all_code_xrefs_to(address: Union[int, str]) -> str:
    """
    获取所有指向指定地址的代码交叉引用（数组形式）
    参数：
        address: 目标地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用列表的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_code_to_array(address)


@mcp.tool()
def get_all_code_xrefs_from(address: Union[int, str]) -> str:
    """
    获取所有从指定地址出发的代码交叉引用（数组形式）
    参数：
        address: 源地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用列表的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_code_from_array(address)


@mcp.tool()
def get_all_data_xrefs_to(address: Union[int, str]) -> str:
    """
    获取所有指向指定地址的数据交叉引用（数组形式）
    参数：
        address: 目标地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用列表的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_data_to_array(address)


@mcp.tool()
def get_all_data_xrefs_from(address: Union[int, str]) -> str:
    """
    获取所有从指定地址出发的数据交叉引用（数组形式）
    参数：
        address: 源地址（整数或十六进制字符串，如0x401000）
    返回值：包含交叉引用列表的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_data_from_array(address)


@mcp.tool()
def get_all_xrefs_list(address: Union[int, str]) -> str:
    """
    获取指定地址的所有交叉引用列表
    参数：
        address: 目标地址（整数或十六进制字符串，如0x401000）
    返回值：包含所有交叉引用的JSON字符串，错误时返回错误信息
    """
    memory_handler = Memory(config)
    return memory_handler.xref_get_list_array(address)


# ------------------------------ Other类接口 ------------------------------
@mcp.tool()
def set_assembly_comment(address: Union[int, str], comment: str) -> str:
    """
    为指定地址的汇编指令添加注释
    参数：
        address: 内存地址（整数或十六进制字符串，如0x401000）
        comment: 注释内容（非空字符串）
    返回值：操作结果的JSON字符串（成功/失败信息）
    """
    other_handler = Other(config)
    return other_handler.set_assembly_commnet(str(address), comment)


@mcp.tool()
def set_function_comment(address: Union[int, str], comment: str) -> str:
    """
    为指定地址的函数添加注释
    参数：
        address: 函数起始地址（整数或十六进制字符串，如0x401000）
        comment: 注释内容（非空字符串）
    返回值：操作结果的JSON字符串（成功/失败信息）
    """
    other_handler = Other(config)
    return other_handler.set_function_commnet(str(address), comment)


@mcp.tool()
def get_function_name(address: Union[int, str]) -> str:
    """
    获取指定地址的函数名称
    参数：
        address: 函数地址（整数或十六进制字符串，如0x401000）
    返回值：包含函数名称的JSON字符串，错误时返回错误信息
    """
    other_handler = Other(config)
    return other_handler.get_function_name(str(address))


@mcp.tool()
def set_function_name(address: Union[int, str], new_name: str) -> str:
    """
    为指定地址的函数重命名
    参数：
        address: 函数起始地址（整数或十六进制字符串，如0x401000）
        new_name: 新函数名称（非空字符串）
    返回值：操作结果的JSON字符串（成功/失败信息）
    """
    other_handler = Other(config)
    return other_handler.set_function_name(str(address), new_name)


@mcp.tool()
def switch_pseudocode_to(address: Union[int, str]) -> str:
    """
    切换伪代码视图到指定地址
    参数：
        address: 目标地址（整数或十六进制字符串，如0x401000）
    返回值：操作结果的JSON字符串（成功/失败信息）
    """
    other_handler = Other(config)
    return other_handler.switch_pseudocode_to(str(address))


@mcp.tool()
def get_function_var_name(address: Union[int, str]) -> str:
    """
    获取指定地址的函数变量名称
    参数：
        address: 变量地址（整数或十六进制字符串，如0x401000）
    返回值：包含变量名称的JSON字符串，错误时返回错误信息
    """
    other_handler = Other(config)
    return other_handler.get_function_var_name(str(address))


@mcp.tool()
def set_function_var_name(address: Union[int, str], uid: str, new_var_name: str) -> str:
    """
    为函数变量重命名
    参数：
        address: 函数地址（整数或十六进制字符串，如0x401000）
        uid: 变量唯一标识（非空字符串）
        new_var_name: 新变量名称（非空字符串）
    返回值：操作结果的JSON字符串（成功/失败信息）
    """
    other_handler = Other(config)
    return other_handler.set_function_var_name(str(address), uid, new_var_name)


@mcp.tool()
def get_struct_member_name(struct_name: str, offset: Union[int, str]) -> str:
    """
    获取结构体指定偏移的成员名称
    参数：
        struct_name: 结构体名称（非空字符串）
        offset: 成员偏移量（非负整数或对应字符串）
    返回值：包含成员名称的JSON字符串，错误时返回错误信息
    """
    other_handler = Other(config)
    return other_handler.get_struct_member_name(struct_name, offset)


@mcp.tool()
def set_struct_member_name(struct_name: str, offset: Union[int, str], new_member_name: str) -> str:
    """
    为结构体成员重命名
    参数：
        struct_name: 结构体名称（非空字符串）
        offset: 成员偏移量（非负整数或对应字符串）
        new_member_name: 新成员名称（非空字符串）
    返回值：操作结果的JSON字符串（成功/失败信息）
    """
    other_handler = Other(config)
    return other_handler.set_struct_member_name(struct_name, offset, new_member_name)


@mcp.tool()
def get_current_selection() -> str:
    """
    获取当前选中的内容信息
    返回值：包含选中内容的JSON字符串
    """
    other_handler = Other(config)
    return other_handler.get_current_select()


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8001, path="/mcp")