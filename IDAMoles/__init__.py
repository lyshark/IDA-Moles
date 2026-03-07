import configparser
import http.client
import sys
import os
import json
import socket
import urllib.request
from urllib.parse import urlparse
from urllib.error import URLError, HTTPError
from typing import List, Dict, Union, Optional, Callable
from io import StringIO
from functools import wraps
import subprocess
from typing import Optional

def check_server_available(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.config.is_server_available():
            return json.dumps({
                "status": "error",
                "message": "Server unavailable"
            }, ensure_ascii=False)
        return func(self, *args, **kwargs)
    return wrapper

def validate_hex_address(address: Union[int, str]) -> Optional[str]:
    if isinstance(address, int):
        return hex(address)

    addr_str = str(address).strip()
    if not addr_str:
        return None

    if addr_str.startswith(('0x', '0X')):
        try:
            int(addr_str, 16)
            return addr_str
        except ValueError:
            return None
    try:
        int(addr_str, 10)
        return addr_str
    except ValueError:
        return None

class Config:
    def __init__(self, address: str = "127.0.0.1", port: int = 8000):
        self.address = address
        self.port = port
        self.ida_server_addr = f"http://{address}:{port}"
        self.ida_path = None
        self.ida_http = "http://moles.lyshark.com/"
        self.ida_engine = "IDAMoles.dll"
        self.timeout = 5

    def is_server_available(self, timeout: Optional[int] = None) -> bool:
        timeout = timeout or self.timeout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((self.address, self.port))
                return result == 0
        except socket.error as e:
            print(f"WARNING: Server check failed: {str(e)}")
            return False

    def set_ida_path(self, ida_path: str) -> bool:
        if not sys.platform.startswith("win32"):
            error_msg = "Only supports setting IDA path on Windows system"
            print(f"ERROR: {error_msg}")
            return

        ida_path = ida_path.strip("'\" ").strip()
        if not ida_path:
            print("ERROR: Empty path provided")
            return

        try:
            expanded_path = os.path.expandvars(ida_path)
            abs_path = os.path.abspath(expanded_path)
            normalized_path = os.path.normpath(abs_path)
        except Exception as e:
            print(f"ERROR: Invalid path format: {ida_path} (reason: {str(e)})")
            return

        if os.path.basename(normalized_path).lower() == "plugins":
            normalized_path = os.path.dirname(normalized_path)
            print(f"WARNING: Path contains 'plugins', automatically adjusted to: {normalized_path}")

        if not os.path.exists(normalized_path):
            error_msg = f"The path does not exist: {normalized_path} (original input: {ida_path})"
            print(f"ERROR: {error_msg}")
            return

        if not os.path.isdir(normalized_path):
            error_msg = f"Not a valid directory: {normalized_path} (original input: {ida_path})"
            print(f"ERROR: {error_msg}")
            return

        if not os.access(normalized_path, os.R_OK):
            error_msg = f"No read permission for path: {normalized_path}"
            print(f"ERROR: {error_msg}")
            return

        ida_exe_path = os.path.join(normalized_path, "ida.exe")
        if not os.path.exists(ida_exe_path):
            error_msg = f"IDA executable 'ida.exe' not found in root directory: {normalized_path}"
            print(f"ERROR: {error_msg}")
            return

        if not os.path.isfile(ida_exe_path):
            error_msg = f"'{ida_exe_path}' is not a valid file (expected ida.exe)"
            print(f"ERROR: {error_msg}")
            return

        self.ida_path = os.path.join(normalized_path, "plugins")
        print(f"The IDA path has been set to: {self.ida_path} (original input: {ida_path})")
        return

    def install_moles(self) -> str:
        if self.ida_path is None:
            print("WARNING: Please first execute set_ida_path to set the IDA directory")
            return

        try:
            target_path = os.path.join(self.ida_path, self.ida_engine)
            save_dir = os.path.dirname(target_path)

            if not os.path.exists(save_dir):
                os.makedirs(save_dir, exist_ok=True)
                print(f"Created directory: {save_dir}")

            with urllib.request.urlopen(self.ida_http + self.ida_engine, timeout=self.timeout) as response:
                file_size = int(response.headers.get('Content-Length', 0))
                downloaded_size = 0
                chunk_size = 8192

                with open(target_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        if file_size > 0:
                            progress = (downloaded_size / file_size) * 100
                            print(f"\rDownload progress: {progress:.2f}%", end='')
            print(f"\n[*] Install Moles Success")
            return

        except HTTPError as e:
            print(f"ERROR: HTTP Error: Server returns status code {e.code}")
            return
        except URLError as e:
            print(f"ERROR: URL error: unable to connect to server - {e.reason}")
            return
        except TimeoutError:
            print("ERROR: Connection to server or data read timeout")
            return
        except IOError as e:
            print(f"ERROR: File write error: unable to write to {target_path} - {e}")
            return
        except PermissionError:
            print(f"ERROR: Permission denied: Unable to write to {target_path}. Please run as administrator.")
            return
        except Exception as e:
            print(f"ERROR: Unknown error occurred: {e}")
            return

    def get_version(self) -> Optional[str]:
        try:
            req = urllib.request.Request(url=f"{self.ida_http}version.ini")
            with urllib.request.urlopen(req, timeout=15) as response:
                try:
                    ini_content = response.read().decode("utf-8")
                except UnicodeDecodeError:
                    ini_content = response.read().decode("gbk")

                config = configparser.ConfigParser()
                config.read_file(StringIO(ini_content))

                if not config.has_section("setting") or not config.has_option("setting", "version"):
                    return None

                return config.get("setting", "version").strip()

        except (HTTPError, URLError, configparser.Error, TimeoutError, Exception) as e:
            print(f"WARNING: Failed to get version: {str(e)}")
            return None

    def open_ida_with_program(self, program_path: str, auto_mode: bool = False, force_new: bool = False) -> bool:
        if not self.ida_path:
            print("ERROR: Please call set_ida_path to set the IDA path first")
            return
        ida_root = os.path.dirname(self.ida_path)
        ida_exe_path = os.path.join(ida_root, "ida.exe")
        if not os.path.exists(ida_exe_path) or not os.path.isfile(ida_exe_path):
            print(f"ERROR: ida.exe not found, path:{ida_exe_path}")
            return
        program_path = os.path.abspath(program_path)
        if not os.path.exists(program_path) or not os.path.isfile(program_path):
            print(f"ERROR: The target program does not exist or is not a file. Path:{program_path}")
            return
        cmd = [ida_exe_path]
        if auto_mode:
            cmd.append("-A")
        if force_new:
            cmd.append("-c")
        cmd.append(program_path)
        try:
            subprocess.Popen(cmd, shell=False)
            print(f"SUCCESS: IDA has been started and the program has been loaded:{program_path}")
            return
        except Exception as e:
            print(f"ERROR: Failed to start IDA:{str(e)}")
            return

class BaseHttpClient:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        parsed_url = urlparse(self.config.ida_server_addr)
        self.address = parsed_url.hostname
        self.port = parsed_url.port
        self.scheme = parsed_url.scheme
        self.path = parsed_url.path or '/'
        self.verify_ssl = True

    def custom_post(self,
                    json_data: Optional[Dict] = None,
                    headers: Optional[Dict] = None,
                    timeout: Optional[int] = None) -> str:
        if not headers:
            headers = {}
        if json_data and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        body = json.dumps(json_data).encode('utf-8') if json_data else None
        timeout = timeout or self.config.timeout

        try:
            if self.scheme == 'https':
                import ssl
                context = ssl._create_unverified_context() if not self.verify_ssl else None
                conn = http.client.HTTPSConnection(self.address, self.port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(self.address, self.port, timeout=timeout)

            conn.request("POST", self.path, body=body, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode('utf-8')
            conn.close()
            return response_text

        except socket.timeout:
            return json.dumps({
                "status": "error",
                "message": "Request timed out"
            }, ensure_ascii=False)
        except ConnectionRefusedError:
            return json.dumps({
                "status": "error",
                "message": "Connection refused by server"
            }, ensure_ascii=False)
        except json.JSONDecodeError:
            return json.dumps({
                "status": "error",
                "message": "Failed to serialize request data"
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": f"Request failed: {str(e)}"
            }, ensure_ascii=False)

class Info(BaseHttpClient):
    @check_server_available
    def get_basic_info(self) -> str:
        request_data = {
            "class": "Info",
            "interface": "GetBasicInfo",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_image_info(self) -> str:
        request_data = {
            "class": "Info",
            "interface": "GetImageInfo",
            "params": []
        }
        return self.custom_post(json_data=request_data)

class Function(BaseHttpClient):
    @check_server_available
    def get_functions(self) -> str:
        request_data = {
            "class": "Function",
            "interface": "GetFunction",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_function_info(self, func_start_addr: Union[int, str]) -> str:
        addr_str = validate_hex_address(func_start_addr)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Function",
            "interface": "GetFunctionInfo",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_import_functions(self) -> str:
        request_data = {
            "class": "Function",
            "interface": "GetImportFunctions",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_function_count(self) -> str:
        request_data = {
            "class": "Function",
            "interface": "GetFunctionCount",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_function_by_addr(self, func_start_addr: Union[int, str]) -> str:
        addr_str = validate_hex_address(func_start_addr)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Function",
            "interface": "GetFunctionByAddr",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_function_by_name(self, func_name: str) -> str:
        if not func_name.strip():
            return json.dumps({
                "status": "error",
                "message": "Function name cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Function",
            "interface": "GetFunctionByName",
            "params": [func_name.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def find_function_by_name(self, keyword: str) -> str:
        if not keyword.strip():
            return json.dumps({
                "status": "error",
                "message": "The search keyword cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Function",
            "interface": "FindFunctionByName",
            "params": [keyword.strip()]
        }
        return self.custom_post(json_data=request_data)

class Segment(BaseHttpClient):
    @check_server_available
    def get_segments(self) -> str:
        request_data = {
            "class": "Segment",
            "interface": "GetSegment",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_segment_count(self) -> str:
        request_data = {
            "class": "Segment",
            "interface": "GetSegmentCount",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_segment_from_addr(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Segment",
            "interface": "GetSegmentFromAddr",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

class Reverse(BaseHttpClient):
    @check_server_available
    def disassembly_function(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid or empty address"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DisassembleFunction",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def disassembly_count(self, address: Union[int, str], line_count: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid or empty address"
            }, ensure_ascii=False)

        try:
            line_count_int = int(str(line_count).strip(), 0)
            if line_count_int <= 0 or line_count_int > 1024:
                return json.dumps({
                    "status": "error",
                    "message": "The line count must be between 1 and 1024"
                }, ensure_ascii=False)
        except ValueError:
            return json.dumps({
                "status": "error",
                "message": "Invalid line count (must be integer)"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DisassemblyCount",
            "params": [addr_str, str(line_count_int)]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def disassembly_range(self, start_address: Union[int, str], end_address: Union[int, str]) -> str:
        start_addr = validate_hex_address(start_address)
        end_addr = validate_hex_address(end_address)

        if not start_addr:
            return json.dumps({
                "status": "error",
                "message": "Invalid or empty start address"
            }, ensure_ascii=False)

        if not end_addr:
            return json.dumps({
                "status": "error",
                "message": "Invalid or empty end address"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DisassemblyRange",
            "params": [start_addr, end_addr]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def decompile_checked(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid or empty address"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DeompileChecked",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def decompile_micro_code(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid or empty address"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "GetMicroCode",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def decompile_from_addr(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DecompileFunctionFromAddr",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def decompile_from_name(self, func_name: str) -> str:
        if not func_name.strip():
            return json.dumps({
                "status": "error",
                "message": "Function name cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DecompileFunctionFromName",
            "params": [func_name.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def decompile_line_to_address(self, address: str, line: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        if not line.strip():
            return json.dumps({
                "status": "error",
                "message": "Line number cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DecompileLineToAddress",
            "params": [addr_str, line.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def decompile_address_to_line(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Reverse",
            "interface": "DecompileAddressToLine",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_select_decompile(self) -> str:
        request_data = {
            "class": "Reverse",
            "interface": "GetSelectDecompile",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_select_disassembly(self) -> str:
        request_data = {
            "class": "Reverse",
            "interface": "GetSelectDisassembly",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_select_hex(self) -> str:
        request_data = {
            "class": "Reverse",
            "interface": "GetSelectHex",
            "params": []
        }
        return self.custom_post(json_data=request_data)

class Memory(BaseHttpClient):
    @check_server_available
    def get_entry_points(self) -> str:
        request_data = {
            "class": "Memory",
            "interface": "GetEntryPoints",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_defined_struct(self) -> str:
        request_data = {
            "class": "Memory",
            "interface": "GetDefinedStruct",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_memory_byte(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "GetMemoryByte",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_memory_word(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "GetMemoryWord",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_memory_dword(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "GetMemoryDword",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_memory_qword(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "GetMemoryQword",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_memory_bytes(self, address: str, byte_len: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        try:
            length = int(byte_len.strip())
            if length <= 0:
                return json.dumps({
                    "status": "error",
                    "message": "Length must be positive"
                }, ensure_ascii=False)
        except ValueError:
            return json.dumps({
                "status": "error",
                "message": "Invalid length format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "GetMemoryBytes",
            "params": [addr_str, str(length)]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_string_info(self) -> str:
        request_data = {
            "class": "Memory",
            "interface": "GetStringInfo",
            "params": []
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_memory_search(self, start_address: str, end_address: str, param: str) -> str:
        start_addr = validate_hex_address(start_address)
        end_addr = validate_hex_address(end_address)

        if not start_addr:
            return json.dumps({
                "status": "error",
                "message": "Invalid start address format"
            }, ensure_ascii=False)

        if not end_addr:
            return json.dumps({
                "status": "error",
                "message": "Invalid end address format"
            }, ensure_ascii=False)

        if not param.strip():
            return json.dumps({
                "status": "error",
                "message": "Search parameter cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "MemorySearch",
            "params": [start_addr, end_addr, param.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_type_by_name(self, type_name: str) -> str:
        if not type_name.strip():
            return json.dumps({
                "status": "error",
                "message": "Type name cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "GetTypeByName",
            "params": [type_name.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_code_first_to(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefCodeFirstTo",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_code_first_from(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefCodeFirstFrom",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_data_first_to(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefDataFirstTo",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_data_first_from(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefDataFirstFrom",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_code_to_array(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format (must be integer or hex string like '0x401000')"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefCodeToArray",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_code_from_array(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format (must be integer or hex string like '0x401538')"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefCodeFromArray",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_data_to_array(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format (must be integer or hex string like '0x401538')"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefDataToArray",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_data_from_array(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format (must be integer or hex string like '0x401538')"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefDataFromArray",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def xref_get_list_array(self, address: Union[int, str]) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format (must be integer or hex string like '0x401538')"
            }, ensure_ascii=False)

        request_data = {
            "class": "Memory",
            "interface": "XrefGetListArray",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

class Other(BaseHttpClient):
    @check_server_available
    def set_assembly_commnet(self, address: str, comment: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        if not comment.strip():
            return json.dumps({
                "status": "error",
                "message": "Comment cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "SetAssemblyComment",
            "params": [addr_str, comment.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def set_function_commnet(self, address: str, comment: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        if not comment.strip():
            return json.dumps({
                "status": "error",
                "message": "Comment cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "SetFunctionComment",
            "params": [addr_str, comment.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_function_name(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "GetFunctionName",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def set_function_name(self, address: str, text: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        if not text.strip():
            return json.dumps({
                "status": "error",
                "message": "Function name cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "SetFunctionName",
            "params": [addr_str, text.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def switch_pseudocode_to(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "SwitchPseudoCodeTo",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_function_var_name(self, address: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "GetFunctionVarName",
            "params": [addr_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def set_function_var_name(self, address: str, uid: str, names: str) -> str:
        addr_str = validate_hex_address(address)
        if not addr_str:
            return json.dumps({
                "status": "error",
                "message": "Invalid address format"
            }, ensure_ascii=False)

        if not uid.strip():
            return json.dumps({
                "status": "error",
                "message": "UID cannot be empty"
            }, ensure_ascii=False)

        if not names.strip():
            return json.dumps({
                "status": "error",
                "message": "Variable name cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "SetFunctionVarName",
            "params": [addr_str, uid.strip(), names.strip()]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_struct_member_name(self, struct_name: str, offset: Union[int, str]) -> str:
        if not struct_name.strip():
            return json.dumps({
                "status": "error",
                "message": "Struct name cannot be empty"
            }, ensure_ascii=False)

        try:
            offset_val = int(str(offset).strip(), 0)
            if offset_val < 0:
                raise ValueError("Offset must be non-negative")
            offset_str = str(offset_val)
        except ValueError as e:
            return json.dumps({
                "status": "error",
                "message": f"Invalid offset format: {str(e)}"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "GetStructMemberName",
            "params": [struct_name.strip(), offset_str]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def set_struct_member_name(self, struct_name: str, offset: Union[int, str], new_member_name: str) -> str:
        if not struct_name.strip():
            return json.dumps({
                "status": "error",
                "message": "Struct name cannot be empty"
            }, ensure_ascii=False)

        try:
            offset_val = int(str(offset).strip(), 0)
            if offset_val < 0:
                raise ValueError("Offset must be non-negative")
            offset_str = str(offset_val)
        except ValueError as e:
            return json.dumps({
                "status": "error",
                "message": f"Invalid offset format: {str(e)}"
            }, ensure_ascii=False)

        if not new_member_name.strip():
            return json.dumps({
                "status": "error",
                "message": "New member name cannot be empty"
            }, ensure_ascii=False)

        request_data = {
            "class": "Other",
            "interface": "SetStructMemberName",
            "params": [
                struct_name.strip(),
                offset_str,
                new_member_name.strip()
            ]
        }
        return self.custom_post(json_data=request_data)

    @check_server_available
    def get_current_select(self) -> str:
        request_data = {
            "class": "Other",
            "interface": "GetCurrentSelect",
            "params": []
        }
        return self.custom_post(json_data=request_data)