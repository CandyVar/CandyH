import os
import platform
import uuid
import requests
import ctypes
import ctypes.wintypes
import psutil
import ctypes
import psutil
import os
import sys
import time
import random
import threading
from ctypes import wintypes
import shutil
import tempfile

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
VirtualAllocEx.restype = wintypes.LPVOID
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_size_t)]

CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
CreateRemoteThread.restype = wintypes.HANDLE
CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID,
                               wintypes.DWORD, wintypes.LPDWORD]

GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleW
GetModuleHandle.restype = wintypes.HANDLE
GetModuleHandle.argtypes = [wintypes.LPCWSTR]

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.restype = wintypes.LPVOID
GetProcAddress.argtypes = [wintypes.HANDLE, wintypes.LPCSTR]

# Константы
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

inject_completed = False


def get_process_handle():
    """Находит процесс javaw.exe, связанный с Lunar Client, и возвращает его PID"""
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        if process.info['name'] == 'javaw.exe':
            if any("lunar" in arg.lower() for arg in process.info['cmdline']):
                return process.info['pid']
    return None


def download_dll(url, filename):
    """Скачиваем DLL файл по указанному URL."""
    response = requests.get(url)
    if response.status_code == 200:
        with open(filename, 'wb') as f:
            f.write(response.content)
        print(f"Downloaded {filename}")
    else:
        print(f"Failed to download DLL: {response.status_code}")


def inject_dll(process_id, dll):
    """Инжектирует DLL в процесс с заданным PID"""
    global inject_completed
    try:
        # Открываем процесс
        h_process = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not h_process:
            print("\n\033[1;31m[ERROR] Не удалось открыть процесс.\033[0m")
            return

        # Выделяем память в процессе для пути к DLL
        dll_path_bytes = dll.encode('utf-8')
        dll_len = len(dll_path_bytes) + 1
        dll_address = VirtualAllocEx(h_process, None, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not dll_address:
            print("\n\033[1;31m[ERROR] Не удалось выделить память в процессе.\033[0m")
            return

        # Записываем путь к DLL в память процесса
        bytes_written = ctypes.c_size_t(0)
        if not WriteProcessMemory(h_process, dll_address, dll_path_bytes, dll_len, ctypes.byref(bytes_written)):
            print("\n\033[1;31m[ERROR] Не удалось записать путь к DLL в память процесса.\033[0m")
            return

        # Находим адрес LoadLibraryA
        kernel32_handle = GetModuleHandle("kernel32.dll")
        load_library_a_address = GetProcAddress(kernel32_handle, b"LoadLibraryA")

        # Создаем удаленный поток, который выполнит LoadLibraryA
        thread_id = ctypes.c_ulong(0)
        h_thread = CreateRemoteThread(h_process, None, 0, load_library_a_address, dll_address, 0,
                                      ctypes.byref(thread_id))
        if not h_thread:
            print("\n\033[1;31m[ERROR] Не удалось создать поток.\033[0m")
            return

        print("\n\033[1;32m[INFO] DLL успешно инжектирована.\033[0m")
    finally:
        inject_completed = True


def get_dll_path(dll_filename):
    # Путь к временной директории
    temp_dir = tempfile.gettempdir()
    # Полный путь к DLL в временной директории
    dll_path = os.path.join(temp_dir, dll_filename)
    # Если DLL уже существует, удаляем её
    if os.path.exists(dll_path):
        os.remove(dll_path)
    # Копируем DLL из текущей директории во временную
    shutil.copyfile(dll_filename, dll_path)
    return dll_path


def get_hwid():
    # Получение серийного номера диска
    disk_serial = "UNKNOWN"
    if os.name == 'nt':  # Windows
        try:
            disk_serial = os.popen('wmic diskdrive get serialnumber').read().split('\n')[1].strip()
        except Exception as e:
            print(f"Error getting disk serial: {e}")

    # Получение информации о процессоре
    cpu_info = "UNKNOWN"
    try:
        cpu_info = platform.processor()
    except Exception as e:
        print(f"Error getting CPU info: {e}")

    # Получение MAC-адреса
    mac_address = "UNKNOWN"
    try:
        mac_address = ':'.join(
            ['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
    except Exception as e:
        print(f"Error getting MAC address: {e}")

    # Объединение всех компонентов в одну строку HWID
    hwid = f"{disk_serial}-{cpu_info}-{mac_address}"
    return ''.join(hwid.split())


def main():
    ip = "http://localhost:5000"  # Замените на ваш IP

    while True:
        email = input("Enter your email: ")
        password = input("Enter your password: ")

        email = "candyvar@mail.ru"
        password = "123"
        # Аутентификация
        login_data = {
            "email": email,
            "password": password
        }
        headers = {
            "Authorization": f"Bearer yandexlyceum_secret_key"
        }
        response = requests.post(f"{ip}/api/login", json=login_data, headers=headers)

        if response.status_code == 200:
            print("Login successful")
            data = response.json()

            # Проверяем HWID
            if data.get("hwid") == "None":
                hwid = get_hwid()
                set_hwid_data = {
                    "email": email,
                    "hwid": hwid,
                    "password": password
                }
                set_response = requests.post(f"{ip}/api/sethwid", json=set_hwid_data, headers=headers)
                if set_response.status_code == 200:
                    print("HWID successfully set")
                else:
                    print(set_response)
            else:
                # Сравниваем HWID
                server_hwid = data.get("hwid")
                generated_hwid = get_hwid()
                if server_hwid == generated_hwid:
                    print("HWID matches with the server")
                    dll_filename = "candyh.dll"
                    dll_url = f"{ip}/download/{dll_filename}"
                    dll_path = get_dll_path(dll_filename)
                    lunar_client_pid = get_process_handle()
                    if lunar_client_pid:
                        print(f"\033[1;32m[INFO] Найден процесс Lunar Client с PID {lunar_client_pid}\033[0m")
                        inject_dll(lunar_client_pid, dll_path)
                    else:
                        print("\033[1;31m[ERROR] Процесс Lunar Client не найден.\033[0m")
                    time.sleep(1)
                    try:
                        os.remove(dll_filename)
                        print(f"Removed {dll_filename}")
                    except Exception as e:
                        print(f"Failed to remove DLL: {e}")

                else:
                    print("HWID does not match with the server", generated_hwid)
            break
        else:
            print("Login failed. Please try again.")
            os.system('cls' if os.name == 'nt' else 'clear')


if __name__ == "__main__":
    main()
