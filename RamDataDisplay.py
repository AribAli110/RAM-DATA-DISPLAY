import psutil
import os
import time
import win32security
import win32api
import wmi

def list_processes():
    """List all running processes and their open files."""
    print("Listing all running processes and open files...\n")
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            print(f"Process ID: {process.info['pid']}, Name: {process.info['name']}")
            files = process.open_files()
            if files:
                for file in files:
                    print(f"    Open File: {file.path}")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            # Skip processes we can't access
            print(f"    [Access Denied or Process Not Found]")
    print("\nFinished listing processes.")

def fetch_process_memory(pid):
    """Fetch memory information for a specific process."""
    try:
        process = psutil.Process(pid)
        print(f"\nFetching memory info for PID: {pid} ({process.name()})")
        memory_info = process.memory_info()
        print(f"  RSS (Resident Set Size): {memory_info.rss / (1024 ** 2):.2f} MB")
        print(f"  VMS (Virtual Memory Size): {memory_info.vms / (1024 ** 2):.2f} MB")
        print(f"  Shared Memory: {memory_info.shared / (1024 ** 2):.2f} MB")
    except psutil.AccessDenied:
        print(f"Access denied to process with PID: {pid}")
    except psutil.NoSuchProcess:
        print(f"Process with PID: {pid} no longer exists.")
    except Exception as e:
        print(f"An error occurred: {e}")

def fetch_logon_details():
    """Fetch user logon details."""
    print("\nFetching user logon details...")
    try:
        sessions = wmi.WMI().Win32_LogonSession()
        for session in sessions:
            print(f"Logon ID: {session.LogonId}")
            print(f"  Logon Type: {session.LogonType}")
            print(f"  Start Time: {session.StartTime}")
            print(f"  Status: {session.Status}")
        print("\nFinished fetching logon details.")
    except Exception as e:
        print(f"An error occurred: {e}")

def menu():
    """Interactive menu for the application."""
    while True:
        print("\nRAM and Open File Inspector")
        print("1. List all processes and open files")
        print("2. Fetch memory info for a specific process")
        print("3. Fetch user logon details")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            list_processes()
        elif choice == '2':
            pid = input("Enter Process ID (PID): ")
            if pid.isdigit():
                fetch_process_memory(int(pid))
            else:
                print("Invalid PID. Please enter a number.")
        elif choice == '3':
            fetch_logon_details()
        elif choice == '4':
            print("Exiting the application.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    print("Starting RAM and Open File Inspector...")
    menu()
