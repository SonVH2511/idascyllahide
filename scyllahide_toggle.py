"""
ScyllaHide Toggle Plugin for IDA Pro
Adds a button to toggle ScyllaHide auto-injection into the current debugging process
Injects HookLibrary DLL using InjectorCLI
"""

import ida_kernwin
import ida_idaapi
import ida_dbg
import idaapi
import idc
import os
import sys
import subprocess
import traceback
import time
import shutil
import hashlib
import random
import string

PLUGIN_NAME = "ScyllaHide Toggle"
PLUGIN_HOTKEY = "Ctrl-Shift-H"

# Determine plugin directory
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
SCYLLAHIDE_DIR = os.path.join(PLUGIN_DIR, "Scyllahide")

# Original DLL names (for reference)
ORIGINAL_X86_DLL = "HookLibraryx86.dll"
ORIGINAL_X64_DLL = "HookLibraryx64.dll"

def log(msg):
    """Print message to IDA output window"""
    print(f"[ScyllaHide] {msg}")

def generate_random_name(prefix="", extension=".dll"):
    """Generate random DLL name to avoid hash detection"""
    # Generate random string
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    if prefix:
        return f"{prefix}_{random_str}{extension}"
    return f"{random_str}{extension}"

def find_hook_dll(directory, original_name):
    """Find hook DLL in directory (original or renamed)"""
    original_path = os.path.join(directory, original_name)
    
    # If original exists, return it
    if os.path.exists(original_path):
        return original_path
    
    # Search for any DLL that might be the renamed hook library
    # Look for DLL files that are not InjectorCLI
    try:
        for file in os.listdir(directory):
            if file.endswith('.dll') and 'InjectorCLI' not in file:
                full_path = os.path.join(directory, file)
                # Check if it's a reasonable size (hook library should be > 10KB)
                if os.path.getsize(full_path) > 10000:
                    log(f"Found potential hook DLL: {file}")
                    return full_path
    except Exception as e:
        log(f"Error searching for DLL: {e}")
    
    return None

def rename_dll_to_avoid_detection(dll_path):
    """Rename DLL file to avoid hash-based detection"""
    if not os.path.exists(dll_path):
        log(f"DLL not found: {dll_path}")
        return None
    
    directory = os.path.dirname(dll_path)
    old_name = os.path.basename(dll_path)
    
    # Generate new random name
    new_name = generate_random_name(prefix="kernel", extension=".dll")
    new_path = os.path.join(directory, new_name)
    
    try:
        # Rename the file
        shutil.move(dll_path, new_path)
        log(f"✓ Renamed: {old_name} -> {new_name}")
        return new_path
    except Exception as e:
        log(f"✗ Failed to rename DLL: {e}")
        return dll_path

class ScyllaHideInjector:
    """Handler for ScyllaHide DLL injection using InjectorCLI"""
    
    def __init__(self):
        self.is_injected = False
        self.injected_pid = None
        self._find_scyllahide_paths()
        log(f"Injector initialized")
        
    def _find_scyllahide_paths(self):
        """Find ScyllaHide binaries and config paths"""
        # Check if ScyllaHide directory exists
        if not os.path.exists(SCYLLAHIDE_DIR):
            log(f"ERROR: ScyllaHide directory not found: {SCYLLAHIDE_DIR}")
            self.x86_injector = None
            self.x64_injector = None
            self.x86_config = None
            self.x64_config = None
            return
            
        # 32-bit paths
        x86_dir = os.path.join(SCYLLAHIDE_DIR, "32")
        self.x86_injector = os.path.join(x86_dir, "InjectorCLIx86.exe")
        self.x86_config = os.path.join(x86_dir, "scylla_hide.ini")
        
        # Find 32-bit DLL (original or renamed)
        self.x86_dll = find_hook_dll(x86_dir, ORIGINAL_X86_DLL)
        
        # 64-bit paths  
        x64_dir = os.path.join(SCYLLAHIDE_DIR, "64")
        self.x64_injector = os.path.join(x64_dir, "InjectorCLIx64.exe")
        self.x64_config = os.path.join(x64_dir, "scylla_hide.ini")
        
        # Find 64-bit DLL (original or renamed)
        self.x64_dll = find_hook_dll(x64_dir, ORIGINAL_X64_DLL)
        
        # Log paths
        log(f"32-bit injector: {self.x86_injector}")
        if self.x86_dll:
            log(f"32-bit DLL: {os.path.basename(self.x86_dll)}")
        else:
            log("✗ 32-bit DLL NOT found")
            
        log(f"64-bit injector: {self.x64_injector}")
        if self.x64_dll:
            log(f"64-bit DLL: {os.path.basename(self.x64_dll)}")
        else:
            log("✗ 64-bit DLL NOT found")
        
        # Check if injectors exist
        if os.path.exists(self.x86_injector):
            log("✓ 32-bit injector found")
        else:
            log("✗ 32-bit injector NOT found")
            
        if os.path.exists(self.x64_injector):
            log("✓ 64-bit injector found")
        else:
            log("✗ 64-bit injector NOT found")
    
    def _is_64bit_process(self, pid):
        """Check if process is 64-bit"""
        try:
            # Get info structure from IDA
            inf = ida_idaapi.get_inf_structure()
            is_64 = inf.is_64bit()
            log(f"Process is {'64-bit' if is_64 else '32-bit'}")
            return is_64
        except:
            try:
                # Alternative method using idaapi
                import idc
                info = idc.get_inf_attr(idc.INF_PROCNAME)
                # Check if it's a 64-bit processor
                is_64 = idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT != 0
                log(f"Process is {'64-bit' if is_64 else '32-bit'} (method 2)")
                return is_64
            except Exception as e:
                log(f"Error checking bitness (method 2): {e}")
                # Default to 32-bit if unable to determine
                log("Defaulting to 32-bit")
                return False
    
    def _get_current_pid(self):
        """Get current debugging process PID"""
        pid = None
        
        # Try to get PID using Windows API via ctypes
        try:
            import ctypes
            import ctypes.wintypes
            
            # Get the target process name from IDA
            process_path = idaapi.get_input_file_path()
            process_name = os.path.basename(process_path)
            log(f"Target process name: {process_name}")
            
            # Use Windows API to find the process by name
            PROCESSENTRY32 = ctypes.wintypes.LPVOID
            TH32CS_SNAPPROCESS = 0x00000002
            
            # Create toolhelp snapshot
            kernel32 = ctypes.windll.kernel32
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            
            if snapshot == -1:
                log("Failed to create process snapshot")
                # Ask user for PID
                pid = ida_kernwin.ask_long(0, f"Enter PID for {process_name}:")
                return pid if pid and pid > 0 else None
            
            # Define PROCESSENTRY32 structure
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ('dwSize', ctypes.wintypes.DWORD),
                    ('cntUsage', ctypes.wintypes.DWORD),
                    ('th32ProcessID', ctypes.wintypes.DWORD),
                    ('th32DefaultHeapID', ctypes.POINTER(ctypes.wintypes.ULONG)),
                    ('th32ModuleID', ctypes.wintypes.DWORD),
                    ('cntThreads', ctypes.wintypes.DWORD),
                    ('th32ParentProcessID', ctypes.wintypes.DWORD),
                    ('pcPriClassBase', ctypes.wintypes.LONG),
                    ('dwFlags', ctypes.wintypes.DWORD),
                    ('szExeFile', ctypes.c_char * 260)
                ]
            
            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            # Iterate through processes to find matching name
            found_pids = []
            if kernel32.Process32First(snapshot, ctypes.byref(pe32)):
                while True:
                    current_name = pe32.szExeFile.decode('utf-8', errors='ignore')
                    if current_name.lower() == process_name.lower():
                        found_pids.append((pe32.th32ProcessID, current_name))
                        log(f"Found matching process: {current_name} (PID: {pe32.th32ProcessID})")
                    
                    if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                        break
            
            kernel32.CloseHandle(snapshot)
            
            # Handle results
            if len(found_pids) == 1:
                pid = found_pids[0][0]
                log(f"✓ Auto-detected PID: {pid}")
            elif len(found_pids) > 1:
                log(f"Multiple instances found: {found_pids}")
                msg = f"Multiple {process_name} processes found:\n\n"
                for p, n in found_pids:
                    msg += f"  PID {p}: {n}\n"
                msg += f"\nEnter the correct PID:"
                pid = ida_kernwin.ask_long(found_pids[0][0], msg)
            else:
                log(f"Process '{process_name}' not found in running processes")
                log("Make sure to start the process first (F9) or it may have a different name")
                pid = ida_kernwin.ask_long(0, f"Process not running.\nEnter PID manually or press F9 first:")
                
        except Exception as e:
            log(f"Error getting PID: {e}")
            traceback.print_exc()
            
            # Fallback: Ask user for PID
            pid = ida_kernwin.ask_long(0, "Enter the Process ID (PID) to inject ScyllaHide:")
        
        if pid and pid > 0:
            log(f"✓ Using PID: {pid}")
            return pid
        else:
            log("ERROR: No valid PID provided")
            return None
    
    def inject_current_process(self):
        """Inject ScyllaHide DLL into current debugging process"""
        pid = self._get_current_pid()
        if pid is None:
            return False
        
        # Determine if 64-bit or 32-bit
        is_64bit = self._is_64bit_process(pid)
        
        # Select appropriate injector and DLL
        if is_64bit:
            injector = self.x64_injector
            dll = self.x64_dll
            config = self.x64_config
            arch = "64-bit"
        else:
            injector = self.x86_injector
            dll = self.x86_dll
            config = self.x86_config
            arch = "32-bit"
        
        # Check if injector exists
        if not os.path.exists(injector):
            log(f"ERROR: {arch} injector not found: {injector}")
            return False
            
        if dll is None or not os.path.exists(dll):
            log(f"ERROR: {arch} DLL not found")
            log(f"Tip: Make sure the DLL file exists in the {arch} folder")
            return False
        
        log(f"Using {arch} injector: {os.path.basename(injector)}")
        log(f"Injecting DLL: {os.path.basename(dll)}")
        if os.path.exists(config):
            log(f"Config file: {os.path.basename(config)}")
        
        try:
            # Build command: InjectorCLI.exe pid:<PID> <DLL_PATH>
            # Note: Config is NOT passed via command line, it must be in same directory as DLL
            cmd = [injector, f"pid:{pid}", dll]
            
            log(f"Executing: {' '.join(cmd)}")
            
            # Execute injector
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=os.path.dirname(injector)  # Run from injector directory
            )
            
            log(f"Return code: {result.returncode}")
            
            if result.stdout:
                log(f"Output: {result.stdout.strip()}")
            if result.stderr:
                log(f"Error: {result.stderr.strip()}")
            
            if result.returncode == 0:
                self.is_injected = True
                self.injected_pid = pid
                log("✓ Successfully injected ScyllaHide!")
                return True
            else:
                log(f"✗ Injection failed with code {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            log("ERROR: Injection timeout")
            return False
        except Exception as e:
            log(f"ERROR: Exception during injection: {e}")
            traceback.print_exc()
            return False
    
    def detach_current_process(self):
        """Detach ScyllaHide from current process"""
        # Note: InjectorCLI doesn't support unloading/detaching
        # The DLL will remain injected until process terminates
        log("Note: ScyllaHide DLL cannot be unloaded dynamically")
        log("The hooks will remain until the process terminates")
        
        # Just update our tracking state
        self.is_injected = False
        self.injected_pid = None
        
        return True
    
    def check_status(self):
        """Check if ScyllaHide files are available"""
        # Check if at least one injector exists
        has_x86 = os.path.exists(self.x86_injector) if self.x86_injector else False
        has_x64 = os.path.exists(self.x64_injector) if self.x64_injector else False
        
        available = has_x86 or has_x64
        
        if available:
            log("✓ ScyllaHide binaries are available")
        else:
            log("✗ ScyllaHide binaries not found")
            
        return available
    
    def rename_dlls_for_stealth(self):
        """Rename DLL files to avoid hash-based detection"""
        renamed = []
        
        # Rename 32-bit DLL
        x86_dir = os.path.join(SCYLLAHIDE_DIR, "32")
        x86_original = os.path.join(x86_dir, ORIGINAL_X86_DLL)
        if os.path.exists(x86_original):
            new_path = rename_dll_to_avoid_detection(x86_original)
            if new_path and new_path != x86_original:
                renamed.append(f"32-bit: {os.path.basename(new_path)}")
                self.x86_dll = new_path
        
        # Rename 64-bit DLL
        x64_dir = os.path.join(SCYLLAHIDE_DIR, "64")
        x64_original = os.path.join(x64_dir, ORIGINAL_X64_DLL)
        if os.path.exists(x64_original):
            new_path = rename_dll_to_avoid_detection(x64_original)
            if new_path and new_path != x64_original:
                renamed.append(f"64-bit: {os.path.basename(new_path)}")
                self.x64_dll = new_path
        
        return renamed


class ScyllaHideAction(ida_kernwin.action_handler_t):
    """Action handler for the toggle button"""
    
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.injector = ScyllaHideInjector()
        log("Action handler initialized")
    
    def activate(self, ctx):
        """Called when the action is triggered"""
        log("=" * 50)
        log("Action activated!")
        log(f"Debugger on: {ida_dbg.is_debugger_on()}")
        
        # Check if debugger is active
        if not ida_dbg.is_debugger_on():
            log("Debugger is not active")
            ida_kernwin.warning("Please start the debugger first!")
            return 0
        
        log("Debugger is active")
        
        # Check if ScyllaHide binaries are available
        if not self.injector.check_status():
            log("ScyllaHide binaries check failed")
            msg = (
                "ScyllaHide binaries not found!\n\n"
                f"Expected location:\n{SCYLLAHIDE_DIR}\n\n"
                "Please ensure ScyllaHide folder with InjectorCLI and DLLs exists."
            )
            ida_kernwin.warning(msg)
            return 0
        
        log("ScyllaHide binaries available")
        
        # Toggle injection
        if self.injector.is_injected:
            log("Attempting to detach...")
            if self.injector.detach_current_process():
                ida_kernwin.info("ScyllaHide state cleared\n(DLL remains active until process terminates)")
        else:
            log("Attempting to inject...")
            if self.injector.inject_current_process():
                ida_kernwin.info("ScyllaHide injected successfully!\nAnti-debug hooks are now active.")
            else:
                ida_kernwin.warning("Failed to inject ScyllaHide!\nCheck the output window for details.")
        
        log("=" * 50)
        return 1
    
    def update(self, ctx):
        """Update the action state"""
        if ida_dbg.is_debugger_on():
            # Show checkmark if injected
            if self.injector.is_injected:
                return ida_kernwin.AST_ENABLE_FOR_IDB | ida_kernwin.AST_CHECKED
            return ida_kernwin.AST_ENABLE_FOR_IDB
        return ida_kernwin.AST_DISABLE_FOR_IDB


class ScyllaHideTogglePlugin(ida_idaapi.plugin_t):
    """Main plugin class"""
    
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Toggle ScyllaHide injection"
    help = "Adds a button to enable/disable ScyllaHide anti-anti-debug protection"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    
    action_name = "scyllahide:toggle"
    menu_path = "Debugger/ScyllaHide/Toggle Injection"
    
    def init(self):
        """Initialize the plugin"""
        log("=== Plugin init() called ===")
        
        # Register the action
        action_desc = ida_kernwin.action_desc_t(
            self.action_name,
            "Toggle ScyllaHide Injection",
            ScyllaHideAction(),
            PLUGIN_HOTKEY,
            "Toggle ScyllaHide anti-anti-debug protection",
            199  # Icon ID (debug icon)
        )
        
        log(f"Registering action: {self.action_name}")
        if not ida_kernwin.register_action(action_desc):
            log("FAILED to register action")
            return ida_idaapi.PLUGIN_SKIP
        
        log("Action registered successfully")
        
        # Attach to menu
        log(f"Attaching to menu: {self.menu_path}")
        if not ida_kernwin.attach_action_to_menu(
            self.menu_path,
            self.action_name,
            ida_kernwin.SETMENU_APP
        ):
            log("Failed to attach to menu (this is OK if menu doesn't exist)")
        else:
            log("Attached to menu successfully")
        
        # Add toolbar button
        log("Attaching to toolbar: DebugToolBar")
        if not ida_kernwin.attach_action_to_toolbar(
            "DebugToolBar",
            self.action_name
        ):
            log("Failed to attach to toolbar (this is OK if toolbar doesn't exist)")
        else:
            log("Attached to toolbar successfully")
        
        log(f"Plugin initialized successfully!")
        log(f"Hotkey: {PLUGIN_HOTKEY}")
        log(f"Use Ctrl+Shift+H to toggle ScyllaHide injection")
        log(f"Tip: Manually rename DLL files in Scyllahide/32 and Scyllahide/64 folders to avoid detection")
        
        return ida_idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        """Run the plugin - trigger the action"""
        log("Plugin run() called - triggering action")
        log(f"Action name: {self.action_name}")
        
        # Try to get and execute the action directly
        action_handler = ScyllaHideAction()
        result = action_handler.activate(None)
        log(f"Action result: {result}")
    
    def term(self):
        """Cleanup on plugin unload"""
        log("Plugin terminating...")
        ida_kernwin.detach_action_from_menu(self.menu_path, self.action_name)
        ida_kernwin.detach_action_from_toolbar("DebugToolBar", self.action_name)
        ida_kernwin.unregister_action(self.action_name)
        log("Plugin terminated")


def PLUGIN_ENTRY():
    """Entry point for IDA Pro"""
    log("=== PLUGIN_ENTRY() called ===")
    return ScyllaHideTogglePlugin()