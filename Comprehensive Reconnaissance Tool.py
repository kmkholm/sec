#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Reconnaissance Tool
Created by Dr. Mohammed Tawfik (kmkhol01@gmail.com)

A unified tool for various reconnaissance tasks including:
- Network scanning with Nmap
- Shodan intelligence gathering
- Domain/DNS information lookup
- Email scraping from websites
- Username search across platforms
- Wayback Machine exploration
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu, font
import subprocess
import threading
import queue
import os
import re
import json
import time
import traceback
from urllib.parse import urlparse
from datetime import datetime

# --- Third-party libraries ---
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# --- Constants ---
VERSION = "2.0.0"
AUTHOR = "Dr. Mohammed Tawfik"
EMAIL = "kmkhol01@gmail.com"
DEFAULT_SHODAN_API_KEY = ""  # Leave empty by default for security
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# Color theme
COLORS = {
    "primary": "#2c3e50",       # Dark blue-gray
    "secondary": "#3498db",     # Blue
    "accent": "#e74c3c",        # Red
    "background": "#ecf0f1",    # Light gray
    "text": "#2c3e50",          # Dark blue-gray
    "success": "#2ecc71",       # Green
    "warning": "#f39c12",       # Orange
    "tabs_bg": "#34495e",       # Darker blue-gray
    "output_bg": "#f8f9fa",     # Nearly white
    "button_hover": "#2980b9",  # Darker blue
    "disabled": "#bdc3c7"       # Light gray for disabled elements
}

# Username check sites
USERNAME_CHECK_SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Facebook": "https://www.facebook.com/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Medium": "https://medium.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Behance": "https://www.behance.net/{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "GitLab": "https://gitlab.com/{}",
    "Wordpress": "https://{}.wordpress.com",
    "Blogger": "https://{}.blogspot.com",
    "Quora": "https://www.quora.com/profile/{}",
    "Snapchat": "https://www.snapchat.com/add/{}"
}

# --- Helper Functions ---
def check_dependencies():
    """Check if required libraries are installed and return status messages."""
    messages = []
    if not SHODAN_AVAILABLE:
        messages.append("Shodan library not found. Install with: pip install shodan")
    if not REQUESTS_AVAILABLE:
        messages.append("Requests library not found. Install with: pip install requests")
    if not BS4_AVAILABLE:
        messages.append("BeautifulSoup library not found. Install with: pip install beautifulsoup4")
    if not WHOIS_AVAILABLE:
        messages.append("Whois library not found. Install with: pip install python-whois")
    if not DNS_AVAILABLE:
        messages.append("DNS resolver library not found. Install with: pip install dnspython")
    return messages

def safe_json_serialize(obj):
    """Handle non-serializable objects for JSON."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    return str(obj)

# --- Main Application Class ---
class ReconTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Comprehensive Reconnaissance Tool")
        self.geometry("950x700")
        self.configure(bg=COLORS["background"])
        
        # Variables
        self.shodan_api_key = tk.StringVar(value=DEFAULT_SHODAN_API_KEY)
        self.show_key = tk.IntVar(value=0)
        
        # Queue for thread-safe GUI updates
        self.output_queue = queue.Queue()
        
        # Initialize components
        self.create_custom_style()
        self.create_menu()
        self.create_main_frame()
        self.check_dependencies()
        
        # Start queue processing
        self.after(100, self.process_queue)
        
        # Initialize services
        self.shodan_api = None
        if SHODAN_AVAILABLE:
            self.initialize_shodan()
    
    def check_dependencies(self):
        """Check and notify about missing dependencies."""
        messages = check_dependencies()
        if messages:
            msg = "Some dependencies are missing:\n\n" + "\n".join(messages)
            messagebox.showwarning("Dependencies Warning", msg)
    
    def create_custom_style(self):
        """Create custom styles for the application."""
        style = ttk.Style(self)
        style.theme_use("clam")
        
        # Configure common elements
        style.configure("TFrame", background=COLORS["background"])
        style.configure("TLabel", background=COLORS["background"], foreground=COLORS["text"])
        style.configure("TLabelframe", background=COLORS["background"], foreground=COLORS["text"])
        style.configure("TLabelframe.Label", background=COLORS["background"], foreground=COLORS["text"])
        
        # Configure buttons
        style.configure("TButton", 
                      background=COLORS["secondary"], 
                      foreground="white",
                      padding=5)
        style.map("TButton",
                background=[("active", COLORS["button_hover"]), ("disabled", COLORS["disabled"])],
                foreground=[("disabled", "#999999")])
        
        # Run button style (green)
        style.configure("Run.TButton", 
                      background=COLORS["success"], 
                      foreground="white")
        style.map("Run.TButton",
                background=[("active", "#27ae60"), ("disabled", COLORS["disabled"])])
        
        # Save button style (blue)
        style.configure("Save.TButton", 
                      background=COLORS["secondary"], 
                      foreground="white")
        style.map("Save.TButton",
                background=[("active", COLORS["button_hover"]), ("disabled", COLORS["disabled"])])
        
        # Configure Notebook
        style.configure("TNotebook", background=COLORS["tabs_bg"], borderwidth=0)
        style.configure("TNotebook.Tab", 
                      background=COLORS["tabs_bg"], 
                      foreground="white",
                      padding=[10, 3],
                      font=('Helvetica', 9, 'bold'))
        style.map("TNotebook.Tab",
                background=[("selected", COLORS["secondary"]), 
                            ("active", "#4e5f70")],
                foreground=[("selected", "white"), 
                            ("active", "white")])
        
        # Configure Entry widgets
        style.configure("TEntry", 
                      fieldbackground="white", 
                      bordercolor=COLORS["secondary"],
                      lightcolor=COLORS["secondary"],
                      darkcolor=COLORS["secondary"])
        
        # Status bar style
        style.configure("TLabel", padding=3)
    
    def create_menu(self):
        """Create the application menu bar."""
        menubar = Menu(self)
        self.config(menu=menubar)
        
        # Author info in menu with better formatting
        label = f"\u2022\u2022\u2022 {AUTHOR}  {EMAIL} \u2022\u2022\u2022"
        menubar.add_command(label=label, 
                          font=("Helvetica", 10, "bold"),
                          foreground=COLORS["secondary"])
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save All Results", command=self.save_all_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        
        # Tools Menu
        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Nmap Scanner", command=lambda: self.notebook.select(0))
        tools_menu.add_command(label="Shodan Search", command=lambda: self.notebook.select(1))
        tools_menu.add_command(label="Web Recon", command=lambda: self.notebook.select(2))
        tools_menu.add_separator()
        tools_menu.add_command(label="Configure API Keys", command=self.show_api_config)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Shodan Usage Guide", command=self.show_shodan_guide)
    
    def create_main_frame(self):
        """Create the main application frame and notebook."""
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill="both")
        
        # Create notebook with tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill="both", pady=5)
        
        # Create tabs
        self.tabs = {}
        self.tabs["nmap"] = NmapTab(self.notebook, self)
        self.tabs["shodan"] = ShodanTab(self.notebook, self)
        self.tabs["web_recon"] = WebReconTab(self.notebook, self)
        
        # Add tabs to notebook
        self.notebook.add(self.tabs["nmap"], text="Nmap Scanner")
        self.notebook.add(self.tabs["shodan"], text="Shodan Search")
        self.notebook.add(self.tabs["web_recon"], text="Web Recon")
        
        # Status bar
        self.status_bar = ttk.Label(main_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def process_queue(self):
        """Process messages from the output queue to update GUI."""
        try:
            while True:  # Process all messages currently in queue
                message_type, target_widget, text = self.output_queue.get_nowait()
                if message_type == "status":
                    self.update_status(text)
                elif message_type == "output":
                    target_widget.configure(state='normal')
                    target_widget.insert(tk.END, text)
                    target_widget.see(tk.END)
                    target_widget.configure(state='disabled')
                elif message_type == "clear":
                    target_widget.configure(state='normal')
                    target_widget.delete('1.0', tk.END)
                    target_widget.configure(state='disabled')
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_queue)  # Check again after 100ms
    
    def update_status(self, message):
        """Update the status bar with a message."""
        self.status_bar.config(text=message)
    
    def initialize_shodan(self, api_key=None):
        """Initialize the Shodan API client."""
        if not SHODAN_AVAILABLE:
            self.update_status("Shodan library not available. Install with: pip install shodan")
            return False
            
        try:
            key_to_use = api_key if api_key else self.shodan_api_key.get()
            if not key_to_use:
                self.update_status("Shodan API key not set")
                return False
                
            self.shodan_api = shodan.Shodan(key_to_use)
            api_info = self.shodan_api.info()
            self.update_status(f"Shodan API Key Validated. Scan Credits: {api_info.get('scan_credits', 'N/A')}")
            return True
        except Exception as e:
            self.shodan_api = None
            self.update_status(f"Shodan API Error: {e}")
            return False
    
    def save_all_results(self):
        """Save results from all tabs to a single file."""
        filepath = filedialog.asksaveasfilename(
            initialfile="all_recon_results.txt",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save All Results"
        )
        if not filepath:
            return
            
        try:
            with open(filepath, "w", encoding='utf-8') as f:
                # Header
                f.write("=== COMPREHENSIVE RECONNAISSANCE TOOL RESULTS ===\n")
                f.write(f"Report generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Get results from Nmap
                nmap_results = self.tabs["nmap"].get_results()
                if nmap_results:
                    f.write("=== NMAP SCAN RESULTS ===\n")
                    f.write(nmap_results + "\n\n")
                
                # Get results from Shodan
                shodan_results = self.tabs["shodan"].get_results()
                if shodan_results:
                    f.write("=== SHODAN SEARCH RESULTS ===\n")
                    f.write(shodan_results + "\n\n")
                
                # Get results from Web Recon tabs
                for name, results in self.tabs["web_recon"].get_all_results().items():
                    if results:
                        f.write(f"=== {name.upper()} RESULTS ===\n")
                        f.write(results + "\n\n")
            
            self.update_status(f"All results saved to {filepath}")
            messagebox.showinfo("Save Successful", f"All reconnaissance results saved to {filepath}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save results: {e}")
            self.update_status("Error saving results.")
    
    def show_api_config(self):
        """Show a dialog to configure API keys."""
        config_window = tk.Toplevel(self)
        config_window.title("API Configuration")
        config_window.geometry("500x300")
        config_window.resizable(False, False)
        config_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        config_window.transient(self)
        config_window.grab_set()
        
        # Add some padding
        frame = ttk.Frame(config_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Shodan API Key
        ttk.Label(frame, text="Shodan API Key:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=0, padx=5, pady=10, sticky="w")
        shodan_key_entry = ttk.Entry(frame, width=40, textvariable=self.shodan_api_key)
        shodan_key_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        
        ttk.Label(frame, text="Get a free API key at: https://account.shodan.io/register", 
                font=("Helvetica", 8)).grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(
            button_frame, 
            text="Test Shodan API Key", 
            command=lambda: self.test_shodan_key(self.shodan_api_key.get(), config_window)
        ).pack(side="left", padx=5)
        
        ttk.Button(
            button_frame, 
            text="Save & Close", 
            command=lambda: self.save_api_config(config_window)
        ).pack(side="right", padx=5)
        
        # Center the window
        config_window.update_idletasks()
        width = config_window.winfo_width()
        height = config_window.winfo_height()
        x = (config_window.winfo_screenwidth() // 2) - (width // 2)
        y = (config_window.winfo_screenheight() // 2) - (height // 2)
        config_window.geometry(f'{width}x{height}+{x}+{y}')
    
    def test_shodan_key(self, api_key, parent_window):
        """Test if the Shodan API key is valid."""
        if not SHODAN_AVAILABLE:
            messagebox.showerror("Error", "Shodan library not installed", parent=parent_window)
            return
            
        if not api_key.strip():
            messagebox.showerror("Error", "Please enter an API key", parent=parent_window)
            return
            
        try:
            # Show a waiting cursor
            parent_window.config(cursor="wait")
            parent_window.update()
            
            # Test the API key
            test_api = shodan.Shodan(api_key)
            info = test_api.info()
            
            # Reset cursor
            parent_window.config(cursor="")
            
            # Show success message
            messagebox.showinfo(
                "Success", 
                f"API key is valid!\nQuery Credits: {info.get('query_credits', 'N/A')}\n"
                f"Scan Credits: {info.get('scan_credits', 'N/A')}", 
                parent=parent_window
            )
        except Exception as e:
            # Reset cursor
            parent_window.config(cursor="")
            messagebox.showerror("Error", f"Failed to validate API key: {e}", parent=parent_window)
    
    def save_api_config(self, window):
        """Save API configuration and close the window."""
        # Update the API client with the new key
        self.initialize_shodan(self.shodan_api_key.get())
        self.update_status("API configuration updated")
        window.destroy()
    
    def show_about(self):
        """Display the About dialog with author information."""
        about_window = tk.Toplevel(self)
        about_window.title("About Reconnaissance Tool")
        about_window.geometry("400x300")
        about_window.resizable(False, False)
        about_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        about_window.transient(self)
        about_window.grab_set()
        
        # Add some padding
        frame = ttk.Frame(about_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Tool name in large font
        title_font = font.Font(family="Helvetica", size=16, weight="bold")
        ttk.Label(frame, text="Comprehensive Reconnaissance Tool", font=title_font).pack(pady=(0, 10))
        
        # Version
        ttk.Label(frame, text=f"Version {VERSION}").pack(pady=(0, 20))
        
        # Author info
        ttk.Label(frame, text="Designed by:").pack(anchor="w")
        author_font = font.Font(family="Helvetica", size=12, weight="bold")
        ttk.Label(frame, text=AUTHOR, font=author_font).pack(anchor="w")
        ttk.Label(frame, text=f"Email: {EMAIL}").pack(anchor="w")
        
        # Dotted separator
        ttk.Label(frame, text="........................................").pack(pady=5)
        ttk.Label(frame, text="........................................").pack(pady=0)
        
        # Description
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=15)
        description = "A comprehensive tool for network reconnaissance, \nfeaturing Nmap scanning, Shodan intelligence, \nand various web reconnaissance capabilities."
        ttk.Label(frame, text=description, justify="center").pack(pady=(0, 15))
        
        # Close button
        ttk.Button(frame, text="Close", command=about_window.destroy).pack()
    
    def show_shodan_guide(self):
        """Show a window with Shodan usage guidelines."""
        guide_window = tk.Toplevel(self)
        guide_window.title("Shodan Usage Guide")
        guide_window.geometry("700x500")
        guide_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        guide_window.transient(self)
        guide_window.grab_set()
        
        # Add some padding
        frame = ttk.Frame(guide_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Title
        title_font = font.Font(family="Helvetica", size=14, weight="bold")
        ttk.Label(frame, text="Shodan Usage Guide", font=title_font).pack(pady=(0, 10))
        
        # Content
        content_text = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, height=20, 
            background="white", foreground=COLORS["text"]
        )
        content_text.pack(expand=True, fill="both", pady=10)
        
        guide_content = """
Effective and Ethical Use of Shodan:

1. Understanding Shodan Syntax:
   - Shodan search syntax differs from typical search engines
   - Basic search: "apache" finds Apache web servers
   - Filter by port: "apache port:80"
   - Filter by country: "apache country:US"
   - Filter by organization: "org:Microsoft"
   - Filter by operating system: "os:Windows"
   - Combine filters: "apache port:80 country:US"

2. Common Search Examples:
   - webcam: Find webcams
   - port:22 openssh: Find SSH servers
   - apache port:443: Find Apache HTTPS servers
   - "default password": Find devices with default credentials
   - org:"Company Name": Find devices belonging to an organization
   - hostname:.gov: Find government servers
   - has_screenshot:true: Find devices with screenshots available

3. Ethical Considerations:
   - Always respect privacy and legal boundaries
   - Only scan your own infrastructure or with explicit permission
   - Avoid accessing exposed systems without authorization
   - Report vulnerabilities responsibly
   - Use for legitimate security research and defense

4. Best Practices:
   - Start with broad queries and narrow down
   - Use filters to refine results
   - Save important searches for future reference
   - Monitor your own infrastructure regularly
   - Update your searches as new vulnerabilities emerge

Remember: Shodan is a powerful tool that should be used responsibly and ethically.
"""
        
        content_text.insert(tk.END, guide_content)
        content_text.configure(state='disabled')
        
        # Close button
        ttk.Button(frame, text="Close", command=guide_window.destroy).pack(pady=10)

# --- Base Tab Class ---
class BaseTab(ttk.Frame):
    def __init__(self, notebook, parent):
        super().__init__(notebook, padding="10")
        self.parent = parent
        self.queue = parent.output_queue
        self.output_text = None
        
    def update_status(self, message):
        """Update the status bar."""
        self.parent.update_status(message)
        
    def save_results(self, tool_name=None):
        """Base method for saving results."""
        if not self.output_text:
            messagebox.showwarning("Warning", "No output to save.")
            return
            
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "There is no content to save.")
            return
        
        tool_name = tool_name or self.__class__.__name__.replace("Tab", "")
        suggested_filename = f"{tool_name}_results.txt"
        
        filepath = filedialog.asksaveasfilename(
            initialfile=suggested_filename,
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("JSON Files", "*.json"), ("All Files", "*.*")],
            title=f"Save {tool_name} Results"
        )
        
        if filepath:
            try:
                with open(filepath, "w", encoding='utf-8') as f:
                    f.write(content)
                self.update_status(f"Results saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save results: {e}")
                self.update_status("Error saving results.")
                
    def get_results(self):
        """Get the current results text."""
        if self.output_text:
            return self.output_text.get("1.0", tk.END).strip()
        return ""

# --- Nmap Tab Class ---
class NmapTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Create widgets
        self.create_input_frame()
        self.create_action_frame()
        self.create_output_frame()
        
    def create_input_frame(self):
        """Create the input frame for Nmap configuration."""
        input_frame = ttk.LabelFrame(self, text="Scan Configuration", padding="10")
        input_frame.pack(fill="x", pady=5)
        
        # Target Input
        ttk.Label(input_frame, text="Target (IP/Hostname):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ttk.Entry(input_frame, width=40)
        self.target_entry.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky="ew")
        
        # Scan Type Options
        ttk.Label(input_frame, text="Scan Type:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.scan_type = tk.StringVar(value="-sS")  # Default to SYN scan
        
        scan_options = [
            ("SYN Scan (-sS)", "-sS"), 
            ("TCP Connect Scan (-sT)", "-sT"),
            ("UDP Scan (-sU)", "-sU"), 
            ("Version Detection (-sV)", "-sV"),
            ("OS Detection (-O)", "-O"), 
            ("Aggressive Scan (-A)", "-A"),
            ("Ping Scan (-sn)", "-sn")
        ]
        
        col_count = 0
        for text, mode in scan_options:
            rb = ttk.Radiobutton(input_frame, text=text, variable=self.scan_type, value=mode)
            rb.grid(row=1 + (col_count // 3), column=1 + (col_count % 3), padx=5, pady=2, sticky="w")
            col_count += 1
        
        # Custom Nmap Flags
        ttk.Label(input_frame, text="Custom Flags:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.custom_flags_entry = ttk.Entry(input_frame, width=40)
        self.custom_flags_entry.grid(row=3, column=1, columnspan=3, padx=5, pady=5, sticky="ew")
        
        input_frame.columnconfigure(1, weight=1)
        
    def create_action_frame(self):
        """Create the action frame for Nmap controls."""
        action_frame = ttk.Frame(self, padding="5")
        action_frame.pack(fill="x")
        
        self.run_button = ttk.Button(
            action_frame, text="Run Nmap Scan", style="Run.TButton", command=self.start_scan
        )
        self.run_button.pack(side="left", padx=5)
        
        self.save_button = ttk.Button(
            action_frame, text="Save Results", style="Save.TButton", command=lambda: self.save_results("Nmap")
        )
        self.save_button.pack(side="right", padx=5)
        
    def create_output_frame(self):
        """Create the output frame for Nmap results."""
        output_frame = ttk.LabelFrame(self, text="Nmap Output", padding="10")
        output_frame.pack(expand=True, fill="both", pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, state='disabled', height=15,
            background=COLORS["output_bg"], foreground=COLORS["text"]
        )
        self.output_text.pack(expand=True, fill="both")
        
    def start_scan(self):
        """Start the Nmap scan."""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP address or hostname.")
            return
        
        scan_type = self.scan_type.get()
        custom_flags = self.custom_flags_entry.get().strip().split()
        
        # Basic command validation/sanitization
        safe_target = target.replace(";", "").replace("&", "").replace("|", "")
        safe_flags = [flag for flag in custom_flags if not any(c in flag for c in ";&|")]
        
        command = ["nmap", scan_type] + safe_flags + [safe_target]
        
        # Clear output and update status
        self.queue.put(("clear", self.output_text, None))
        self.queue.put(("status", None, f"Running Nmap scan on {safe_target}..."))
        self.run_button.config(state=tk.DISABLED)
        
        # Run in a separate thread
        thread = threading.Thread(
            target=self.run_command_thread,
            args=(command, self.output_text, self.run_button),
            daemon=True
        )
        thread.start()
        
    def run_command_thread(self, command, output_widget, button_to_enable):
        """Run a shell command in a separate thread."""
        try:
            self.queue.put(("output", output_widget, f"Running command: {' '.join(command)}\n---\n"))
            
            # Use Popen for better control
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1, 
                universal_newlines=True, 
                encoding='utf-8', 
                errors='replace'
            )
            
            # Read output line by line
            for line in iter(process.stdout.readline, ''):
                self.queue.put(("output", output_widget, line))
            
            process.stdout.close()
            return_code = process.wait()
            
            self.queue.put(("output", output_widget, f"\n---\nCommand finished with exit code: {return_code}\n"))
            self.queue.put(("status", None, "Scan finished."))
            
        except FileNotFoundError:
            self.queue.put((
                "output", 
                output_widget, 
                f"Error: Command '{command[0]}' not found. Make sure it's installed and in your PATH.\n"
            ))
            self.queue.put(("status", None, "Error: Command not found."))
        except Exception as e:
            self.queue.put((
                "output", 
                output_widget, 
                f"An error occurred: {e}\n{traceback.format_exc()}\n"
            ))
            self.queue.put(("status", None, "Error during scan."))
        finally:
            # Re-enable button on the main thread
            if button_to_enable:
                self.parent.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

# --- Shodan Tab Class ---
class ShodanTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Init
        self.shodan_query_type = tk.StringVar(value="host")
        
        # Create widgets
        self.create_api_frame()
        self.create_input_frame()
        self.create_action_frame()
        self.create_output_frame()
        
    def create_api_frame(self):
        """Create the API key input frame."""
        api_frame = ttk.Frame(self, padding="10")
        api_frame.pack(fill="x", pady=5)
        
        ttk.Label(api_frame, text="Shodan API Key:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        # Use the parent's API key variable
        api_key_entry = ttk.Entry(
            api_frame, width=40, textvariable=self.parent.shodan_api_key, show="*"
        )
        api_key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Show/Hide password toggle
        show_key_check = ttk.Checkbutton(
            api_frame, text="Show API Key", 
            variable=self.parent.show_key, 
            command=lambda: api_key_entry.config(show="" if self.parent.show_key.get() else "*")
        )
        show_key_check.grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Button(
            api_frame, text="Test Key", 
            command=lambda: self.parent.test_shodan_key(self.parent.shodan_api_key.get(), self.parent)
        ).grid(row=0, column=3, padx=5, pady=5)
        
        api_frame.columnconfigure(1, weight=1)
        
    def create_input_frame(self):
        """Create the input frame for Shodan queries."""
        input_frame = ttk.LabelFrame(self, text="Shodan Query", padding="10")
        input_frame.pack(fill="x", pady=5)
        
        # Query Input
        ttk.Label(input_frame, text="Query:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.query_entry = ttk.Entry(input_frame, width=50)
        self.query_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        
        # Quick search options
        ttk.Label(input_frame, text="Quick Search:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        # Create a frame for the quick search buttons
        quick_search_frame = ttk.Frame(input_frame)
        quick_search_frame.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        
        # Define quick search queries
        quick_searches = [
            ("Webcams", "webcam has_screenshot:true"),
            ("IoT Devices", "port:23,2323,8080 has_screenshot:true"),
            ("Default Passwords", "default password"),
            ("Industrial Controls", "tag:ics"),
            ("Routers", "router -401"),
            ("Databases", "product:MySQL port:3306")
        ]
        
        # Create a button for each quick search
        col = 0
        for label, query in quick_searches:
            btn = ttk.Button(
                quick_search_frame, text=label, 
                command=lambda q=query: self.set_quick_search(q)
            )
            btn.grid(row=0, column=col, padx=3, pady=2)
            col += 1
        
        # Query Type
        ttk.Label(input_frame, text="Query Type:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        
        host_rb = ttk.Radiobutton(
            input_frame, text="Host Lookup", variable=self.shodan_query_type, value="host"
        )
        search_rb = ttk.Radiobutton(
            input_frame, text="General Search", variable=self.shodan_query_type, value="search"
        )
        
        host_rb.grid(row=2, column=1, padx=5, pady=2, sticky="w")
        search_rb.grid(row=2, column=2, padx=5, pady=2, sticky="w")
        
        input_frame.columnconfigure(1, weight=1)
        
    def create_action_frame(self):
        """Create the action frame for Shodan controls."""
        action_frame = ttk.Frame(self, padding="5")
        action_frame.pack(fill="x")
        
        self.run_button = ttk.Button(
            action_frame, text="Run Shodan Query", style="Run.TButton", command=self.start_query
        )
        self.run_button.pack(side="left", padx=5)
        
        self.save_button = ttk.Button(
            action_frame, text="Save Results", style="Save.TButton", command=lambda: self.save_results("Shodan")
        )
        self.save_button.pack(side="right", padx=5)
        
        # Add a help button
        self.help_button = ttk.Button(
            action_frame, text="Shodan Help", command=self.parent.show_shodan_guide
        )
        self.help_button.pack(side="right", padx=5)
        
    def create_output_frame(self):
        """Create the output frame for Shodan results."""
        output_frame = ttk.LabelFrame(self, text="Shodan Output", padding="10")
        output_frame.pack(expand=True, fill="both", pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, state='disabled', height=15,
            background=COLORS["output_bg"], foreground=COLORS["text"]
        )
        self.output_text.pack(expand=True, fill="both")
        
    def set_quick_search(self, query):
        """Set a predefined search query."""
        self.query_entry.delete(0, tk.END)
        self.query_entry.insert(0, query)
        
        # If it's not an IP address, switch to search mode
        if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', query):
            self.shodan_query_type.set("search")
            
    def start_query(self):
        """Start a Shodan query."""
        if not SHODAN_AVAILABLE:
            messagebox.showerror("Error", "Shodan library not installed. Please install with: pip install shodan")
            return
            
        # Get the current API key
        api_key = self.parent.shodan_api_key.get().strip()
        if not api_key:
            messagebox.showerror("Error", "Please enter a valid Shodan API key.")
            return
        
        # Initialize API if needed
        if not self.parent.shodan_api:
            if not self.parent.initialize_shodan(api_key):
                messagebox.showerror("Error", "Failed to initialize Shodan API. Please check your API key.")
                return
        
        query = self.query_entry.get().strip()
        query_type = self.shodan_query_type.get()
        
        if not query:
            messagebox.showerror("Error", "Please enter a Shodan query.")
            return
        
        # Validate input for host lookup
        if query_type == "host" and not (re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', query) or '.' in query):
            if not messagebox.askyesno(
                "Warning", 
                "Your input doesn't look like an IP address or domain name. Are you sure you want to do a host lookup?"
            ):
                return
        
        # Update status and clear output
        self.queue.put(("clear", self.output_text, None))
        self.queue.put(("status", None, f"Running Shodan {query_type} query for '{query}'..."))
        self.queue.put(("output", self.output_text, f"Preparing to run {query_type} query for: {query}\n"))
        self.run_button.config(state=tk.DISABLED)
        
        # Run in a separate thread
        thread = threading.Thread(
            target=self.run_query_thread,
            args=(query, query_type, self.output_text, self.run_button),
            daemon=True
        )
        thread.start()
        
    def run_query_thread(self, query, query_type, output_widget, button_to_enable):
        """Run Shodan query in a thread."""
        try:
            # Print status
            self.queue.put(("output", output_widget, f"Performing Shodan {query_type} for: {query}\n---\n"))
            
            # Ensure API is available
            if not self.parent.shodan_api:
                self.queue.put(("output", output_widget, "Error: Shodan API not initialized\n"))
                return
            
            # Execute query
            results = None
            if query_type == "host":
                self.queue.put(("output", output_widget, "Searching for host information...\n"))
                results = self.parent.shodan_api.host(query)
            elif query_type == "search":
                self.queue.put(("output", output_widget, "Executing search query...\n"))
                results = self.parent.shodan_api.search(query)
            
            # Process results
            if results:
                self.queue.put(("output", output_widget, "Query successful! Formatting results...\n\n"))
                
                # Format and display results
                formatted_results = json.dumps(
                    results, indent=4, sort_keys=True, default=safe_json_serialize
                )
                self.queue.put(("output", output_widget, formatted_results + "\n"))
                
                # Display summary
                if query_type == "host":
                    # Host summary
                    if 'ip_str' in results:
                        self.queue.put(("output", output_widget, f"\n--- Summary for {results.get('ip_str')} ---\n"))
                        if 'hostnames' in results and results['hostnames']:
                            self.queue.put(("output", output_widget, f"Hostnames: {', '.join(results['hostnames'])}\n"))
                        if 'ports' in results:
                            self.queue.put(("output", output_widget, f"Open Ports: {', '.join(map(str, results['ports']))}\n"))
                        if 'org' in results:
                            self.queue.put(("output", output_widget, f"Organization: {results['org']}\n"))
                elif query_type == "search":
                    # Search summary
                    if 'matches' in results:
                        match_count = len(results['matches'])
                        self.queue.put(("output", output_widget, f"\n--- Found {match_count} matches ---\n"))
                        for i, match in enumerate(results['matches'][:5]):  # Show first 5
                            ip = match.get('ip_str', 'Unknown IP')
                            hostnames = match.get('hostnames', [])
                            hostname_str = hostnames[0] if hostnames else 'No hostname'
                            self.queue.put(("output", output_widget, f"{i+1}. {ip} ({hostname_str})\n"))
                        if match_count > 5:
                            self.queue.put(("output", output_widget, f"...and {match_count - 5} more results\n"))
                
                self.queue.put(("status", None, f"Shodan {query_type} query finished successfully."))
            else:
                self.queue.put(("output", output_widget, "No results found.\n"))
                self.queue.put(("status", None, f"Shodan {query_type} query finished - No results."))
                
        except Exception as e:
            self.queue.put(("output", output_widget, f"Shodan API Error: {e}\n"))
            
            # More helpful error messages
            if "Invalid API key" in str(e):
                self.queue.put(("output", output_widget, "Your API key appears to be invalid. Please check it and try again.\n"))
            elif "No information available" in str(e):
                self.queue.put(("output", output_widget, "No information is available for the specified IP or host.\n"))
            elif "Rate limit reached" in str(e):
                self.queue.put(("output", output_widget, "You've reached your Shodan API rate limit. Please wait and try again later.\n"))
                
            self.queue.put(("status", None, "Error during Shodan query."))
        finally:
            # Re-enable button
            if button_to_enable:
                self.parent.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

# --- Web Recon Tab Class ---
class WebReconTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Create sub-notebook for web recon tools
        self.web_notebook = ttk.Notebook(self)
        self.web_notebook.pack(expand=True, fill="both", pady=5)
        
        # Create tabs for each web recon tool
        self.sub_tabs = {}
        self.sub_tabs["domain"] = DomainTab(self.web_notebook, parent)
        self.sub_tabs["email"] = EmailTab(self.web_notebook, parent)
        self.sub_tabs["username"] = UsernameTab(self.web_notebook, parent)
        self.sub_tabs["wayback"] = WaybackTab(self.web_notebook, parent)
        
        # Add tabs to notebook
        self.web_notebook.add(self.sub_tabs["domain"], text="Domain/DNS Info")
        self.web_notebook.add(self.sub_tabs["email"], text="Email Scraper")
        self.web_notebook.add(self.sub_tabs["username"], text="Username Search")
        self.web_notebook.add(self.sub_tabs["wayback"], text="Wayback Machine")
        
    def get_all_results(self):
        """Get results from all sub-tabs."""
        results = {}
        for name, tab in self.sub_tabs.items():
            results[name] = tab.get_results()
        return results

# --- Domain Tab Class ---
class DomainTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Create widgets
        self.create_input_frame()
        self.create_action_frame()
        self.create_output_frame()
        
    def create_input_frame(self):
        """Create the input frame for domain info."""
        input_frame = ttk.LabelFrame(self, text="Domain Input", padding="10")
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="Domain Name:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.domain_entry = ttk.Entry(input_frame, width=40)
        self.domain_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        input_frame.columnconfigure(1, weight=1)
        
    def create_action_frame(self):
        """Create the action frame for domain controls."""
        action_frame = ttk.Frame(self, padding="5")
        action_frame.pack(fill="x")
        
        self.whois_button = ttk.Button(
            action_frame, text="Get WHOIS", style="Run.TButton", command=self.start_whois
        )
        self.whois_button.pack(side="left", padx=5)
        
        self.dns_button = ttk.Button(
            action_frame, text="Get DNS Records", style="Run.TButton", command=self.start_dns
        )
        self.dns_button.pack(side="left", padx=5)
        
        self.save_button = ttk.Button(
            action_frame, text="Save Results", style="Save.TButton", command=lambda: self.save_results("DomainInfo")
        )
        self.save_button.pack(side="right", padx=5)
        
    def create_output_frame(self):
        """Create the output frame for domain results."""
        output_frame = ttk.LabelFrame(self, text="Domain/DNS Output", padding="10")
        output_frame.pack(expand=True, fill="both", pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, state='disabled', height=15,
            background=COLORS["output_bg"], foreground=COLORS["text"]
        )
        self.output_text.pack(expand=True, fill="both")
        
    def start_whois(self):
        """Start a WHOIS lookup."""
        if not WHOIS_AVAILABLE:
            messagebox.showerror("Error", "WHOIS library not installed. Please install with: pip install python-whois")
            return
            
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name.")
            return
        
        # Clear output and update status
        self.queue.put(("clear", self.output_text, None))
        self.queue.put(("status", None, f"Performing WHOIS lookup for {domain}..."))
        
        # Disable buttons
        self.whois_button.config(state=tk.DISABLED)
        self.dns_button.config(state=tk.DISABLED)
        
        # Run in a thread
        thread = threading.Thread(
            target=self.run_whois_thread,
            args=(domain, self.output_text, [self.whois_button, self.dns_button]),
            daemon=True
        )
        thread.start()
        
    def start_dns(self):
        """Start a DNS lookup."""
        if not DNS_AVAILABLE:
            messagebox.showerror("Error", "DNS library not installed. Please install with: pip install dnspython")
            return
            
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name.")
            return
        
        # Clear output and update status
        self.queue.put(("clear", self.output_text, None))
        self.queue.put(("status", None, f"Performing DNS lookup for {domain}..."))
        
        # Disable buttons
        self.whois_button.config(state=tk.DISABLED)
        self.dns_button.config(state=tk.DISABLED)
        
        # Run in a thread
        thread = threading.Thread(
            target=self.run_dns_thread,
            args=(domain, self.output_text, [self.whois_button, self.dns_button]),
            daemon=True
        )
        thread.start()
        
    def run_whois_thread(self, domain, output_widget, buttons_to_enable):
        """Run WHOIS lookup in a thread."""
        try:
            self.queue.put(("output", output_widget, f"--- WHOIS Lookup for {domain} ---\n"))
            
            # First ensure domain format is correct
            if domain.startswith(("http://", "https://")):
                parsed = urlparse(domain)
                domain = parsed.netloc
                self.queue.put(("output", output_widget, f"Note: Extracted domain {domain} from URL\n"))
            
            # Try multiple methods
            try:
                self.queue.put(("output", output_widget, "Attempting WHOIS lookup...\n"))
                w = whois.whois(domain)
            except Exception as e:
                self.queue.put(("output", output_widget, f"Standard WHOIS lookup failed: {e}\n"))
                self.queue.put(("output", output_widget, "Trying alternative method...\n"))
                
                # Try using subprocess call as fallback
                try:
                    process = subprocess.Popen(
                        ["whois", domain], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE, 
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=15)
                    
                    if stderr:
                        self.queue.put(("output", output_widget, f"WHOIS Error: {stderr}\n"))
                    
                    if stdout:
                        self.queue.put(("output", output_widget, stdout + "\n"))
                        self.queue.put(("status", None, "WHOIS lookup finished (using system whois)."))
                        return
                except Exception as e:
                    self.queue.put(("output", output_widget, f"Alternative method also failed: {e}\n"))
                    
                    # Try online WHOIS service as last resort
                    if REQUESTS_AVAILABLE:
                        self.queue.put(("output", output_widget, "Trying to use online WHOIS service...\n"))
                        try:
                            response = requests.get(
                                f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
                                f"?domainName={domain}&outputFormat=JSON", 
                                timeout=10
                            )
                            if response.status_code == 200:
                                data = response.json()
                                if 'WhoisRecord' in data:
                                    record = data['WhoisRecord']
                                    self.queue.put((
                                        "output", output_widget, 
                                        f"Domain: {record.get('domainName', 'N/A')}\n"
                                    ))
                                    if 'registryData' in record:
                                        reg = record['registryData']
                                        self.queue.put((
                                            "output", output_widget, 
                                            f"Registrar: {reg.get('registrarName', 'N/A')}\n"
                                        ))
                                        self.queue.put((
                                            "output", output_widget, 
                                            f"Created: {reg.get('createdDate', 'N/A')}\n"
                                        ))
                                        self.queue.put((
                                            "output", output_widget, 
                                            f"Expires: {reg.get('expiresDate', 'N/A')}\n"
                                        ))
                                    self.queue.put(("status", None, "WHOIS lookup finished (using online service)."))
                                    return
                        except Exception as e:
                            self.queue.put(("output", output_widget, f"Online WHOIS service failed: {e}\n"))
                    
                    self.queue.put((
                        "output", output_widget, 
                        "All WHOIS lookup methods failed. Please check the domain and try again.\n"
                    ))
                    self.queue.put(("status", None, "WHOIS lookup failed."))
                    return
            
            # Process standard WHOIS results
            whois_text = ""
            if isinstance(w, dict):
                for key, value in w.items():
                    if isinstance(value, list):
                        whois_text += f"{key}:\n"
                        for item in value:
                            whois_text += f"  - {str(item)}\n"
                    else:
                        whois_text += f"{key}: {str(value)}\n"
            elif w and hasattr(w, 'text') and w.text:
                whois_text = w.text  # Use raw text if available
            else:
                whois_text = str(w)
            
            self.queue.put(("output", output_widget, whois_text + "\n"))
            self.queue.put(("status", None, "WHOIS lookup finished."))
            
        except Exception as e:
            self.queue.put((
                "output", output_widget, 
                f"An unexpected error occurred during WHOIS lookup: {e}\n{traceback.format_exc()}\n"
            ))
            self.queue.put(("status", None, "Error during WHOIS lookup."))
        finally:
            # Re-enable buttons
            if buttons_to_enable:
                self.parent.after(0, lambda: [btn.config(state=tk.NORMAL) for btn in buttons_to_enable])
                
    def run_dns_thread(self, domain, output_widget, buttons_to_enable):
        """Run DNS lookup in a thread."""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        try:
            self.queue.put(("output", output_widget, f"--- DNS Lookup for {domain} ---\n"))
            
            # Format domain if needed
            if domain.startswith(("http://", "https://")):
                parsed = urlparse(domain)
                domain = parsed.netloc
                self.queue.put(("output", output_widget, f"Note: Extracted domain {domain} from URL\n"))
            
            # Create resolver
            resolver = dns.resolver.Resolver()
            
            # Option to use specific nameservers
            # resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            # Query each record type
            nxdomain_reported = False
            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    self.queue.put(("output", output_widget, f"\n[{rtype} Records]\n"))
                    for rdata in answers:
                        self.queue.put(("output", output_widget, f"  {rdata.to_text()}\n"))
                except dns.resolver.NoAnswer:
                    self.queue.put(("output", output_widget, f"\n[{rtype} Records]\n  No {rtype} records found.\n"))
                except dns.resolver.NXDOMAIN:
                    if not nxdomain_reported:
                        self.queue.put(("output", output_widget, f"\nError: Domain {domain} not found (NXDOMAIN).\n"))
                        nxdomain_reported = True
                        break  # Stop checking other records
                except dns.exception.Timeout:
                    self.queue.put(("output", output_widget, f"\n[{rtype} Records]\n  Query timed out.\n"))
                except Exception as e:
                    self.queue.put(("output", output_widget, f"\n[{rtype} Records]\n  Error querying {rtype}: {e}\n"))
            
            self.queue.put(("status", None, "DNS lookup finished."))
            
        except Exception as e:
            self.queue.put((
                "output", output_widget, 
                f"An unexpected error occurred during DNS lookup: {e}\n{traceback.format_exc()}\n"
            ))
            self.queue.put(("status", None, "Error during DNS lookup."))
        finally:
            # Re-enable buttons
            if buttons_to_enable:
                self.parent.after(0, lambda: [btn.config(state=tk.NORMAL) for btn in buttons_to_enable])

# --- Email Tab Class ---
class EmailTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Create widgets
        self.create_input_frame()
        self.create_action_frame()
        self.create_output_frame()
        
    def create_input_frame(self):
        """Create the input frame for email scraper."""
        input_frame = ttk.LabelFrame(self, text="Target URL", padding="10")
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="URL:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_entry = ttk.Entry(input_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        input_frame.columnconfigure(1, weight=1)
        
    def create_action_frame(self):
        """Create the action frame for email scraper controls."""
        action_frame = ttk.Frame(self, padding="5")
        action_frame.pack(fill="x")
        
        self.scrape_button = ttk.Button(
            action_frame, text="Scrape Emails", style="Run.TButton", command=self.start_scrape
        )
        self.scrape_button.pack(side="left", padx=5)
        
        self.save_button = ttk.Button(
            action_frame, text="Save Results", style="Save.TButton", command=lambda: self.save_results("EmailScrape")
        )
        self.save_button.pack(side="right", padx=5)
        
    def create_output_frame(self):
        """Create the output frame for email results."""
        output_frame = ttk.LabelFrame(self, text="Found Emails", padding="10")
        output_frame.pack(expand=True, fill="both", pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, state='disabled', height=15,
            background=COLORS["output_bg"], foreground=COLORS["text"]
        )
        self.output_text.pack(expand=True, fill="both")
        
    def start_scrape(self):
        """Start email scraping."""
        if not REQUESTS_AVAILABLE:
            messagebox.showerror("Error", "Requests library not installed. Please install with: pip install requests")
            return
            
        if not BS4_AVAILABLE:
            messagebox.showerror("Error", "BeautifulSoup library not installed. Please install with: pip install beautifulsoup4")
            return
            
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to scrape.")
            return
        
        # Basic URL validation
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "http://" + url
            parsed_url = urlparse(url)
            
        if not parsed_url.netloc:
            messagebox.showerror("Error", "Invalid URL format.")
            return
        
        # Clear output and update status
        self.queue.put(("clear", self.output_text, None))
        self.queue.put(("status", None, f"Scraping emails from {url}..."))
        self.scrape_button.config(state=tk.DISABLED)
        
        # Run in a thread
        thread = threading.Thread(
            target=self.run_scrape_thread,
            args=(url, self.output_text, self.scrape_button),
            daemon=True
        )
        thread.start()
        
    def run_scrape_thread(self, url, output_widget, button_to_enable):
        """Run email scraping in a thread."""
        try:
            self.queue.put(("output", output_widget, f"--- Email Scraping for {url} ---\n"))
            
            # Setup headers
            headers = {"User-Agent": USER_AGENT}
            
            # Fetch the page
            self.queue.put(("output", output_widget, "Fetching web page...\n"))
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            response.raise_for_status()
            
            # Check content type
            content_type = response.headers.get("content-type", "").lower()
            
            # Find emails
            emails = set()
            
            if "text/html" not in content_type:
                self.queue.put((
                    "output", output_widget, 
                    f"Warning: Content type is '{content_type}', not HTML. Scraping page text only.\n"
                ))
                # Process as text
                text_content = response.text
                emails = set(re.findall(EMAIL_REGEX, text_content))
            else:
                # Process as HTML
                self.queue.put(("output", output_widget, "Parsing HTML content...\n"))
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Find emails in text
                text_content = soup.get_text()
                emails.update(re.findall(EMAIL_REGEX, text_content))
                
                # Find emails in mailto links
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    if href.startswith("mailto:"):
                        email = href[7:].split("?")[0]  # Remove "mailto:" and any parameters
                        if re.match(EMAIL_REGEX, email):
                            emails.add(email)
            
            # Display results
            if emails:
                self.queue.put(("output", output_widget, f"\nFound {len(emails)} unique email(s):\n"))
                for email in sorted(list(emails)):
                    self.queue.put(("output", output_widget, f"  - {email}\n"))
            else:
                self.queue.put(("output", output_widget, "\nNo emails found on this page.\n"))
                
                # Suggestion
                self.queue.put((
                    "output", output_widget, 
                    "Tip: Try checking the Contact or About pages for email addresses.\n"
                ))
            
            self.queue.put(("status", None, "Email scraping finished."))
            
        except requests.exceptions.Timeout:
            self.queue.put((
                "output", output_widget, 
                f"HTTP Request Error: Timeout while trying to connect to {url}\n"
            ))
            self.queue.put(("output", output_widget, "The request took too long to complete. Try again later.\n"))
            self.queue.put(("status", None, "Error: Request timed out."))
        except requests.exceptions.RequestException as e:
            self.queue.put(("output", output_widget, f"HTTP Request Error: {e}\n"))
            self.queue.put(("status", None, "Error during email scraping."))
        except Exception as e:
            self.queue.put((
                "output", output_widget, 
                f"An unexpected error occurred during email scraping: {e}\n{traceback.format_exc()}\n"
            ))
            self.queue.put(("status", None, "Error during email scraping."))
        finally:
            # Re-enable button
            if button_to_enable:
                self.parent.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

# --- Username Tab Class ---
class UsernameTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Create widgets
        self.create_input_frame()
        self.create_action_frame()
        self.create_output_frame()
        
    def create_input_frame(self):
        """Create the input frame for username search."""
        input_frame = ttk.LabelFrame(self, text="Username Input", padding="10")
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = ttk.Entry(input_frame, width=40)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Site selection
        ttk.Label(input_frame, text="Sites to check:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        # Create a frame for site selection
        sites_frame = ttk.Frame(input_frame)
        sites_frame.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # All sites option
        self.check_all = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            sites_frame, text="Check All Sites", 
            variable=self.check_all,
            command=self.toggle_all_sites
        ).grid(row=0, column=0, padx=5, pady=2, sticky="w")
        
        input_frame.columnconfigure(1, weight=1)
        
    def create_action_frame(self):
        """Create the action frame for username search controls."""
        action_frame = ttk.Frame(self, padding="5")
        action_frame.pack(fill="x")
        
        self.search_button = ttk.Button(
            action_frame, text="Search Username", style="Run.TButton", command=self.start_search
        )
        self.search_button.pack(side="left", padx=5)
        
        self.save_button = ttk.Button(
            action_frame, text="Save Results", style="Save.TButton", command=lambda: self.save_results("UsernameSearch")
        )
        self.save_button.pack(side="right", padx=5)
        
    def create_output_frame(self):
        """Create the output frame for username search results."""
        output_frame = ttk.LabelFrame(self, text="Username Search Results", padding="10")
        output_frame.pack(expand=True, fill="both", pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, state='disabled', height=15,
            background=COLORS["output_bg"], foreground=COLORS["text"]
        )
        self.output_text.pack(expand=True, fill="both")
        
    def toggle_all_sites(self):
        """Toggle all site selections."""
        # This would toggle individual site checkboxes if implemented
        pass
        
    def start_search(self):
        """Start username search."""
        if not REQUESTS_AVAILABLE:
            messagebox.showerror("Error", "Requests library not installed. Please install with: pip install requests")
            return
            
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username to search.")
            return
        
        # Basic username validation
        if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
            if not messagebox.askyesno(
                "Warning", 
                "Username contains potentially invalid characters. Results may vary. Continue anyway?"
            ):
                return
        
        # Clear output and update status
        self.queue.put(("clear", self.output_text, None))
        self.queue.put(("status", None, f"Searching for username '{username}'..."))
        self.search_button.config(state=tk.DISABLED)
        
        # Run in a thread
        thread = threading.Thread(
            target=self.run_search_thread,
            args=(username, self.output_text, self.search_button),
            daemon=True
        )
        thread.start()
        
    def run_search_thread(self, username, output_widget, button_to_enable):
        """Run username search in a thread."""
        try:
            self.queue.put(("output", output_widget, f"--- Username Search for: {username} ---\n"))
            self.queue.put(("output", output_widget, f"Searching across {len(USERNAME_CHECK_SITES)} platforms...\n\n"))
            
            # Setup headers
            headers = {"User-Agent": USER_AGENT}
            
            # Track found sites
            found_count = 0
            found_sites = []
            error_sites = []
            
            # Check each site
            for site, url_format in USERNAME_CHECK_SITES.items():
                try:
                    formatted_url = url_format.format(username)
                    self.queue.put(("output", output_widget, f"Checking {site}... "))
                    
                    response = requests.get(
                        formatted_url, 
                        headers=headers, 
                        timeout=10, 
                        allow_redirects=True
                    )
                    
                    # Check response
                    if response.status_code == 200:
                        self.queue.put(("output", output_widget, f"Found! ✓\n"))
                        found_count += 1
                        found_sites.append((site, formatted_url))
                    elif response.status_code == 404:
                        self.queue.put(("output", output_widget, f"Not found\n"))
                    else:
                        self.queue.put((
                            "output", output_widget, 
                            f"Uncertain (Status: {response.status_code})\n"
                        ))
                    
                    # Small delay to avoid rate limiting
                    time.sleep(0.5)
                    
                except requests.exceptions.Timeout:
                    self.queue.put(("output", output_widget, f"Timeout!\n"))
                    error_sites.append(site)
                except requests.exceptions.RequestException as e:
                    self.queue.put(("output", output_widget, f"Error: {e}\n"))
                    error_sites.append(site)
            
            # Summary
            self.queue.put(("output", output_widget, f"\n--- Search complete. Found on {found_count} site(s). ---\n"))
            
            if found_sites:
                self.queue.put(("output", output_widget, "\nDetailed Results:\n"))
                for i, (site, url) in enumerate(found_sites, 1):
                    self.queue.put(("output", output_widget, f"{i}. {site}: {url}\n"))
            
            if error_sites:
                self.queue.put((
                    "output", output_widget, 
                    f"\nNote: Encountered errors with {len(error_sites)} sites. Try again later.\n"
                ))
            
            self.queue.put(("status", None, "Username search finished."))
            
        except Exception as e:
            self.queue.put((
                "output", output_widget, 
                f"An unexpected error occurred during username search: {e}\n{traceback.format_exc()}\n"
            ))
            self.queue.put(("status", None, "Error during username search."))
        finally:
            # Re-enable button
            if button_to_enable:
                self.parent.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

# --- Wayback Tab Class ---
class WaybackTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Create widgets
        self.create_input_frame()
        self.create_action_frame()
        self.create_output_frame()
        
    def create_input_frame(self):
        """Create the input frame for Wayback Machine."""
        input_frame = ttk.LabelFrame(self, text="Target URL", padding="10")
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="URL:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_entry = ttk.Entry(input_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        input_frame.columnconfigure(1, weight=1)
        
    def create_action_frame(self):
        """Create the action frame for Wayback Machine controls."""
        action_frame = ttk.Frame(self, padding="5")
        action_frame.pack(fill="x")
        
        self.query_button = ttk.Button(
            action_frame, text="Check Wayback Machine", style="Run.TButton", command=self.start_query
        )
        self.query_button.pack(side="left", padx=5)
        
        self.save_button = ttk.Button(
            action_frame, text="Save Results", style="Save.TButton", command=lambda: self.save_results("WaybackCheck")
        )
        self.save_button.pack(side="right", padx=5)
        
    def create_output_frame(self):
        """Create the output frame for Wayback Machine results."""
        output_frame = ttk.LabelFrame(self, text="Wayback Machine Results", padding="10")
        output_frame.pack(expand=True, fill="both", pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, state='disabled', height=15,
            background=COLORS["output_bg"], foreground=COLORS["text"]
        )
        self.output_text.pack(expand=True, fill="both")
        
    def start_query(self):
        """Start Wayback Machine query."""
        if not REQUESTS_AVAILABLE:
            messagebox.showerror("Error", "Requests library not installed. Please install with: pip install requests")
            return
            
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to check.")
            return
        
        # Basic URL validation
        parsed_url = urlparse(url)
        if not parsed_url.scheme and not parsed_url.netloc:
            # Try to determine if it's a domain or path
            if '.' in url and '/' not in url:
                # Looks like a domain
                url = "http://" + url
            else:
                messagebox.showerror("Error", "Invalid URL format.")
                return
        
        # Clear output and update status
        self.queue.put(("clear", self.output_text, None))
        self.queue.put(("status", None, f"Checking Wayback Machine for {url}..."))
        self.query_button.config(state=tk.DISABLED)
        
        # Run in a thread
        thread = threading.Thread(
            target=self.run_query_thread,
            args=(url, self.output_text, self.query_button),
            daemon=True
        )
        thread.start()
        
    def run_query_thread(self, url, output_widget, button_to_enable):
        """Run Wayback Machine query in a thread."""
        try:
            self.queue.put(("output", output_widget, f"--- Wayback Machine Check for: {url} ---\n"))
            
            # First, properly format the URL if needed
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                self.queue.put(("output", output_widget, f"Note: URL reformatted to {url}\n"))
            
            # Query the Wayback Machine API
            api_url = f"https://archive.org/wayback/available?url={url}"
            headers = {"User-Agent": USER_AGENT}
            
            self.queue.put(("output", output_widget, "Contacting Wayback Machine API...\n"))
            
            response = requests.get(api_url, headers=headers, timeout=15)
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                raise Exception("Could not parse response from Wayback Machine API. Invalid JSON.")
            
            archived_snapshots = data.get("archived_snapshots")
            
            if archived_snapshots and archived_snapshots.get("closest"):
                closest = archived_snapshots["closest"]
                snapshot_url = closest.get("url")
                timestamp = closest.get("timestamp")
                status = closest.get("status")
                
                # Format timestamp for better readability if possible
                formatted_date = ""
                if timestamp and len(timestamp) >= 14:
                    try:
                        year = timestamp[0:4]
                        month = timestamp[4:6]
                        day = timestamp[6:8]
                        hour = timestamp[8:10]
                        minute = timestamp[10:12]
                        second = timestamp[12:14]
                        formatted_date = f" ({year}-{month}-{day} {hour}:{minute}:{second})"
                    except:
                        formatted_date = ""
                
                self.queue.put(("output", output_widget, "✓ Snapshot found!\n"))
                self.queue.put(("output", output_widget, f"  Closest Snapshot URL: {snapshot_url}\n"))
                self.queue.put(("output", output_widget, f"  Timestamp: {timestamp}{formatted_date}\n"))
                self.queue.put(("output", output_widget, f"  Status Code: {status}\n"))
                
                # Link to browse history
                browse_url = f"https://web.archive.org/web/*/{url}"
                self.queue.put(("output", output_widget, f"\nBrowse full history: {browse_url}\n"))
                
                # Get more detailed information using the CDX API
                try:
                    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&limit=10"
                    cdx_response = requests.get(cdx_url, headers=headers, timeout=15)
                    
                    if cdx_response.status_code == 200:
                        try:
                            cdx_data = cdx_response.json()
                            
                            if len(cdx_data) > 1:  # First row is header
                                self.queue.put(("output", output_widget, f"\nRecent snapshots (up to 10):\n"))
                                
                                # Headers are in the first row
                                headers = cdx_data[0]
                                timestamp_idx = headers.index("timestamp") if "timestamp" in headers else 1
                                status_idx = headers.index("statuscode") if "statuscode" in headers else 2
                                
                                for i, snapshot in enumerate(cdx_data[1:], 1):  # Skip header row
                                    timestamp = snapshot[timestamp_idx]
                                    status = snapshot[status_idx]
                                    
                                    # Format timestamp
                                    if len(timestamp) >= 14:
                                        year = timestamp[0:4]
                                        month = timestamp[4:6]
                                        day = timestamp[6:8]
                                        formatted_date = f"{year}-{month}-{day}"
                                    else:
                                        formatted_date = timestamp
                                        
                                    self.queue.put((
                                        "output", output_widget, 
                                        f"  {i}. {formatted_date} (Status: {status})\n"
                                    ))
                        except:
                            # Not critical, just skip detailed info
                            pass
                except:
                    # Not critical, continue without detailed info
                    pass
                    
            else:
                self.queue.put(("output", output_widget, "No snapshots found in the Wayback Machine for this URL.\n"))
                self.queue.put((
                    "output", output_widget, 
                    "This may mean the site has never been archived or has been excluded from archiving.\n"
                ))
                
                # Suggest to check with wildcards or domain only
                parsed_url = urlparse(url)
                if parsed_url.path and parsed_url.path != '/':
                    domain_only = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    self.queue.put((
                        "output", output_widget, 
                        f"\nTip: Try checking the domain only: {domain_only}\n"
                    ))
            
            self.queue.put(("status", None, "Wayback Machine check finished."))
            
        except requests.exceptions.Timeout:
            self.queue.put((
                "output", output_widget, 
                "HTTP Request Error: Timeout while contacting Wayback Machine API\n"
            ))
            self.queue.put((
                "output", output_widget, 
                "The request took too long to complete. This may be due to network issues or high server load.\n"
            ))
            self.queue.put(("status", None, "Error: Wayback API timeout."))
        except requests.exceptions.RequestException as e:
            self.queue.put(("output", output_widget, f"Wayback Machine API Error: {e}\n"))
            self.queue.put((
                "output", output_widget, 
                "Failed to connect to the Wayback Machine API. Please check your internet connection and try again.\n"
            ))
            self.queue.put(("status", None, "Error during Wayback check."))
        except Exception as e:
            self.queue.put((
                "output", output_widget, 
                f"An unexpected error occurred during Wayback check: {e}\n{traceback.format_exc()}\n"
            ))
            self.queue.put(("status", None, "Error during Wayback check."))
        finally:
            # Re-enable button
            if button_to_enable:
                self.parent.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

# --- Main Entry Point ---
def main():
    """Main entry point for the application."""
    # Check if running in a headless environment
    display_available = True
    if "DISPLAY" not in os.environ and os.name != 'nt':  # Skip display check on Windows
        print("No display environment detected. Attempting to start Xvfb...")
        try:
            # Check if Xvfb is already running on :99
            lock_file = "/tmp/.X99-lock"
            if not os.path.exists(lock_file):
                # Start Xvfb in the background with more parameters
                print("Starting Xvfb with extended parameters...")
                xvfb_process = subprocess.Popen(
                    ["Xvfb", ":99", "-screen", "0", "1024x768x24", "-ac", 
                     "+extension", "GLX", "+render", "-noreset"],
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                )
                # Give Xvfb more time to start
                time.sleep(3)
                
                # Check if it started successfully
                if xvfb_process.poll() is not None:
                    exit_code = xvfb_process.poll()
                    print(f"Xvfb failed to start. Exit code: {exit_code}")
                    # Try debugging by running with output
                    print("Attempting to get Xvfb error output:")
                    debug_output = subprocess.run(
                        ["Xvfb", ":99", "-screen", "0", "1024x768x24"], 
                        capture_output=True, 
                        text=True
                    )
                    print(f"Xvfb debug stdout: {debug_output.stdout}")
                    print(f"Xvfb debug stderr: {debug_output.stderr}")
                    
                    # Try alternative display number
                    print("Trying alternative display number :1...")
                    xvfb_process = subprocess.Popen(
                        ["Xvfb", ":1", "-screen", "0", "1024x768x24"],
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL
                    )
                    time.sleep(3)
                    if xvfb_process.poll() is None:
                        print("Started Xvfb on display :1")
                        os.environ["DISPLAY"] = ":1"
                    else:
                        raise RuntimeError(f"All Xvfb attempts failed. Last exit code: {xvfb_process.poll()}")
                else:
                    print("Started virtual display (Xvfb) on :99")
                    os.environ["DISPLAY"] = ":99"
            else:
                print("Xvfb lock file found, assuming display :99 is available.")
                os.environ["DISPLAY"] = ":99"
                
        except FileNotFoundError:
            print("Xvfb not found. Cannot start virtual display. GUI requires a display.")
            print("On Ubuntu/Debian, install with: sudo apt-get install xvfb")
            print("On CentOS/RHEL, install with: sudo yum install xorg-x11-server-Xvfb")
            display_available = False
        except Exception as e:
            print(f"Failed to start or detect Xvfb: {e}")
            print("If running in Docker, make sure to install Xvfb and related packages.")
            display_available = False

    if display_available:
        try:
            app = ReconTool()
            app.mainloop()
        except tk.TclError as e:
            print(f"Tkinter Error: {e}")
            print("Could not initialize the Tkinter GUI. Ensure a display server is available.")
            # Attempt to diagnose common TclError
            if "no display name" in str(e):
                 print("\nCommon causes and solutions:")
                 print("1. SSH connection without X forwarding: Use 'ssh -X user@host'")
                 print("2. Container/headless environment: Make sure Xvfb is installed and DISPLAY is set")
                 print("3. Missing X11 libraries: Install required packages:")
                 print("   - Ubuntu/Debian: sudo apt-get install xorg libx11-dev libxext-dev")
                 print("   - CentOS/RHEL: sudo yum install xorg-x11-xauth xorg-x11-apps")
                 print("4. Try manually setting: export DISPLAY=:0 (or :1, :99)")
            exit(1)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            print(traceback.format_exc())
            exit(1)
    else:
        print("\nExiting because no display is available.")
        print("Options to solve this issue:")
        print("1. Run on a system with a desktop environment")
        print("2. Install and configure Xvfb for headless systems")
        print("3. Use X11 forwarding if connecting via SSH")
        exit(1)

if __name__ == "__main__":
    main()