# -*- coding: utf-8 -*-
"""
Created on Sun May  4 00:36:41 2025

@author: kmkho
"""

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
- Claude AI integration for enhanced analysis
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
import socket
from datetime import datetime

# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# --- Constants ---
VERSION = "2.0.0"
AUTHOR = "Dr. Mohammed Tawfik"
EMAIL = "kmkhol01@gmail.com"
DEFAULT_SHODAN_API_KEY = "pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM"  # User provided API key
DEFAULT_CLAUDE_API_KEY = "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"  # Default Claude API key
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"

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
    "disabled": "#bdc3c7",      # Light gray for disabled elements
    "ai_highlight": "#9b59b6"   # Purple for AI-related elements
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

# Claude AI prompt templates
CLAUDE_PROMPTS = {
    "analyze_nmap": """You are a cybersecurity expert analyzing Nmap scan results. 
Provide a detailed analysis including:
1. Open ports and services discovered
2. Potential security vulnerabilities
3. Recommended security measures
4. Explanation of interesting findings

Here are the Nmap scan results:
{}
""",

    "analyze_shodan": """You are a cybersecurity expert analyzing Shodan intelligence data.
Provide a detailed analysis including:
1. Key findings and exposed services
2. Security implications
3. Potential vulnerabilities
4. Recommendations for security improvements

Here are the Shodan results:
{}
""",

    "analyze_domain": """You are a cybersecurity expert analyzing domain and DNS information.
Provide a detailed analysis including:
1. Key domain ownership information
2. DNS configuration analysis
3. Security implications
4. Recommendations for domain security

Here is the domain information:
{}
""",

    "analyze_emails": """You are a cybersecurity expert analyzing email addresses found during reconnaissance.
Provide a detailed analysis including:
1. Email patterns and naming conventions
2. Assessment of information exposure
3. Potential risks of these exposed emails
4. Recommendations for email security

Here are the email addresses found:
{}
""",

    "analyze_username": """You are a cybersecurity expert analyzing username presence across platforms.
Provide a detailed analysis including:
1. Assessment of online presence
2. OSINT implications
3. Digital footprint evaluation
4. Privacy recommendations

Here are the username search results:
{}
""",

    "analyze_wayback": """You are a cybersecurity expert analyzing Wayback Machine data for a website.
Provide a detailed analysis including:
1. Historical website analysis
2. Changes over time
3. Potential information exposure through archives
4. Security implications of archived content

Here are the Wayback Machine results:
{}
""",

    "generate_report": """You are a cybersecurity expert creating a comprehensive reconnaissance report.
Create a professional security report including:
1. Executive summary
2. Key findings from all reconnaissance methods
3. Vulnerabilities identified
4. Risk assessment
5. Detailed recommendations

Here are all the reconnaissance results:
{}
""",

    "generate_code": """You are a cybersecurity expert creating Python code to further analyze the reconnaissance data.
Create well-documented, functional Python code that:
1. Parses and analyzes the data provided
2. Identifies patterns and potential security issues
3. Generates visualizations or structured output
4. Follows best practices for security tools

The code should address the following requirements:
{}

Here's the data to analyze:
{}
"""
}

# --- Main Application Class ---
class ReconTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Comprehensive Reconnaissance Tool")
        self.geometry("950x700")
        self.configure(bg=COLORS["background"])
        
        # Variables
        self.shodan_api_key = tk.StringVar(value=DEFAULT_SHODAN_API_KEY)
        self.claude_api_key = tk.StringVar(value=DEFAULT_CLAUDE_API_KEY)
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
        messages = []
        if not SHODAN_AVAILABLE:
            messages.append("Shodan library not found. Install with: pip install shodan")
        if not REQUESTS_AVAILABLE:
            messages.append("Requests library not found. Install with: pip install requests")
        if not BS4_AVAILABLE:
            messages.append("BeautifulSoup library not found. Install with: pip install beautifulsoup4")
        if not DNS_AVAILABLE:
            messages.append("DNS resolver library not found. Install with: pip install dnspython")
            
        # Emphasize the importance of the requests library for Claude AI
        if not REQUESTS_AVAILABLE:
            messages.append("Requests library is REQUIRED for Claude AI integration.")
            
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
        
        # AI button style (purple)
        style.configure("AI.TButton", 
                      background=COLORS["ai_highlight"], 
                      foreground="white")
        style.map("AI.TButton",
                background=[("active", "#8e44ad"), ("disabled", COLORS["disabled"])])
        
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
        file_menu.add_command(label="Generate Comprehensive Report", command=self.generate_comprehensive_report)
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
        
        # AI Menu
        ai_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Claude AI", menu=ai_menu)
        ai_menu.add_command(label="Generate Comprehensive Report", command=self.generate_comprehensive_report)
        ai_menu.add_command(label="Custom AI Analysis", command=self.show_custom_ai_prompt)
        ai_menu.add_command(label="Generate Analysis Code", command=self.generate_analysis_code)
        ai_menu.add_separator()
        ai_menu.add_command(label="Configure Claude AI", command=self.show_claude_config)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Shodan Usage Guide", command=self.show_shodan_guide)
        help_menu.add_command(label="Claude AI Guide", command=self.show_claude_guide)
    
    def create_main_frame(self):
        """Create the main application frame and notebook."""
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill="both")
        
        # Create notebook with tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill="both", pady=5)
        
        # Create tabs
        self.nmap_tab = NmapTab(self.notebook, self)
        self.shodan_tab = ShodanTab(self.notebook, self)
        self.web_recon_tab = WebReconTab(self.notebook, self)
        
        # Add tabs to notebook
        self.notebook.add(self.nmap_tab, text="Nmap Scanner")
        self.notebook.add(self.shodan_tab, text="Shodan Search")
        self.notebook.add(self.web_recon_tab, text="Web Recon")
        
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
    
    def initialize_shodan(self):
        """Initialize the Shodan API client."""
        if not SHODAN_AVAILABLE:
            self.update_status("Shodan library not available. Install with: pip install shodan")
            return False
            
        try:
            self.shodan_api = shodan.Shodan(self.shodan_api_key.get())
            api_info = self.shodan_api.info()
            self.update_status(f"Shodan API Key Validated. Scan Credits: {api_info.get('scan_credits', 'N/A')}")
            return True
        except Exception as e:
            self.shodan_api = None
            self.update_status(f"Shodan API Error: {e}")
            return False
    
    def test_claude_api(self, api_key, parent_window=None):
        """Test if the Claude API key is valid."""
        if not REQUESTS_AVAILABLE:
            msg = "Requests library not installed. Please install with: pip install requests"
            if parent_window:
                messagebox.showerror("Error", msg, parent=parent_window)
            else:
                messagebox.showerror("Error", msg)
            return False
            
        if not api_key.strip():
            msg = "Please enter a valid Claude API key."
            if parent_window:
                messagebox.showerror("Error", msg, parent=parent_window)
            else:
                messagebox.showerror("Error", msg)
            return False
            
        # Show a waiting cursor
        if parent_window:
            parent_window.config(cursor="wait")
            parent_window.update()
        else:
            self.config(cursor="wait")
            self.update()
        
        try:
            headers = {
                "x-api-key": api_key,
                "content-type": "application/json",
                "anthropic-version": "2023-06-01"
            }
            
            data = {
                "model": "claude-3-haiku-20240307",
                "max_tokens": 100,
                "system": "You are a helpful cybersecurity assistant.",
                "messages": [
                    {"role": "user", "content": "Say hello and confirm you can help with cybersecurity tasks."}
                ]
            }
            
            response = requests.post(
                CLAUDE_API_URL,
                headers=headers, 
                json=data,
                timeout=15
            )
            
            # Reset cursor
            if parent_window:
                parent_window.config(cursor="")
            else:
                self.config(cursor="")
            
            if response.status_code == 200:
                msg = "Claude API key is valid! Connection successful."
                if parent_window:
                    messagebox.showinfo("Success", msg, parent=parent_window)
                else:
                    messagebox.showinfo("Success", msg)
                return True
            else:
                error_message = response.json().get("error", {}).get("message", "Unknown error")
                msg = f"Failed to validate API key. Status code: {response.status_code}\nError: {error_message}"
                if parent_window:
                    messagebox.showerror("Error", msg, parent=parent_window)
                else:
                    messagebox.showerror("Error", msg)
                return False
                
        except Exception as e:
            # Reset cursor
            if parent_window:
                parent_window.config(cursor="")
            else:
                self.config(cursor="")
                
            msg = f"Failed to validate API key: {str(e)}"
            if parent_window:
                messagebox.showerror("Error", msg, parent=parent_window)
            else:
                messagebox.showerror("Error", msg)
            return False
    
    def call_claude_ai(self, prompt, output_widget=None, max_tokens=2000):
        """Call Claude AI API with the given prompt."""
        if not REQUESTS_AVAILABLE:
            if output_widget:
                self.output_queue.put(("output", output_widget, "Error: Requests library not installed. Please install with: pip install requests\n"))
            else:
                messagebox.showerror("Error", "Requests library not installed. Please install with: pip install requests")
            return None
            
        api_key = self.claude_api_key.get().strip()
        if not api_key:
            if output_widget:
                self.output_queue.put(("output", output_widget, "Error: No Claude API key set. Please configure it in Settings > Configure API Keys.\n"))
            else:
                messagebox.showerror("Error", "No Claude API key set. Please configure it in Settings > Configure API Keys.")
            return None
            
        try:
            if output_widget:
                self.output_queue.put(("output", output_widget, "Sending request to Claude AI...\n"))
                
            headers = {
                "x-api-key": api_key,
                "content-type": "application/json",
                "anthropic-version": "2023-06-01"
            }
            
            data = {
                "model": "claude-3-haiku-20240307",
                "max_tokens": max_tokens,
                "system": "You are a helpful cybersecurity assistant specializing in reconnaissance analysis. Provide detailed, actionable insights.",
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            }
            
            response = requests.post(
                CLAUDE_API_URL,
                headers=headers, 
                json=data,
                timeout=60
            )
            
            if response.status_code == 200:
                response_data = response.json()
                assistant_message = response_data.get("content", [{}])[0].get("text", "")
                
                if output_widget:
                    self.output_queue.put(("output", output_widget, "\n--- Claude AI Analysis ---\n\n"))
                    self.output_queue.put(("output", output_widget, assistant_message + "\n"))
                    self.output_queue.put(("status", None, "Claude AI analysis completed."))
                
                return assistant_message
            else:
                error_message = response.json().get("error", {}).get("message", "Unknown error")
                if output_widget:
                    self.output_queue.put(("output", output_widget, f"\nAPI Error (Status {response.status_code}): {error_message}\n"))
                    self.output_queue.put(("status", None, f"Claude API error: {response.status_code}"))
                else:
                    messagebox.showerror("API Error", f"Status {response.status_code}: {error_message}")
                return None
                
        except Exception as e:
            if output_widget:
                self.output_queue.put(("output", output_widget, f"\nAn error occurred while calling Claude AI: {str(e)}\n"))
                self.output_queue.put(("status", None, "Error during Claude AI analysis."))
            else:
                messagebox.showerror("Error", f"An error occurred while calling Claude AI: {str(e)}")
            return None
    
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
                nmap_results = self.nmap_tab.get_results()
                if nmap_results:
                    f.write("=== NMAP SCAN RESULTS ===\n")
                    f.write(nmap_results + "\n\n")
                
                # Get results from Shodan
                shodan_results = self.shodan_tab.get_results()
                if shodan_results:
                    f.write("=== SHODAN SEARCH RESULTS ===\n")
                    f.write(shodan_results + "\n\n")
                
                # Get results from Web Recon tabs
                for name, results in self.web_recon_tab.get_all_results().items():
                    if results:
                        f.write(f"=== {name.upper()} RESULTS ===\n")
                        f.write(results + "\n\n")
            
            self.update_status(f"All results saved to {filepath}")
            messagebox.showinfo("Save Successful", f"All reconnaissance results saved to {filepath}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save results: {e}")
            self.update_status("Error saving results.")
    
    def generate_comprehensive_report(self):
        """Generate a comprehensive report with Claude AI."""
        # Create a dialog for report options
        report_window = tk.Toplevel(self)
        report_window.title("Generate Comprehensive Report")
        report_window.geometry("600x500")
        report_window.resizable(False, False)
        report_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        report_window.transient(self)
        report_window.grab_set()
        
        # Add padding
        frame = ttk.Frame(report_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Title
        title_font = font.Font(family="Helvetica", size=14, weight="bold")
        ttk.Label(frame, text="Generate Comprehensive Security Report", font=title_font).pack(pady=(0, 10))
        
        # Instructions
        ttk.Label(frame, text="This will analyze all reconnaissance data and generate a detailed security report.", 
                wraplength=550).pack(pady=(0, 10))
        
        # Options
        options_frame = ttk.LabelFrame(frame, text="Report Options", padding="10")
        options_frame.pack(fill="x", pady=10)
        
        # Report format
        ttk.Label(options_frame, text="Report Format:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        format_var = tk.StringVar(value="Detailed")
        format_options = ["Executive Summary", "Detailed", "Technical"]
        format_dropdown = ttk.Combobox(options_frame, textvariable=format_var, values=format_options, state="readonly")
        format_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Include recommendations
        include_recommendations = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Include Security Recommendations", variable=include_recommendations).grid(
            row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        
        # Include code snippets
        include_code = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Include Analysis Code Snippets", variable=include_code).grid(
            row=2, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        
        # Output area
        ttk.Label(frame, text="Report Output:").pack(anchor="w", pady=(10, 5))
        
        output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=12, 
                                            background="white", foreground=COLORS["text"])
        output_text.pack(expand=True, fill="both", pady=5)
        output_text.configure(state='disabled')
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=10)
        
        generate_button = ttk.Button(
            button_frame, text="Generate Report", style="AI.TButton",
            command=lambda: self.run_report_generation(
                output_text, 
                format_var.get(),
                include_recommendations.get(),
                include_code.get(),
                save_button
            )
        )
        generate_button.pack(side="left", padx=5)
        
        save_button = ttk.Button(
            button_frame, text="Save Report", style="Save.TButton",
            command=lambda: self.save_ai_report(output_text), 
            state=tk.DISABLED
        )
        save_button.pack(side="right", padx=5)
        
        close_button = ttk.Button(
            button_frame, text="Close",
            command=report_window.destroy
        )
        close_button.pack(side="right", padx=5)
        
    def run_report_generation(self, output_widget, format_type, include_recommendations, include_code, save_button):
        """Run the report generation with Claude AI."""
        # Gather all results
        all_results = []
        
        # Get results from Nmap
        nmap_results = self.nmap_tab.get_results()
        if nmap_results:
            all_results.append("=== NMAP SCAN RESULTS ===\n" + nmap_results)
        
        # Get results from Shodan
        shodan_results = self.shodan_tab.get_results()
        if shodan_results:
            all_results.append("=== SHODAN SEARCH RESULTS ===\n" + shodan_results)
        
        # Get results from Web Recon tabs
        for name, results in self.web_recon_tab.get_all_results().items():
            if results:
                all_results.append(f"=== {name.upper()} RESULTS ===\n" + results)
        
        if not all_results:
            self.output_queue.put(("output", output_widget, "No reconnaissance data found. Please run some scans first.\n"))
            return
        
        # Build prompt
        prompt = "You are a cybersecurity expert creating a comprehensive reconnaissance report. "
        
        if format_type == "Executive Summary":
            prompt += "Create a concise executive summary with the most critical findings. "
        elif format_type == "Detailed":
            prompt += "Create a detailed security assessment with thorough analysis of all findings. "
        elif format_type == "Technical":
            prompt += "Create a technical security report with in-depth technical analysis. "
        
        prompt += "Include: 1. Key findings from all reconnaissance methods, 2. Vulnerabilities identified, 3. Risk assessment"
        
        if include_recommendations:
            prompt += ", 4. Detailed security recommendations"
            
        if include_code:
            prompt += ", 5. Example code snippets for further analysis (in Python)"
        
        prompt += ".\n\nHere are all the reconnaissance results:\n" + "\n\n".join(all_results)
        
        # Clear output
        self.output_queue.put(("clear", output_widget, None))
        self.output_queue.put(("output", output_widget, "Generating comprehensive report with Claude AI...\n"))
        
        # Create a thread for the API call
        thread = threading.Thread(
            target=self.run_report_thread,
            args=(prompt, output_widget, save_button),
            daemon=True
        )
        thread.start()
    
    def run_report_thread(self, prompt, output_widget, save_button):
        """Run the report generation in a thread."""
        try:
            # Call Claude AI
            result = self.call_claude_ai(prompt, output_widget, max_tokens=4000)
            
            if result:
                # Enable save button
                self.after(0, lambda: save_button.config(state=tk.NORMAL))
        except Exception as e:
            self.output_queue.put(("output", output_widget, f"\nAn error occurred: {str(e)}\n{traceback.format_exc()}\n"))
    
    def save_ai_report(self, output_widget):
        """Save the generated AI report to a file."""
        content = output_widget.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No report content to save.")
            return
        
        filepath = filedialog.asksaveasfilename(
            initialfile="reconnaissance_report.txt",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("Markdown Files", "*.md"), ("All Files", "*.*")],
            title="Save Security Report"
        )
        
        if filepath:
            try:
                with open(filepath, "w", encoding='utf-8') as f:
                    f.write(content)
                self.update_status(f"Report saved to {filepath}")
                messagebox.showinfo("Save Successful", f"Security report saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save report: {e}")
                self.update_status("Error saving report.")
    
    def show_custom_ai_prompt(self):
        """Show dialog for custom AI prompt."""
        prompt_window = tk.Toplevel(self)
        prompt_window.title("Custom Claude AI Analysis")
        prompt_window.geometry("600x600")
        prompt_window.resizable(True, True)
        prompt_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        prompt_window.transient(self)
        prompt_window.grab_set()
        
        # Add padding
        frame = ttk.Frame(prompt_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Title
        title_font = font.Font(family="Helvetica", size=14, weight="bold")
        ttk.Label(frame, text="Custom Claude AI Analysis", font=title_font).pack(pady=(0, 10))
        
        # Prompt input
        ttk.Label(frame, text="Enter your prompt for Claude AI:").pack(anchor="w", pady=(10, 5))
        
        prompt_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=8, 
                                         background="white", foreground=COLORS["text"])
        prompt_text.pack(fill="x", pady=5)
        prompt_text.insert(tk.END, "Analyze the following reconnaissance data and provide insights on:")
        
        # Data selection
        data_frame = ttk.LabelFrame(frame, text="Include Data", padding="10")
        data_frame.pack(fill="x", pady=10)
        
        # Checkboxes for data sources
        include_nmap = tk.BooleanVar(value=True)
        include_shodan = tk.BooleanVar(value=True)
        include_domain = tk.BooleanVar(value=True)
        include_email = tk.BooleanVar(value=False)
        include_username = tk.BooleanVar(value=False)
        include_wayback = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(data_frame, text="Nmap Scan Results", variable=include_nmap).grid(
            row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="Shodan Results", variable=include_shodan).grid(
            row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="Domain Info", variable=include_domain).grid(
            row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="Email Scrape", variable=include_email).grid(
            row=1, column=1, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="Username Search", variable=include_username).grid(
            row=2, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="Wayback Machine", variable=include_wayback).grid(
            row=2, column=1, padx=5, pady=5, sticky="w")
        
        # Output area
        ttk.Label(frame, text="Claude AI Response:").pack(anchor="w", pady=(10, 5))
        
        output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=12, 
                                          background="white", foreground=COLORS["text"])
        output_text.pack(expand=True, fill="both", pady=5)
        output_text.configure(state='disabled')
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=10)
        
        analyze_button = ttk.Button(
            button_frame, text="Analyze with Claude AI", style="AI.TButton",
            command=lambda: self.run_custom_ai_analysis(
                prompt_text.get("1.0", tk.END),
                include_nmap.get(),
                include_shodan.get(),
                include_domain.get(),
                include_email.get(),
                include_username.get(),
                include_wayback.get(),
                output_text,
                save_button
            )
        )
        analyze_button.pack(side="left", padx=5)
        
        save_button = ttk.Button(
            button_frame, text="Save Results", style="Save.TButton",
            command=lambda: self.save_ai_report(output_text), 
            state=tk.DISABLED
        )
        save_button.pack(side="right", padx=5)
        
        close_button = ttk.Button(
            button_frame, text="Close",
            command=prompt_window.destroy
        )
        close_button.pack(side="right", padx=5)
    
    def run_custom_ai_analysis(self, prompt, include_nmap, include_shodan, include_domain, 
                             include_email, include_username, include_wayback, output_widget, save_button):
        """Run custom AI analysis with selected data."""
        # Gather selected results
        all_results = []
        
        # Get results based on selection
        if include_nmap:
            nmap_results = self.nmap_tab.get_results()
            if nmap_results:
                all_results.append("=== NMAP SCAN RESULTS ===\n" + nmap_results)
        
        if include_shodan:
            shodan_results = self.shodan_tab.get_results()
            if shodan_results:
                all_results.append("=== SHODAN SEARCH RESULTS ===\n" + shodan_results)
        
        # Get results from Web Recon tabs based on selection
        web_recon_results = self.web_recon_tab.get_all_results()
        
        if include_domain and "Domain Info" in web_recon_results:
            all_results.append(f"=== DOMAIN INFO RESULTS ===\n" + web_recon_results["Domain Info"])
            
        if include_email and "Email Scrape" in web_recon_results:
            all_results.append(f"=== EMAIL SCRAPE RESULTS ===\n" + web_recon_results["Email Scrape"])
            
        if include_username and "Username Search" in web_recon_results:
            all_results.append(f"=== USERNAME SEARCH RESULTS ===\n" + web_recon_results["Username Search"])
            
        if include_wayback and "Wayback Machine" in web_recon_results:
            all_results.append(f"=== WAYBACK MACHINE RESULTS ===\n" + web_recon_results["Wayback Machine"])
        
        if not all_results:
            self.output_queue.put(("output", output_widget, "No selected reconnaissance data found. Please run some scans first.\n"))
            return
        
        # Complete prompt with data
        full_prompt = prompt.strip() + "\n\n" + "\n\n".join(all_results)
        
        # Clear output
        self.output_queue.put(("clear", output_widget, None))
        self.output_queue.put(("output", output_widget, "Analyzing with Claude AI...\n"))
        
        # Create a thread for the API call
        thread = threading.Thread(
            target=self.run_custom_analysis_thread,
            args=(full_prompt, output_widget, save_button),
            daemon=True
        )
        thread.start()
    
    def run_custom_analysis_thread(self, prompt, output_widget, save_button):
        """Run custom analysis in a thread."""
        try:
            # Call Claude AI
            result = self.call_claude_ai(prompt, output_widget, max_tokens=4000)
            
            if result:
                # Enable save button
                self.after(0, lambda: save_button.config(state=tk.NORMAL))
        except Exception as e:
            self.output_queue.put(("output", output_widget, f"\nAn error occurred: {str(e)}\n{traceback.format_exc()}\n"))
    
    def generate_analysis_code(self):
        """Show dialog to generate Python code for analysis of recon data."""
        code_window = tk.Toplevel(self)
        code_window.title("Generate Analysis Code")
        code_window.geometry("700x700")
        code_window.resizable(True, True)
        code_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        code_window.transient(self)
        code_window.grab_set()
        
        # Add padding
        frame = ttk.Frame(code_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Title
        title_font = font.Font(family="Helvetica", size=14, weight="bold")
        ttk.Label(frame, text="Generate Python Analysis Code with Claude AI", font=title_font).pack(pady=(0, 10))
        
        # Instructions
        ttk.Label(frame, text="Specify what kind of analysis code you need:", 
               wraplength=650).pack(pady=(0, 10))
        
        # Requirements input
        requirement_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=6, 
                                               background="white", foreground=COLORS["text"])
        requirement_text.pack(fill="x", pady=5)
        requirement_text.insert(tk.END, "Generate Python code that:\n1. Parses the reconnaissance data\n2. Identifies potential security vulnerabilities\n3. Creates a summary report with findings")
        
        # Data selection
        data_frame = ttk.LabelFrame(frame, text="Include Data for Analysis", padding="10")
        data_frame.pack(fill="x", pady=10)
        
        # Checkboxes for data sources
        include_nmap = tk.BooleanVar(value=True)
        include_shodan = tk.BooleanVar(value=False)
        include_domain = tk.BooleanVar(value=False)
        include_all = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(data_frame, text="Nmap Scan Results", variable=include_nmap).grid(
            row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="Shodan Results", variable=include_shodan).grid(
            row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="Domain Info", variable=include_domain).grid(
            row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(data_frame, text="All Available Data", variable=include_all,
                     command=lambda: self.toggle_all_data_sources(include_all, [include_nmap, include_shodan, include_domain])).grid(
            row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Output area
        ttk.Label(frame, text="Generated Code:").pack(anchor="w", pady=(10, 5))
        
        output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=18, 
                                          background="white", foreground=COLORS["text"],
                                          font=("Courier", 10))
        output_text.pack(expand=True, fill="both", pady=5)
        output_text.configure(state='disabled')
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=10)
        
        generate_button = ttk.Button(
            button_frame, text="Generate Code", style="AI.TButton",
            command=lambda: self.run_code_generation(
                requirement_text.get("1.0", tk.END),
                include_nmap.get(),
                include_shodan.get(),
                include_domain.get(),
                include_all.get(),
                output_text,
                save_button
            )
        )
        generate_button.pack(side="left", padx=5)
        
        save_button = ttk.Button(
            button_frame, text="Save Code", style="Save.TButton",
            command=lambda: self.save_generated_code(output_text), 
            state=tk.DISABLED
        )
        save_button.pack(side="right", padx=5)
        
        close_button = ttk.Button(
            button_frame, text="Close",
            command=code_window.destroy
        )
        close_button.pack(side="right", padx=5)
    
    def toggle_all_data_sources(self, all_var, source_vars):
        """Toggle all data source checkboxes based on 'All' checkbox."""
        if all_var.get():
            for var in source_vars:
                var.set(True)
        
    def run_code_generation(self, requirements, include_nmap, include_shodan, include_domain, 
                          include_all, output_widget, save_button):
        """Run code generation with Claude AI."""
        # Gather selected results for sample data
        all_results = []
        
        # Get results based on selection
        if include_all or include_nmap:
            nmap_results = self.nmap_tab.get_results()
            if nmap_results:
                all_results.append("=== NMAP SCAN RESULTS ===\n" + nmap_results)
        
        if include_all or include_shodan:
            shodan_results = self.shodan_tab.get_results()
            if shodan_results:
                all_results.append("=== SHODAN SEARCH RESULTS ===\n" + shodan_results)
        
        # Get results from Web Recon tabs based on selection
        if include_all or include_domain:
            web_recon_results = self.web_recon_tab.get_all_results()
            
            if "Domain Info" in web_recon_results:
                all_results.append(f"=== DOMAIN INFO RESULTS ===\n" + web_recon_results["Domain Info"])
        
        if include_all:
            web_recon_results = self.web_recon_tab.get_all_results()
            
            for name, results in web_recon_results.items():
                if name != "Domain Info" and results:  # Already added Domain Info if selected
                    all_results.append(f"=== {name.upper()} RESULTS ===\n" + results)
        
        if not all_results:
            self.output_queue.put(("output", output_widget, "No selected reconnaissance data found to use as example. Please run some scans first.\n"))
            return
        
        # Build prompt
        prompt = f"""You are a cybersecurity expert creating Python code to analyze reconnaissance data.
Create well-documented, functional Python code that satisfies the following requirements:

{requirements}

The code should:
1. Be well-documented with comments explaining each section
2. Include error handling
3. Follow best practices for security tools
4. Be modular and reusable
5. Include main() function that demonstrates usage

Here's the data to analyze as an example:

all_results[0] if len(all_results) == 1 else all_results[0] + "\n\n" + all_results[1]"""
        
        # Clear output
        self.output_queue.put(("clear", output_widget, None))
        self.output_queue.put(("output", output_widget, "Generating Python code with Claude AI...\n"))
        
        # Create a thread for the API call
        thread = threading.Thread(
            target=self.run_code_generation_thread,
            args=(prompt, output_widget, save_button),
            daemon=True
        )
        thread.start()
    
    def run_code_generation_thread(self, prompt, output_widget, save_button):
        """Run code generation in a thread."""
        try:
            # Call Claude AI
            result = self.call_claude_ai(prompt, output_widget, max_tokens=4000)
            
            if result:
                # Enable save button
                self.after(0, lambda: save_button.config(state=tk.NORMAL))
        except Exception as e:
            self.output_queue.put(("output", output_widget, f"\nAn error occurred: {str(e)}\n{traceback.format_exc()}\n"))
    
    def save_generated_code(self, output_widget):
        """Save the generated code to a Python file."""
        content = output_widget.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No code content to save.")
            return
        
        # Extract just the code part, removing any explanations before or after
        code_lines = []
        in_code_block = False
        for line in content.split('\n'):
            if line.strip() == '```python':
                in_code_block = True
                continue
            elif line.strip() == '```' and in_code_block:
                in_code_block = False
                continue
                
            if in_code_block:
                code_lines.append(line)
        
        # If no code blocks found, use the entire content
        final_code = '\n'.join(code_lines) if code_lines else content
        
        filepath = filedialog.asksaveasfilename(
            initialfile="recon_analysis.py",
            defaultextension=".py",
            filetypes=[("Python Files", "*.py"), ("All Files", "*.*")],
            title="Save Python Code"
        )
        
        if filepath:
            try:
                with open(filepath, "w", encoding='utf-8') as f:
                    # Add shebang and encoding lines if not present
                    if not final_code.startswith("#!/usr/bin/env python"):
                        f.write("#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\n")
                    f.write(final_code)
                    
                self.update_status(f"Code saved to {filepath}")
                messagebox.showinfo("Save Successful", f"Python code saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save code: {e}")
                self.update_status("Error saving code.")
    
    def show_api_config(self):
        """Show a dialog to configure API keys."""
        config_window = tk.Toplevel(self)
        config_window.title("API Configuration")
        config_window.geometry("500x400")
        config_window.resizable(False, False)
        config_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        config_window.transient(self)
        config_window.grab_set()
        
        # Add padding
        frame = ttk.Frame(config_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Title
        title_font = font.Font(family="Helvetica", size=14, weight="bold")
        ttk.Label(frame, text="API Configuration", font=title_font).pack(pady=(0, 20))
        
        # Shodan API Key
        shodan_frame = ttk.LabelFrame(frame, text="Shodan API", padding="10")
        shodan_frame.pack(fill="x", pady=10)
        
        ttk.Label(shodan_frame, text="API Key:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        shodan_key_entry = ttk.Entry(shodan_frame, width=40, textvariable=self.shodan_api_key, show="*")
        shodan_key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Show/Hide Shodan key toggle
        show_shodan_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            shodan_frame, text="Show Key", 
            variable=show_shodan_key,
            command=lambda: shodan_key_entry.config(show="" if show_shodan_key.get() else "*")
        ).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(shodan_frame, text="Get a free API key at: https://account.shodan.io/register", 
                font=("Helvetica", 8)).grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="w")
        
        ttk.Button(
            shodan_frame, text="Test Shodan Key", 
            command=lambda: self.test_shodan_key(self.shodan_api_key.get(), config_window)
        ).grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        shodan_frame.columnconfigure(1, weight=1)
        
        # Claude API Key
        claude_frame = ttk.LabelFrame(frame, text="Claude AI API", padding="10")
        claude_frame.pack(fill="x", pady=10)
        
        ttk.Label(claude_frame, text="API Key:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        claude_key_entry = ttk.Entry(claude_frame, width=40, textvariable=self.claude_api_key, show="*")
        claude_key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Show/Hide Claude key toggle
        show_claude_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            claude_frame, text="Show Key", 
            variable=show_claude_key,
            command=lambda: claude_key_entry.config(show="" if show_claude_key.get() else "*")
        ).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(claude_frame, text="Get an API key at: https://console.anthropic.com", 
                font=("Helvetica", 8)).grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="w")
        
        ttk.Button(
            claude_frame, text="Test Claude Key", 
            command=lambda: self.test_claude_api(self.claude_api_key.get(), config_window)
        ).grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        claude_frame.columnconfigure(1, weight=1)
        
        # Save button
        ttk.Button(
            frame, text="Save & Close", 
            command=lambda: self.save_api_config(config_window)
        ).pack(pady=20)
    
    def save_api_config(self, window):
        """Save API configuration and close the window."""
        # Update the API client with the new key
        self.initialize_shodan()
        self.update_status("API configuration updated")
        window.destroy()
    
    def show_claude_config(self):
        """Show a dialog to configure Claude AI settings."""
        config_window = tk.Toplevel(self)
        config_window.title("Claude AI Configuration")
        config_window.geometry("500x400")
        config_window.resizable(False, False)
        config_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        config_window.transient(self)
        config_window.grab_set()
        
        # Add padding
        frame = ttk.Frame(config_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Title
        title_font = font.Font(family="Helvetica", size=14, weight="bold")
        ttk.Label(frame, text="Claude AI Configuration", font=title_font).pack(pady=(0, 20))
        
        # API Key
        api_frame = ttk.LabelFrame(frame, text="API Settings", padding="10")
        api_frame.pack(fill="x", pady=10)
        
        ttk.Label(api_frame, text="Claude API Key:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        key_entry = ttk.Entry(api_frame, width=40, textvariable=self.claude_api_key, show="*")
        key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Show/Hide key toggle
        show_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            api_frame, text="Show Key", 
            variable=show_key,
            command=lambda: key_entry.config(show="" if show_key.get() else "*")
        ).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(api_frame, text="Get an API key at: https://console.anthropic.com", 
                font=("Helvetica", 8)).grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="w")
        
        ttk.Button(
            api_frame, text="Test API Key", 
            command=lambda: self.test_claude_api(self.claude_api_key.get(), config_window)
        ).grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        api_frame.columnconfigure(1, weight=1)
        
        # Usage Information
        usage_frame = ttk.LabelFrame(frame, text="Usage Information", padding="10")
        usage_frame.pack(fill="x", pady=10)
        
        ttk.Label(usage_frame, text="Claude AI is integrated throughout the application to:").pack(anchor="w", pady=5)
        ttk.Label(usage_frame, text="• Analyze reconnaissance results").pack(anchor="w", pady=2)
        ttk.Label(usage_frame, text="• Generate comprehensive security reports").pack(anchor="w", pady=2)
        ttk.Label(usage_frame, text="• Create custom Python scripts for data analysis").pack(anchor="w", pady=2)
        ttk.Label(usage_frame, text="• Provide security recommendations based on findings").pack(anchor="w", pady=2)
        
        ttk.Label(usage_frame, text="Each tool tab has AI analysis capabilities accessible via the 'Analyze with Claude' button.",
                wraplength=450).pack(anchor="w", pady=5)
        
        # Save button
        ttk.Button(
            frame, text="Save & Close", 
            command=lambda: self.save_api_config(config_window)
        ).pack(pady=20)
    
    def show_about(self):
        """Display the About dialog with author information."""
        about_window = tk.Toplevel(self)
        about_window.title("About Reconnaissance Tool")
        about_window.geometry("400x400")
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
        description = ("A comprehensive tool for network reconnaissance, featuring "
                     "Nmap scanning, Shodan intelligence, and various web "
                     "reconnaissance capabilities. Enhanced with Claude AI for "
                     "intelligent analysis and insights.")
        ttk.Label(frame, text=description, justify="center", wraplength=350).pack(pady=(0, 15))
        
        # AI Integration note
        ai_note = "Powered by Claude AI for enhanced security analysis."
        ttk.Label(frame, text=ai_note, foreground=COLORS["ai_highlight"], 
                font=("Helvetica", 10, "italic")).pack(pady=(0, 15))
        
        # Close button
        ttk.Button(frame, text="Close", command=about_window.destroy).pack(pady=10)
    
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
        content_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20, 
                                              background="white", foreground=COLORS["text"])
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

5. Using with Claude AI:
   - Use the "Analyze with Claude" button to get AI analysis of Shodan results
   - Claude can identify patterns and security implications
   - Get recommendations based on findings
   - Generate custom reports for client presentations

Remember: Shodan is a powerful tool that should be used responsibly and ethically.
"""
        
        content_text.insert(tk.END, guide_content)
        content_text.configure(state='disabled')
        
        # Close button
        ttk.Button(frame, text="Close", command=guide_window.destroy).pack(pady=10)
    
    def show_claude_guide(self):
        """Show a window with Claude AI usage guidelines."""
        guide_window = tk.Toplevel(self)
        guide_window.title("Claude AI Usage Guide")
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
        ttk.Label(frame, text="Claude AI Usage Guide", font=title_font).pack(pady=(0, 10))
        
        # Content
        content_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20, 
                                               background="white", foreground=COLORS["text"])
        content_text.pack(expand=True, fill="both", pady=10)
        
        guide_content = """
Claude AI Integration Guide:

1. Introduction to Claude AI:
   - Claude AI is integrated throughout the reconnaissance tool
   - Provides intelligent analysis of reconnaissance data
   - Generates security insights, reports, and code
   - Enhances the value of collected data with expert analysis

2. Key Features:
   - Analyze scan results for security vulnerabilities
   - Generate comprehensive security reports
   - Create custom Python scripts for data analysis
   - Provide actionable security recommendations
   - Identify patterns and relationships in reconnaissance data

3. How to Use Claude AI in Each Tab:
   - Nmap Scanner: Click "Analyze with Claude" after running a scan
   - Shodan Search: Use "Analyze Results" to identify security implications
   - Domain Info: Get detailed domain security analysis with "Analyze Domain"
   - Email Scraper: Analyze exposure risks and patterns in found emails
   - Username Search: Assess digital footprint implications
   - Wayback Machine: Analyze historical website security posture

4. Additional AI Features:
   - Generate Comprehensive Report: Create a full security assessment
   - Custom AI Analysis: Ask custom questions about your reconnaissance data
   - Generate Analysis Code: Create Python scripts for further analysis
   
5. Best Practices:
   - Run scans first to collect data before using AI analysis
   - Be specific in custom analysis prompts
   - Save AI-generated reports for later reference
   - Use AI insights to guide further reconnaissance
   - Combine insights from multiple tools for a complete picture

6. API Key Management:
   - Configure your Claude API key in Settings > Configure API Keys
   - Test your API key to ensure it's working
   - Your API key is stored only locally and never shared
   - Default API key is provided but you can use your own

Claude AI enhances your reconnaissance capabilities with expert analysis and insights.
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
    
    def analyze_with_claude(self, prompt_template, data=None):
        """Use Claude AI to analyze results."""
        if not data:
            data = self.get_results()
            
        if not data or len(data.strip()) < 10:
            messagebox.showwarning("Warning", "No data available to analyze. Please run a scan first.")
            return
        
        # Create analysis dialog
        analysis_window = tk.Toplevel(self)
        analysis_window.title("Claude AI Analysis")
        analysis_window.geometry("700x600")
        analysis_window.resizable(True, True)
        analysis_window.configure(bg=COLORS["background"])
        
        # Make the window modal
        analysis_window.transient(self)
        analysis_window.grab_set()
        
        # Add padding
        frame = ttk.Frame(analysis_window, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Title
        title_font = font.Font(family="Helvetica", size=14, weight="bold")
        ttk.Label(frame, text="Claude AI Security Analysis", font=title_font).pack(pady=(0, 10))
        
        # Analysis output
        ttk.Label(frame, text="Analysis Results:").pack(anchor="w", pady=(10, 5))
        
        analysis_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20, 
                                               background="white", foreground=COLORS["text"])
        analysis_text.pack(expand=True, fill="both", pady=5)
        analysis_text.configure(state='disabled')
        
        # Prepare for analysis
        self.queue.put(("output", analysis_text, "Analyzing data with Claude AI...\n"))
        
        # Final prompt
        prompt = prompt_template.format(data)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=10)
        
        save_button = ttk.Button(
            button_frame, text="Save Analysis", style="Save.TButton",
            command=lambda: self.save_analysis(analysis_text),
            state=tk.DISABLED
        )
        save_button.pack(side="right", padx=5)
        
        close_button = ttk.Button(
            button_frame, text="Close",
            command=analysis_window.destroy
        )
        close_button.pack(side="right", padx=5)
        
        # Create a thread for the analysis
        thread = threading.Thread(
            target=self.run_analysis_thread,
            args=(prompt, analysis_text, save_button),
            daemon=True
        )
        thread.start()
    
    def run_analysis_thread(self, prompt, output_widget, save_button):
        """Run AI analysis in a thread."""
        try:
            # Call Claude AI
            result = self.parent.call_claude_ai(prompt, output_widget)
            
            if result:
                # Enable save button
                self.after(0, lambda: save_button.config(state=tk.NORMAL))
        except Exception as e:
            self.queue.put(("output", output_widget, f"\nAn error occurred during analysis: {str(e)}\n{traceback.format_exc()}\n"))
    
    def save_analysis(self, analysis_text):
        """Save the Claude AI analysis to a file."""
        content = analysis_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No analysis content to save.")
            return
        
        filepath = filedialog.asksaveasfilename(
            initialfile="claude_analysis.txt",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("Markdown Files", "*.md"), ("All Files", "*.*")],
            title="Save Analysis Results"
        )
        
        if filepath:
            try:
                with open(filepath, "w", encoding='utf-8') as f:
                    f.write(content)
                self.update_status(f"Analysis saved to {filepath}")
                messagebox.showinfo("Save Successful", f"Analysis saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save analysis: {e}")
                self.update_status("Error saving analysis.")

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
        
        # Add AI analysis button
        self.analyze_button = ttk.Button(
            action_frame, text="Analyze with Claude", style="AI.TButton", 
            command=lambda: self.analyze_with_claude(CLAUDE_PROMPTS["analyze_nmap"])
        )
        self.analyze_button.pack(side="left", padx=5)
        
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
            self.queue.put(("output", output_widget, 
                          f"Error: Command '{command[0]}' not found. Make sure it's installed and in your PATH.\n"))
            self.queue.put(("status", None, "Error: Command not found."))
        except Exception as e:
            self.queue.put(("output", output_widget, 
                          f"An error occurred: {e}\n{traceback.format_exc()}\n"))
            self.queue.put(("status", None, "Error during scan."))
        finally:
            # Re-enable button on the main thread
            if button_to_enable:
                self.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

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
        
        # Add AI analysis button
        self.analyze_button = ttk.Button(
            action_frame, text="Analyze with Claude", style="AI.TButton", 
            command=lambda: self.analyze_with_claude(CLAUDE_PROMPTS["analyze_shodan"])
        )
        self.analyze_button.pack(side="left", padx=5)
        
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
            if not self.parent.initialize_shodan():
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
            target=self.run_query_thread,args=(query, query_type, self.output_text, self.run_button),
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
                try:
                    formatted_results = json.dumps(results, indent=4, sort_keys=True, default=str)
                    self.queue.put(("output", output_widget, formatted_results + "\n"))
                except:
                    # Fallback if JSON formatting fails
                    self.queue.put(("output", output_widget, f"Raw results: {str(results)[:2000]}...\n"))
                
                # Display summary
                try:
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
                except:
                    # Fallback if summary fails
                    self.queue.put(("output", output_widget, "\nCould not generate summary from results.\n"))
                
                self.queue.put(("status", None, f"Shodan {query_type} query finished successfully."))
            else:
                self.queue.put(("output", output_widget, "No results found.\n"))
                self.queue.put(("status", None, f"Shodan {query_type} query finished - No results."))
                
        except Exception as e:
            self.queue.put(("output", output_widget, f"Shodan API Error: {str(e)}\n"))
            
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
                self.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

# --- Web Recon Tab Class ---
class WebReconTab(BaseTab):
    def __init__(self, notebook, parent):
        super().__init__(notebook, parent)
        
        # Create sub-notebook for web recon tools
        self.web_notebook = ttk.Notebook(self)
        self.web_notebook.pack(expand=True, fill="both", pady=5)
        
        # Create tabs for each web recon tool
        self.domain_tab = DomainTab(self.web_notebook, parent)
        self.email_tab = EmailTab(self.web_notebook, parent)
        self.username_tab = UsernameTab(self.web_notebook, parent)
        self.wayback_tab = WaybackTab(self.web_notebook, parent)
        
        # Add tabs to notebook
        self.web_notebook.add(self.domain_tab, text="Domain/DNS Info")
        self.web_notebook.add(self.email_tab, text="Email Scraper")
        self.web_notebook.add(self.username_tab, text="Username Search")
        self.web_notebook.add(self.wayback_tab, text="Wayback Machine")
        
    def get_all_results(self):
        """Get results from all sub-tabs."""
        results = {}
        sub_tabs = {
            "Domain Info": self.domain_tab,
            "Email Scrape": self.email_tab,
            "Username Search": self.username_tab,
            "Wayback Machine": self.wayback_tab
        }
        
        for name, tab in sub_tabs.items():
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
        
        # Add AI analysis button
        self.analyze_button = ttk.Button(
            action_frame, text="Analyze with Claude", style="AI.TButton", 
            command=lambda: self.analyze_with_claude(CLAUDE_PROMPTS["analyze_domain"])
        )
        self.analyze_button.pack(side="left", padx=5)
        
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
    
    def run_whois_thread(self, domain, output_widget, buttons_to_enable):
        """Completely self-contained WHOIS lookup function with no external dependencies."""
        try:
            # Show starting message
            if domain.startswith(("http://", "https://")):
                from urllib.parse import urlparse
                parsed = urlparse(domain)
                domain = parsed.netloc
                self.queue.put(("output", output_widget, f"--- WHOIS Lookup for {domain} ---\n"))
                self.queue.put(("output", output_widget, f"Note: Extracted domain {domain} from URL\n"))
            else:
                self.queue.put(("output", output_widget, f"--- WHOIS Lookup for {domain} ---\n"))
            
            # Remove www. prefix if present
            if domain.startswith("www."):
                domain = domain[4:]
                self.queue.put(("output", output_widget, f"Note: Removed www. prefix: {domain}\n"))
            
            # First try: WHOIS XML API
            self.queue.put(("output", output_widget, "Trying WHOIS API lookup...\n"))
            try:
                import requests
                api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON&apiKey=at_demo_key"
                response = requests.get(api_url, timeout=10)
                
                if response.status_code == 200:
                    import json
                    data = response.json()
                    if 'WhoisRecord' in data:
                        record = data['WhoisRecord']
                        result = f"Domain Information for: {record.get('domainName', domain)}\n\n"
                        
                        if 'registryData' in record:
                            reg = record['registryData']
                            if 'registrarName' in reg:
                                result += f"Registrar: {reg.get('registrarName', 'N/A')}\n"
                            if 'createdDate' in reg:
                                result += f"Created Date: {reg.get('createdDate', 'N/A')}\n"
                            if 'expiresDate' in reg:
                                result += f"Expiration Date: {reg.get('expiresDate', 'N/A')}\n"
                            if 'updatedDate' in reg:
                                result += f"Updated Date: {reg.get('updatedDate', 'N/A')}\n"
                            if 'status' in reg:
                                if isinstance(reg['status'], list):
                                    result += f"Status: {', '.join(reg['status'])}\n"
                                else:
                                    result += f"Status: {reg.get('status', 'N/A')}\n"
                        
                        if 'contactEmail' in record:
                            result += f"Contact Email: {record.get('contactEmail', 'N/A')}\n"
                        
                        if 'nameServers' in record:
                            ns = record['nameServers']
                            if 'hostNames' in ns and ns['hostNames']:
                                result += f"Name Servers: {', '.join(ns['hostNames'])}\n"
                        
                        self.queue.put(("output", output_widget, result + "\n"))
                        self.queue.put(("output", output_widget, "WHOIS lookup completed successfully via API.\n"))
                        self.queue.put(("status", None, "WHOIS lookup finished."))
                        return # Success - exit early
            except Exception as e:
                self.queue.put(("output", output_widget, f"WHOIS API lookup failed: {str(e)}\n"))
            
            # Second try: Web scraping from Whois.com
            self.queue.put(("output", output_widget, "Trying web scraping for WHOIS data...\n"))
            try:
                import requests
                import re
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
                
                # Try whois.com
                whois_url = f"https://www.whois.com/whois/{domain}"
                response = requests.get(whois_url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    # Look for the whois data section
                    whois_pattern = re.compile(r'<div class="df-block">(.*?)</div>', re.DOTALL)
                    match = whois_pattern.search(response.text)
                    
                    if match:
                        # Clean up the HTML
                        whois_text = match.group(1)
                        whois_text = re.sub(r'<[^>]+>', ' ', whois_text)  # Remove HTML tags
                        whois_text = re.sub(r'\s+', ' ', whois_text)      # Normalize whitespace
                        whois_text = whois_text.strip()
                        
                        # Format nicely
                        formatted_text = whois_text
                        self.queue.put(("output", output_widget, "WHOIS Information:\n\n"))
                        self.queue.put(("output", output_widget, formatted_text + "\n"))
                        self.queue.put(("output", output_widget, "\nWHOIS lookup completed via web scraping.\n"))
                        self.queue.put(("status", None, "WHOIS lookup finished."))
                        return # Success - exit early
                    else:
                        # Try an alternative scraping approach
                        self.queue.put(("output", output_widget, "Trying alternative data extraction method...\n"))
                        if "Domain Information" in response.text:
                            # Just grab the page content and try to clean it
                            start_idx = response.text.find("Domain Information")
                            end_idx = response.text.find("</div>", start_idx)
                            if start_idx > 0 and end_idx > start_idx:
                                content = response.text[start_idx:end_idx]
                                # Clean HTML tags
                                content = re.sub(r'<[^>]+>', ' ', content)
                                content = re.sub(r'\s+', ' ', content)
                                content = content.strip()
                                
                                self.queue.put(("output", output_widget, "WHOIS Information:\n\n"))
                                self.queue.put(("output", output_widget, content + "\n"))
                                self.queue.put(("output", output_widget, "\nWHOIS lookup completed via web scraping.\n"))
                                self.queue.put(("status", None, "WHOIS lookup finished."))
                                return # Success - exit early
            except Exception as e:
                self.queue.put(("output", output_widget, f"Web scraping for WHOIS data failed: {str(e)}\n"))
            
            # Third try: Alternative API
            self.queue.put(("output", output_widget, "Trying alternative WHOIS service...\n"))
            try:
                import requests
                import json
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                
                # Try using the public ICANN lookup API
                icann_url = f"https://rdap.org/domain/{domain}"
                response = requests.get(icann_url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        result = f"Domain Information for: {domain}\n\n"
                        
                        # Extract basic info
                        if 'handle' in data:
                            result += f"Handle: {data['handle']}\n"
                        
                        # Extract entities (registrar, registrant)
                        if 'entities' in data:
                            for entity in data['entities']:
                                entity_type = entity.get('roles', ['Unknown'])[0]
                                result += f"{entity_type.capitalize()}: "
                                
                                # Try to get name from vcardArray
                                if 'vcardArray' in entity and len(entity['vcardArray']) > 1:
                                    for field in entity['vcardArray'][1:]:
                                        if field[0] == 'fn':
                                            result += f"{field[3]}\n"
                                            break
                                    else:
                                        result += "Unknown\n"
                                else:
                                    result += "Unknown\n"
                        
                        # Extract events (registration, expiration)
                        if 'events' in data:
                            for event in data['events']:
                                if 'eventAction' in event and 'eventDate' in event:
                                    result += f"{event['eventAction'].capitalize()}: {event['eventDate']}\n"
                        
                        self.queue.put(("output", output_widget, result + "\n"))
                        self.queue.put(("output", output_widget, "WHOIS lookup completed via RDAP API.\n"))
                        self.queue.put(("status", None, "WHOIS lookup finished."))
                        return # Success - exit early
                    except Exception as e:
                        self.queue.put(("output", output_widget, f"Error parsing RDAP API response: {str(e)}\n"))
            except Exception as e:
                self.queue.put(("output", output_widget, f"Alternative WHOIS service failed: {str(e)}\n"))
            
            # Fourth try: Direct WHOIS server socket connection
            self.queue.put(("output", output_widget, "Trying direct WHOIS server connection...\n"))
            try:
                import socket
                
                # Extract TLD
                tld = domain.split('.')[-1]
                
                # Known WHOIS servers for common TLDs
                whois_servers = {
                    'com': 'whois.verisign-grs.com',
                    'net': 'whois.verisign-grs.com',
                    'org': 'whois.pir.org',
                    'edu': 'whois.educause.edu',
                    'gov': 'whois.dotgov.gov',
                    'io': 'whois.nic.io',
                    'co': 'whois.nic.co',
                    'uk': 'whois.nic.uk',
                    'au': 'whois.auda.org.au',
                    'de': 'whois.denic.de',
                    'jp': 'whois.jprs.jp',
                    'ru': 'whois.tcinet.ru',
                    'jo': 'whois.tld.jo',  # Jordan TLD
                }
                
                # Select WHOIS server
                server = whois_servers.get(tld, 'whois.iana.org')
                
                # Connect to the WHOIS server
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((server, 43))
                
                # Send the domain query
                query = f"{domain}\r\n"
                s.send(query.encode())
                
                # Receive the response
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                
                s.close()
                
                # Convert to string
                try:
                    whois_text = response.decode('utf-8', errors='ignore')
                except:
                    whois_text = response.decode('latin-1', errors='ignore')
                
                if whois_text and len(whois_text) > 10:  # Ensure we got a meaningful response
                    self.queue.put(("output", output_widget, "WHOIS Information:\n\n"))
                    self.queue.put(("output", output_widget, whois_text + "\n"))
                    self.queue.put(("output", output_widget, "\nWHOIS lookup completed via direct server connection.\n"))
                    self.queue.put(("status", None, "WHOIS lookup finished."))
                    return # Success - exit early
            except Exception as e:
                self.queue.put(("output", output_widget, f"Direct WHOIS server connection failed: {str(e)}\n"))
            
            # If all methods failed, try one last approach - who.is web lookup
            self.queue.put(("output", output_widget, "Trying who.is lookup service...\n"))
            try:
                import requests
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                
                who_is_url = f"https://who.is/whois/{domain}"
                response = requests.get(who_is_url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    import re
                    # Look for the whois data section
                    whois_pattern = re.compile(r'<div class="queryResponseBodyKey">(.*?)</div>', re.DOTALL)
                    match = whois_pattern.search(response.text)
                    
                    if match:
                        # Clean up the HTML
                        whois_text = match.group(1)
                        whois_text = re.sub(r'<[^>]+>', ' ', whois_text)  # Remove HTML tags
                        whois_text = re.sub(r'\s+', ' ', whois_text)      # Normalize whitespace
                        whois_text = whois_text.strip()
                        
                        self.queue.put(("output", output_widget, "WHOIS Information:\n\n"))
                        self.queue.put(("output", output_widget, whois_text + "\n"))
                        self.queue.put(("output", output_widget, "\nWHOIS lookup completed via who.is service.\n"))
                        self.queue.put(("status", None, "WHOIS lookup finished."))
                        return
            except Exception as e:
                self.queue.put(("output", output_widget, f"Who.is service lookup failed: {str(e)}\n"))
            
            # If we got here, all methods failed
            self.queue.put(("output", output_widget, "\nAll WHOIS lookup methods failed.\n\n"))
            self.queue.put(("output", output_widget, "Domain information might not be publicly available or there might be connection issues.\n"))
            self.queue.put(("output", output_widget, "Try these alternatives:\n"))
            self.queue.put(("output", output_widget, f"1. Use a simpler domain (try anu.edu.jo instead of moodle.anu.edu.jo)\n"))
            self.queue.put(("output", output_widget, f"2. Check these WHOIS services in your web browser:\n"))
            self.queue.put(("output", output_widget, f"   - https://www.whois.com/whois/{domain}\n"))
            self.queue.put(("output", output_widget, f"   - https://lookup.icann.org/en/lookup?q={domain}\n"))
            self.queue.put(("output", output_widget, f"   - https://who.is/whois/{domain}\n"))
            self.queue.put(("status", None, "WHOIS lookup failed."))
            
        except Exception as e:
            import traceback
            self.queue.put(("output", output_widget, f"An unexpected error occurred: {str(e)}\n{traceback.format_exc()}\n"))
            self.queue.put(("status", None, "Error during WHOIS lookup."))
        finally:
            # Re-enable buttons
            if buttons_to_enable:
                # Use self directly, not self.parent
                self.after(0, lambda: [btn.config(state=tk.NORMAL) for btn in buttons_to_enable])
        
    def start_dns(self):
        """Start a DNS lookup."""
        if not DNS_AVAILABLE:
            messagebox.showerror("Error", "DNS resolver library not installed. Please install with: pip install dnspython")
            return
            
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name.")
            return
        
        # Extract domain from URL if needed
        if domain.startswith(("http://", "https://")):
            parsed = urlparse(domain)
            domain = parsed.netloc
        
        # Remove www. prefix if present
        if domain.startswith("www."):
            domain = domain[4:]
        
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
        
    def run_dns_thread(self, domain, output_widget, buttons_to_enable):
        """Run DNS lookup in a thread."""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        try:
            self.queue.put(("output", output_widget, f"--- DNS Lookup for {domain} ---\n"))
            
            # Create resolver
            resolver = dns.resolver.Resolver()
            
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
            self.queue.put(("output", output_widget, 
                          f"An unexpected error occurred during DNS lookup: {e}\n{traceback.format_exc()}\n"))
            self.queue.put(("status", None, "Error during DNS lookup."))
        finally:
            # Re-enable buttons
            if buttons_to_enable:
                self.after(0, lambda: [btn.config(state=tk.NORMAL) for btn in buttons_to_enable])

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
        
        # Add AI analysis button
        self.analyze_button = ttk.Button(
            action_frame, text="Analyze with Claude", style="AI.TButton", 
            command=lambda: self.analyze_with_claude(CLAUDE_PROMPTS["analyze_emails"])
        )
        self.analyze_button.pack(side="left", padx=5)
        
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
                self.queue.put(("output", output_widget, 
                              f"Warning: Content type is '{content_type}', not HTML. Scraping page text only.\n"))
                # Process as text
                text_content = response.text
                emails = set(re.findall(EMAIL_REGEX, text_content))
            else:
                # Process as HTML
                self.queue.put(("output", output_widget, "Parsing HTML content...\n"))
                if BS4_AVAILABLE:
                    soup = BeautifulSoup(response.text, "html.parser")
                    text_content = soup.get_text()
                    emails.update(re.findall(EMAIL_REGEX, text_content))
                    
                    # Find emails in mailto links
                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag["href"]
                        if href.startswith("mailto:"):
                            email = href[7:].split("?")[0]  # Remove "mailto:" and any parameters
                            if re.match(EMAIL_REGEX, email):
                                emails.add(email)
                else:
                    # Fallback if BeautifulSoup is not available
                    self.queue.put(("output", output_widget, "Note: BeautifulSoup not installed. Using basic regex instead.\n"))
                    text_content = response.text
                    emails = set(re.findall(EMAIL_REGEX, text_content))
                    
                    # Also try to find mailto links with regex
                    mailto_regex = r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
                    mailto_emails = re.findall(mailto_regex, text_content)
                    emails.update(mailto_emails)
            
            # Display results
            if emails:
                self.queue.put(("output", output_widget, f"\nFound {len(emails)} unique email(s):\n"))
                for email in sorted(list(emails)):
                    self.queue.put(("output", output_widget, f"  - {email}\n"))
            else:
                self.queue.put(("output", output_widget, "\nNo emails found on this page.\n"))
                
                # Suggestion
                self.queue.put(("output", output_widget, 
                              "Tip: Try checking the Contact or About pages for email addresses.\n"))
            
            self.queue.put(("status", None, "Email scraping finished."))
            
        except requests.exceptions.Timeout:
            self.queue.put(("output", output_widget, 
                          f"HTTP Request Error: Timeout while trying to connect to {url}\n"))
            self.queue.put(("output", output_widget, "The request took too long to complete. Try again later.\n"))
            self.queue.put(("status", None, "Error: Request timed out."))
        except requests.exceptions.RequestException as e:
            self.queue.put(("output", output_widget, f"HTTP Request Error: {e}\n"))
            self.queue.put(("status", None, "Error during email scraping."))
        except Exception as e:
            self.queue.put(("output", output_widget, 
                          f"An unexpected error occurred during email scraping: {e}\n{traceback.format_exc()}\n"))
            self.queue.put(("status", None, "Error during email scraping."))
        finally:
            # Re-enable button
            if button_to_enable:
                self.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

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
        
        # Add AI analysis button
        self.analyze_button = ttk.Button(
            action_frame, text="Analyze with Claude", style="AI.TButton", 
            command=lambda: self.analyze_with_claude(CLAUDE_PROMPTS["analyze_username"])
        )
        self.analyze_button.pack(side="left", padx=5)
        
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
                        self.queue.put(("output", output_widget, 
                                      f"Uncertain (Status: {response.status_code})\n"))
                    
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
                self.queue.put(("output", output_widget, 
                              f"\nNote: Encountered errors with {len(error_sites)} sites. Try again later.\n"))
            
            self.queue.put(("status", None, "Username search finished."))
            
        except Exception as e:
            self.queue.put(("output", output_widget, 
                          f"An unexpected error occurred during username search: {e}\n{traceback.format_exc()}\n"))
            self.queue.put(("status", None, "Error during username search."))
        finally:
            # Re-enable button
            if button_to_enable:
                self.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

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
        
        # Add AI analysis button
        self.analyze_button = ttk.Button(
            action_frame, text="Analyze with Claude", style="AI.TButton", 
            command=lambda: self.analyze_with_claude(CLAUDE_PROMPTS["analyze_wayback"])
        )
        self.analyze_button.pack(side="left", padx=5)
        
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
                                headers_row = cdx_data[0]
                                timestamp_idx = headers_row.index("timestamp") if "timestamp" in headers_row else 1
                                status_idx = headers_row.index("statuscode") if "statuscode" in headers_row else 2
                                
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
                                        
                                    self.queue.put(("output", output_widget, 
                                                  f"  {i}. {formatted_date} (Status: {status})\n"))
                        except:
                            # Not critical, just skip detailed info
                            pass
                except:
                    # Not critical, continue without detailed info
                    pass
                    
            else:
                self.queue.put(("output", output_widget, "No snapshots found in the Wayback Machine for this URL.\n"))
                self.queue.put(("output", output_widget, 
                              "This may mean the site has never been archived or has been excluded from archiving.\n"))
                
                # Suggest to check with wildcards or domain only
                parsed_url = urlparse(url)
                if parsed_url.path and parsed_url.path != '/':
                    domain_only = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    self.queue.put(("output", output_widget, 
                                  f"\nTip: Try checking the domain only: {domain_only}\n"))
            
            self.queue.put(("status", None, "Wayback Machine check finished."))
            
        except requests.exceptions.Timeout:
            self.queue.put(("output", output_widget, 
                          "HTTP Request Error: Timeout while contacting Wayback Machine API\n"))
            self.queue.put(("output", output_widget, 
                          "The request took too long to complete. This may be due to network issues or high server load.\n"))
            self.queue.put(("status", None, "Error: Wayback API timeout."))
        except requests.exceptions.RequestException as e:
            self.queue.put(("output", output_widget, f"Wayback Machine API Error: {e}\n"))
            self.queue.put(("output", output_widget, 
                          "Failed to connect to the Wayback Machine API. Please check your internet connection and try again.\n"))
            self.queue.put(("status", None, "Error during Wayback check."))
        except Exception as e:
            self.queue.put(("output", output_widget, 
                          f"An unexpected error occurred during Wayback check: {e}\n{traceback.format_exc()}\n"))
            self.queue.put(("status", None, "Error during Wayback check."))
        finally:
            # Re-enable button
            if button_to_enable:
                self.after(0, lambda: button_to_enable.config(state=tk.NORMAL))

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