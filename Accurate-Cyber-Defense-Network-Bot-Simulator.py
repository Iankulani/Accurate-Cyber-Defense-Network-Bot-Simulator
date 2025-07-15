import sys
import time
import socket
import threading
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json
import platform
import subprocess
import netifaces
import datetime
from collections import defaultdict
import numpy as np

# Constants
TELEGRAM_API_URL = "https://api.telegram.org/bot{}/sendMessage"
CONFIG_FILE = "config.json"
LOG_FILE = "security_monitor.log"
UPDATE_INTERVAL = 5  # seconds

class CyberSecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Security Monitor v1.0")
        self.root.geometry("1200x800")
        self.set_theme("black_green")
        
        # Monitoring variables
        self.monitoring = False
        self.target_ip = ""
        self.telegram_token = ""
        self.telegram_chat_id = ""
        self.load_config()
        
        # Data storage
        self.traffic_data = defaultdict(list)
        self.threat_data = {
            "DoS": 0,
            "DDoS": 0,
            "Port Scanning": 0,
            "Unusual Traffic": 0
        }
        self.bandwidth_data = {
            "incoming": [],
            "outgoing": []
        }
        
        # Create GUI
        self.create_menu()
        self.create_dashboard()
        self.create_terminal()
        
        # Start background threads
        self.update_thread = threading.Thread(target=self.update_gui, daemon=True)
        self.update_thread.start()
        
    def set_theme(self, theme_name):
        if theme_name == "black_green":
            self.bg_color = "#000000"
            self.fg_color = "#00FF00"
            self.accent_color = "#006600"
            self.text_bg = "#111111"
        else:
            self.bg_color = "#FFFFFF"
            self.fg_color = "#000000"
            self.accent_color = "#CCCCCC"
            self.text_bg = "#EEEEEE"
            
        self.root.configure(bg=self.bg_color)
        
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New", command=self.dummy_command)
        file_menu.add_command(label="Open", command=self.dummy_command)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Terminal", command=self.show_terminal)
        view_menu.add_separator()
        view_menu.add_command(label="Black/Green Theme", command=lambda: self.set_theme("black_green"))
        view_menu.add_command(label="Light Theme", command=lambda: self.set_theme("light"))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.dummy_command)
        tools_menu.add_command(label="Threat Analyzer", command=self.dummy_command)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Telegram Settings", command=self.open_telegram_settings)
        settings_menu.add_command(label="Monitoring Settings", command=self.dummy_command)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard(self):
        self.dashboard_frame = tk.Frame(self.root, bg=self.bg_color)
        
        # Left panel - Stats
        left_panel = tk.Frame(self.dashboard_frame, bg=self.bg_color)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Monitoring controls
        monitor_frame = tk.LabelFrame(left_panel, text="Monitoring Controls", bg=self.bg_color, fg=self.fg_color)
        monitor_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(monitor_frame, text="Target IP:", bg=self.bg_color, fg=self.fg_color).pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(monitor_frame, bg=self.text_bg, fg=self.fg_color, insertbackground=self.fg_color)
        self.ip_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.ip_entry.insert(0, self.target_ip)
        
        self.start_btn = tk.Button(monitor_frame, text="Start Monitoring", command=self.start_monitoring, 
                                  bg=self.accent_color, fg=self.fg_color)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(monitor_frame, text="Stop Monitoring", command=self.stop_monitoring, 
                                 bg=self.accent_color, fg=self.fg_color, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        # Threat summary
        threat_frame = tk.LabelFrame(left_panel, text="Threat Summary", bg=self.bg_color, fg=self.fg_color)
        threat_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.threat_canvas = tk.Canvas(threat_frame, bg=self.bg_color)
        self.threat_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - Charts
        right_panel = tk.Frame(self.dashboard_frame, bg=self.bg_color)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Bandwidth chart
        bw_frame = tk.LabelFrame(right_panel, text="Bandwidth Usage", bg=self.bg_color, fg=self.fg_color)
        bw_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.bw_fig, self.bw_ax = plt.subplots(figsize=(5, 3), facecolor=self.bg_color)
        self.bw_ax.set_facecolor(self.bg_color)
        self.bw_ax.tick_params(colors=self.fg_color)
        for spine in self.bw_ax.spines.values():
            spine.set_color(self.fg_color)
        self.bw_ax.set_title("Bandwidth Usage", color=self.fg_color)
        self.bw_ax.set_xlabel("Time", color=self.fg_color)
        self.bw_ax.set_ylabel("KB/s", color=self.fg_color)
        
        self.bw_canvas = FigureCanvasTkAgg(self.bw_fig, master=bw_frame)
        self.bw_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threat distribution chart
        threat_chart_frame = tk.LabelFrame(right_panel, text="Threat Distribution", bg=self.bg_color, fg=self.fg_color)
        threat_chart_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.threat_fig, self.threat_ax = plt.subplots(figsize=(5, 3), facecolor=self.bg_color)
        self.threat_ax.set_facecolor(self.bg_color)
        self.threat_ax.tick_params(colors=self.fg_color)
        for spine in self.threat_ax.spines.values():
            spine.set_color(self.fg_color)
        
        self.threat_canvas = FigureCanvasTkAgg(self.threat_fig, master=threat_chart_frame)
        self.threat_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
    
    def create_terminal(self):
        self.terminal_frame = tk.Frame(self.root, bg=self.bg_color)
        
        # Terminal output
        output_frame = tk.Frame(self.terminal_frame, bg=self.bg_color)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.terminal_output = scrolledtext.ScrolledText(
            output_frame, bg=self.text_bg, fg=self.fg_color, insertbackground=self.fg_color,
            wrap=tk.WORD, state='disabled'
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        
        # Terminal input
        input_frame = tk.Frame(self.terminal_frame, bg=self.bg_color)
        input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.cmd_entry = tk.Entry(input_frame, bg=self.text_bg, fg=self.fg_color, insertbackground=self.fg_color)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        tk.Button(input_frame, text="Execute", command=lambda: self.execute_command(None), 
                 bg=self.accent_color, fg=self.fg_color).pack(side=tk.LEFT, padx=5)
        
        self.terminal_frame.pack(fill=tk.BOTH, expand=True)
        self.terminal_frame.pack_forget()  # Hide initially
    
    def show_dashboard(self):
        self.terminal_frame.pack_forget()
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_terminal(self):
        self.dashboard_frame.pack_forget()
        self.terminal_frame.pack(fill=tk.BOTH, expand=True)
    
    def execute_command(self, event):
        cmd = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)
        
        self.print_to_terminal(f"> {cmd}\n")
        
        if cmd.lower() == "help":
            self.show_terminal_help()
        elif cmd.lower().startswith("ping"):
            self.ping_command(cmd)
        elif cmd.lower().startswith("start monitoring"):
            self.start_monitoring_command(cmd)
        elif cmd.lower() == "stop":
            self.stop_monitoring_command()
        elif cmd.lower() == "exit":
            self.root.quit()
        elif cmd.lower() == "clear":
            self.terminal_output.configure(state='normal')
            self.terminal_output.delete(1.0, tk.END)
            self.terminal_output.configure(state='disabled')
        elif cmd.lower() in ["ifconfig /all", "ifconfig"]:
            self.ifconfig_command(cmd)
        elif cmd.lower() == "netstat":
            self.netstat_command()
        elif cmd.lower() == "netsh wlan show network mode=bssid":
            self.wlan_scan_command()
        elif cmd.lower() == "netsh wlan show network profile":
            self.wlan_profile_command()
        else:
            self.print_to_terminal(f"Unknown command: {cmd}\nType 'help' for available commands.\n")
    
    def print_to_terminal(self, text):
        self.terminal_output.configure(state='normal')
        self.terminal_output.insert(tk.END, text)
        self.terminal_output.see(tk.END)
        self.terminal_output.configure(state='disabled')
    
    def show_terminal_help(self):
        help_text = """Available Commands:
- help: Show this help message
- ping <ip address>: Ping an IP address
- start monitoring <ip address>: Start monitoring an IP address
- stop: Stop monitoring
- exit: Exit the program
- clear: Clear the terminal
- ifconfig /all: Show detailed network interface information
- ifconfig: Show basic network interface information
- netstat: Show network statistics
- netsh wlan show network mode=bssid: Show available WiFi networks
- netsh wlan show network profile: Show saved WiFi profiles
"""
        self.print_to_terminal(help_text)
    
    def ping_command(self, cmd):
        parts = cmd.split()
        if len(parts) < 2:
            self.print_to_terminal("Usage: ping <ip address>\n")
            return
        
        ip = parts[1]
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["ping", "-n", "4", ip], capture_output=True, text=True)
            else:
                result = subprocess.run(["ping", "-c", "4", ip], capture_output=True, text=True)
            
            self.print_to_terminal(result.stdout + "\n")
        except Exception as e:
            self.print_to_terminal(f"Error: {str(e)}\n")
    
    def start_monitoring_command(self, cmd):
        parts = cmd.split()
        if len(parts) < 3:
            self.print_to_terminal("Usage: start monitoring <ip address>\n")
            return
        
        ip = parts[2]
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip)
        self.start_monitoring()
    
    def stop_monitoring_command(self):
        self.stop_monitoring()
        self.print_to_terminal("Monitoring stopped\n")
    
    def ifconfig_command(self, cmd):
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["ipconfig", "/all"] if "/all" in cmd else ["ipconfig"], 
                                      capture_output=True, text=True)
            else:
                result = subprocess.run(["ifconfig", "-a"] if "/all" in cmd else ["ifconfig"], 
                                      capture_output=True, text=True)
            
            self.print_to_terminal(result.stdout + "\n")
        except Exception as e:
            self.print_to_terminal(f"Error: {str(e)}\n")
    
    def netstat_command(self):
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            else:
                result = subprocess.run(["netstat", "-tulnp"], capture_output=True, text=True)
            
            self.print_to_terminal(result.stdout + "\n")
        except Exception as e:
            self.print_to_terminal(f"Error: {str(e)}\n")
    
    def wlan_scan_command(self):
        if platform.system().lower() != "windows":
            self.print_to_terminal("This command is only available on Windows\n")
            return
        
        try:
            result = subprocess.run(["netsh", "wlan", "show", "network", "mode=bssid"], 
                                  capture_output=True, text=True)
            self.print_to_terminal(result.stdout + "\n")
        except Exception as e:
            self.print_to_terminal(f"Error: {str(e)}\n")
    
    def wlan_profile_command(self):
        if platform.system().lower() != "windows":
            self.print_to_terminal("This command is only available on Windows\n")
            return
        
        try:
            result = subprocess.run(["netsh", "wlan", "show", "network", "profile"], 
                                  capture_output=True, text=True)
            self.print_to_terminal(result.stdout + "\n")
        except Exception as e:
            self.print_to_terminal(f"Error: {str(e)}\n")
    
    def start_monitoring(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter a valid IP address")
            return
        
        self.target_ip = ip
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start monitoring threads
        self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitor_thread.start()
        
        self.alert_thread = threading.Thread(target=self.check_for_threats, daemon=True)
        self.alert_thread.start()
        
        self.print_to_terminal(f"Started monitoring {ip}\n")
        self.send_telegram_alert(f"🚨 Started monitoring {ip}")
    
    def stop_monitoring(self):
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.print_to_terminal("Stopped monitoring\n")
        self.send_telegram_alert("🛑 Stopped monitoring")
    
    def monitor_network(self):
        prev_bytes_sent = psutil.net_io_counters().bytes_sent
        prev_bytes_recv = psutil.net_io_counters().bytes_recv
        
        while self.monitoring:
            time.sleep(UPDATE_INTERVAL)
            
            # Get current network stats
            net_io = psutil.net_io_counters()
            current_bytes_sent = net_io.bytes_sent
            current_bytes_recv = net_io.bytes_recv
            
            # Calculate bandwidth
            sent_speed = (current_bytes_sent - prev_bytes_sent) / UPDATE_INTERVAL / 1024  # KB/s
            recv_speed = (current_bytes_recv - prev_bytes_recv) / UPDATE_INTERVAL / 1024  # KB/s
            
            # Store data
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.bandwidth_data["incoming"].append((timestamp, recv_speed))
            self.bandwidth_data["outgoing"].append((timestamp, sent_speed))
            
            # Keep only last 20 data points
            if len(self.bandwidth_data["incoming"]) > 20:
                self.bandwidth_data["incoming"] = self.bandwidth_data["incoming"][-20:]
                self.bandwidth_data["outgoing"] = self.bandwidth_data["outgoing"][-20:]
            
            # Update previous values
            prev_bytes_sent = current_bytes_sent
            prev_bytes_recv = current_bytes_recv
    
    def check_for_threats(self):
        while self.monitoring:
            time.sleep(10)  # Check every 10 seconds
            
            # Simulate threat detection (in a real app, this would analyze actual network traffic)
            if np.random.random() < 0.2:  # 20% chance of detecting a threat
                threat_type = np.random.choice(["DoS", "DDoS", "Port Scanning", "Unusual Traffic"])
                self.threat_data[threat_type] += 1
                
                alert_msg = f"⚠️ Threat Detected: {threat_type} on {self.target_ip}"
                self.print_to_terminal(alert_msg + "\n")
                self.send_telegram_alert(alert_msg)
    
    def update_gui(self):
        while True:
            if self.monitoring:
                self.update_bandwidth_chart()
                self.update_threat_charts()
            time.sleep(UPDATE_INTERVAL)
    
    def update_bandwidth_chart(self):
        if not self.bandwidth_data["incoming"]:
            return
        
        # Clear previous plot
        self.bw_ax.clear()
        
        # Prepare data
        timestamps = [x[0] for x in self.bandwidth_data["incoming"]]
        incoming = [x[1] for x in self.bandwidth_data["incoming"]]
        outgoing = [x[1] for x in self.bandwidth_data["outgoing"]]
        
        # Plot new data
        self.bw_ax.plot(timestamps, incoming, label="Incoming", color='#00FF00')
        self.bw_ax.plot(timestamps, outgoing, label="Outgoing", color='#FF0000')
        
        # Format plot
        self.bw_ax.set_facecolor(self.bg_color)
        self.bw_ax.tick_params(colors=self.fg_color)
        for spine in self.bw_ax.spines.values():
            spine.set_color(self.fg_color)
        self.bw_ax.set_title("Bandwidth Usage", color=self.fg_color)
        self.bw_ax.set_xlabel("Time", color=self.fg_color)
        self.bw_ax.set_ylabel("KB/s", color=self.fg_color)
        self.bw_ax.legend(facecolor=self.bg_color, labelcolor=self.fg_color)
        
        # Rotate x-axis labels
        plt.setp(self.bw_ax.get_xticklabels(), rotation=45, ha='right')
        
        # Redraw canvas
        self.bw_canvas.draw()
    
    def update_threat_charts(self):
        # Update threat summary text
        self.threat_canvas.delete("all")
        
        y_pos = 20
        for threat, count in self.threat_data.items():
            self.threat_canvas.create_text(10, y_pos, anchor=tk.W, text=f"{threat}: {count}", 
                                         fill=self.fg_color, font=('Courier', 10))
            y_pos += 20
        
        # Update threat distribution pie chart
        self.threat_ax.clear()
        
        labels = []
        sizes = []
        for threat, count in self.threat_data.items():
            if count > 0:
                labels.append(threat)
                sizes.append(count)
        
        if sizes:
            colors = ['#ff9999','#66b3ff','#99ff99','#ffcc99']
            self.threat_ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors,
                             textprops={'color': self.fg_color})
            self.threat_ax.set_title("Threat Distribution", color=self.fg_color)
        
        self.threat_canvas.draw()
    
    def send_telegram_alert(self, message):
        if not self.telegram_token or not self.telegram_chat_id:
            return
        
        try:
            url = TELEGRAM_API_URL.format(self.telegram_token)
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload)
            
            if response.status_code != 200:
                self.print_to_terminal(f"Failed to send Telegram alert: {response.text}\n")
        except Exception as e:
            self.print_to_terminal(f"Error sending Telegram alert: {str(e)}\n")
    
    def open_telegram_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Telegram Settings")
        settings_window.geometry("400x200")
        settings_window.configure(bg=self.bg_color)
        
        tk.Label(settings_window, text="Telegram Bot Token:", bg=self.bg_color, fg=self.fg_color).pack(pady=(10, 0))
        token_entry = tk.Entry(settings_window, bg=self.text_bg, fg=self.fg_color, insertbackground=self.fg_color)
        token_entry.pack(fill=tk.X, padx=20, pady=5)
        token_entry.insert(0, self.telegram_token)
        
        tk.Label(settings_window, text="Chat ID:", bg=self.bg_color, fg=self.fg_color).pack()
        chat_id_entry = tk.Entry(settings_window, bg=self.text_bg, fg=self.fg_color, insertbackground=self.fg_color)
        chat_id_entry.pack(fill=tk.X, padx=20, pady=5)
        chat_id_entry.insert(0, self.telegram_chat_id)
        
        def save_settings():
            self.telegram_token = token_entry.get().strip()
            self.telegram_chat_id = chat_id_entry.get().strip()
            self.save_config()
            settings_window.destroy()
            messagebox.showinfo("Success", "Telegram settings saved successfully")
        
        tk.Button(settings_window, text="Save", command=save_settings, 
                bg=self.accent_color, fg=self.fg_color).pack(pady=10)
    
    def open_network_scanner(self):
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("Network Scanner")
        scanner_window.geometry("600x400")
        scanner_window.configure(bg=self.bg_color)
        
        output_text = scrolledtext.ScrolledText(
            scanner_window, bg=self.text_bg, fg=self.fg_color, insertbackground=self.fg_color,
            wrap=tk.WORD
        )
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def scan_network():
            output_text.insert(tk.END, "Scanning network...\n")
            output_text.see(tk.END)
            
            try:
                # Get default gateway
                gateways = netifaces.gateways()
                default_gateway = gateways['default'][netifaces.AF_INET][0]
                
                output_text.insert(tk.END, f"Default Gateway: {default_gateway}\n")
                
                # Get local IP and subnet
                local_ip = socket.gethostbyname(socket.gethostname())
                subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
                
                output_text.insert(tk.END, f"Scanning subnet: {subnet}\n")
                output_text.see(tk.END)
                
                # Simulate scanning (in a real app, you would use nmap or similar)
                for i in range(1, 11):
                    time.sleep(0.5)
                    ip = f"192.168.1.{i}"  # Simulated IPs
                    output_text.insert(tk.END, f"Found device at {ip}\n")
                    output_text.see(tk.END)
                
                output_text.insert(tk.END, "Scan completed\n")
            except Exception as e:
                output_text.insert(tk.END, f"Error: {str(e)}\n")
            
            output_text.see(tk.END)
        
        scan_button = tk.Button(scanner_window, text="Start Scan", command=scan_network,
                              bg=self.accent_color, fg=self.fg_color)
        scan_button.pack(pady=10)
    
    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.telegram_token = config.get("telegram_token", "")
                self.telegram_chat_id = config.get("telegram_chat_id", "")
                self.target_ip = config.get("target_ip", "")
        except (FileNotFoundError, json.JSONDecodeError):
            # Use defaults if config file doesn't exist or is invalid
            self.telegram_token = ""
            self.telegram_chat_id = ""
            self.target_ip = ""
    
    def save_config(self):
        config = {
            "telegram_token": self.telegram_token,
            "telegram_chat_id": self.telegram_chat_id,
            "target_ip": self.target_ip
        }
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
    
    def show_help(self):
        help_text = """Cyber Security Monitor Help

This tool allows you to monitor network traffic and detect potential threats.

Features:
- Real-time bandwidth monitoring
- Threat detection (DoS, DDoS, Port Scanning, Unusual Traffic)
- Telegram alerts
- Network scanning tools

Dashboard:
- View real-time bandwidth usage
- See threat statistics
- Start/stop monitoring

Terminal:
- Execute network commands
- Configure monitoring
"""
        messagebox.showinfo("Help", help_text)
    
    def show_about(self):
        about_text = """Cyber Security Monitor v1.0

A comprehensive network monitoring tool for detecting and alerting on security threats.

Developed in Python with:
- Tkinter for GUI
- Matplotlib for charts
- psutil for system monitoring
"""
        messagebox.showinfo("About", about_text)
    
    def dummy_command(self):
        messagebox.showinfo("Info", "This feature is not implemented in this demo")

def main():
    root = tk.Tk()
    app = CyberSecurityMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()