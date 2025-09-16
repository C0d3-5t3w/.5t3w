#!/usr/bin/env python3
"""
5T3W Terminal User Interface (TUI)
A rich terminal interface for the 5t3w WiFi monitoring and attack tool
"""

import json
import os
import time
import threading
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich import box
from rich.columns import Columns

class WiFiMonitorTUI:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.running = False
        self.stats = {
            "packets_captured": 0,
            "stations_detected": 0,
            "aps_detected": 0,
            "scans_completed": 0,
            "attacks_executed": 0,
            "vulnerabilities_found": 0,
            "start_time": datetime.now()
        }
        self.active_operations = []
        self.log_messages = []
        self.max_log_messages = 15
        self.discovered_targets = {"stations": set(), "aps": set()}
        
    def setup_layout(self):
        """Setup the TUI layout with panels"""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1)
        )
        
        self.layout["left"].split_column(
            Layout(name="stats", size=10),
            Layout(name="operations", ratio=1)
        )
        
        self.layout["right"].split_column(
            Layout(name="targets", ratio=1),
            Layout(name="logs", ratio=1)
        )

    def create_header(self) -> Panel:
        """Create the header panel"""
        uptime = datetime.now() - self.stats["start_time"]
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds
        
        title = Text("🔐 5T3W - WiFi Security Testing Framework", style="bold cyan")
        subtitle = Text(f"⏱️  Uptime: {uptime_str} | 🚀 Active Operations: {len(self.active_operations)}", style="dim")
        
        header_content = Align.center(
            Text.assemble(title, "\n", subtitle)
        )
        
        return Panel(
            header_content,
            style="bright_blue",
            box=box.ROUNDED
        )

    def create_stats_panel(self) -> Panel:
        """Create the statistics panel"""
        stats_table = Table(show_header=False, box=None, padding=(0, 1))
        stats_table.add_column("Metric", style="cyan", width=20)
        stats_table.add_column("Value", style="bright_green", width=10)
        
        stats_table.add_row("📡 Packets", str(self.stats["packets_captured"]))
        stats_table.add_row("📱 Stations", str(self.stats["stations_detected"]))
        stats_table.add_row("📶 Access Points", str(self.stats["aps_detected"]))
        stats_table.add_row("🔍 Port Scans", str(self.stats["scans_completed"]))
        stats_table.add_row("⚔️  Attacks", str(self.stats["attacks_executed"]))
        stats_table.add_row("🚨 Vulns Found", str(self.stats["vulnerabilities_found"]))
        
        return Panel(
            stats_table,
            title="📊 Live Statistics",
            border_style="green",
            box=box.ROUNDED
        )

    def create_operations_panel(self) -> Panel:
        """Create the active operations panel"""
        if not self.active_operations:
            content = Text("🟢 System Idle", style="green")
        else:
            lines = []
            for op in self.active_operations[-6:]:  # Show last 6 operations
                status_icon = "🔄" if op['status'] == "Running" else "✅" if op['status'] == "Completed" else "❌"
                lines.append(f"{status_icon} {op['name']}")
                lines.append(f"   └─ {op['status']}")
            content = "\n".join(lines)
        
        return Panel(
            content,
            title="⚙️  Operations Status",
            border_style="yellow",
            box=box.ROUNDED
        )

    def create_targets_panel(self) -> Panel:
        """Create the discovered targets panel"""
        targets_table = Table(box=box.SIMPLE, show_header=True)
        targets_table.add_column("Type", style="cyan", width=8)
        targets_table.add_column("MAC Address", style="bright_white", width=17)
        targets_table.add_column("Status", style="green", width=10)
        
        # Add recent APs
        recent_aps = list(self.discovered_targets["aps"])[-8:]
        for ap in recent_aps:
            targets_table.add_row("📶 AP", ap, "Active")
        
        # Add recent stations
        recent_stations = list(self.discovered_targets["stations"])[-8:]
        for station in recent_stations:
            targets_table.add_row("📱 STA", station, "Active")
        
        if targets_table.row_count == 0:
            content = Text("🔍 Scanning for targets...", style="dim")
            return Panel(content, title="🎯 WiFi Targets", border_style="blue")
        
        return Panel(
            targets_table,
            title=f"🎯 WiFi Targets ({targets_table.row_count})",
            border_style="blue",
            box=box.ROUNDED
        )

    def create_logs_panel(self) -> Panel:
        """Create the logs panel"""
        if not self.log_messages:
            content = Text("📝 Waiting for activity...", style="dim")
        else:
            log_lines = []
            for log in self.log_messages[-self.max_log_messages:]:
                timestamp = log.get("timestamp", "")[-8:]  # HH:MM:SS
                level = log.get("level", "INFO")
                message = log.get("message", "")[:50]  # Truncate long messages
                
                # Icons and colors by level
                if level == "ERROR":
                    icon, style = "❌", "red"
                elif level == "WARNING":
                    icon, style = "⚠️ ", "yellow"
                elif level == "SUCCESS":
                    icon, style = "✅", "green"
                elif level == "ATTACK":
                    icon, style = "⚔️ ", "bold red"
                elif level == "SCAN":
                    icon, style = "🔍", "blue"
                else:
                    icon, style = "ℹ️ ", "white"
                
                log_lines.append(
                    Text.assemble(
                        (f"[{timestamp}] ", "dim"),
                        (f"{icon} ", style),
                        (message, "white")
                    )
                )
            
            content = Text("\n").join(log_lines)
        
        return Panel(
            content,
            title="📋 Activity Log",
            border_style="magenta",
            box=box.ROUNDED
        )

    def create_footer(self) -> Panel:
        """Create the footer panel"""
        controls = [
            "[bold red]CTRL+C[/] Exit",
            "[bold green]S[/] Scan", 
            "[bold blue]A[/] Attack",
            "[bold yellow]V[/] Vuln Scan",
            "[bold cyan]R[/] Report"
        ]
        
        footer_content = Align.center(" | ".join(controls))
        
        return Panel(
            footer_content,
            style="bright_black",
            box=box.ROUNDED
        )

    def add_log_message(self, level: str, message: str):
        """Add a log message"""
        self.log_messages.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })
        
        # Keep only recent messages
        if len(self.log_messages) > self.max_log_messages * 2:
            self.log_messages = self.log_messages[-self.max_log_messages:]

    def add_operation(self, name: str, status: str = "Running"):
        """Add an active operation"""
        self.active_operations.append({
            "name": name,
            "status": status,
            "started": datetime.now().isoformat()
        })

    def update_operation_status(self, name: str, status: str):
        """Update an operation's status"""
        for op in self.active_operations:
            if op["name"] == name:
                op["status"] = status
                break

    def simulate_activity(self):
        """Simulate WiFi monitoring activity for demo"""
        # Simulate packet capture
        self.stats["packets_captured"] += random.randint(5, 20)
        
        # Simulate target discovery
        if random.random() < 0.3:  # 30% chance
            mac_types = ["AP", "Station"]
            mac_type = random.choice(mac_types)
            fake_mac = f"02:00:00:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
            
            if mac_type == "AP":
                self.discovered_targets["aps"].add(fake_mac)
                self.stats["aps_detected"] = len(self.discovered_targets["aps"])
                self.add_log_message("INFO", f"New AP detected: {fake_mac}")
            else:
                self.discovered_targets["stations"].add(fake_mac)
                self.stats["stations_detected"] = len(self.discovered_targets["stations"])
                self.add_log_message("INFO", f"New station: {fake_mac}")
        
        # Simulate operations
        if len(self.active_operations) < 3 and random.random() < 0.1:  # 10% chance
            operations = [
                ("Port Scan", "SCAN"),
                ("Vulnerability Assessment", "SCAN"), 
                ("Deauth Attack", "ATTACK"),
                ("Association Flood", "ATTACK")
            ]
            op_name, op_type = random.choice(operations)
            self.add_operation(op_name)
            self.add_log_message(op_type, f"Started {op_name}")
            
            # Schedule completion
            def complete_op():
                time.sleep(random.uniform(2, 8))
                self.update_operation_status(op_name, "Completed")
                self.add_log_message("SUCCESS", f"Completed {op_name}")
                if op_type == "SCAN":
                    self.stats["scans_completed"] += 1
                elif op_type == "ATTACK":
                    self.stats["attacks_executed"] += 1
                    self.stats["vulnerabilities_found"] += random.randint(0, 3)
            
            threading.Thread(target=complete_op, daemon=True).start()

    def update_display(self):
        """Update all display panels"""
        self.simulate_activity()
        
        self.layout["header"].update(self.create_header())
        self.layout["stats"].update(self.create_stats_panel())
        self.layout["operations"].update(self.create_operations_panel())
        self.layout["targets"].update(self.create_targets_panel())
        self.layout["logs"].update(self.create_logs_panel())
        self.layout["footer"].update(self.create_footer())

    def run(self):
        """Run the TUI main loop"""
        self.setup_layout()
        self.running = True
        
        self.add_log_message("INFO", "5T3W TUI interface started")
        self.add_log_message("INFO", "WiFi monitoring system online")
        
        try:
            with Live(self.layout, refresh_per_second=1, screen=True) as live:
                while self.running:
                    self.update_display()
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            self.add_log_message("INFO", "Shutdown requested by user")
            self.running = False

def create_interactive_menu():
    """Create an interactive menu for TUI mode selection"""
    console = Console()
    
    console.print()
    console.print(Panel.fit(
        "[bold cyan]🔐 5T3W - WiFi Security Testing Framework[/]\n"
        "[dim]Terminal User Interface Selection[/]",
        border_style="cyan"
    ), justify="center")
    console.print()
    
    options = [
        ("1", "🖥️  Live Dashboard", "Real-time monitoring interface"),
        ("2", "📊 Quick Stats", "Display current statistics"),
        ("3", "🎯 Target List", "Show discovered WiFi targets"),
        ("4", "📋 Activity Log", "View recent system activity"),
        ("5", "⚙️  System Info", "Display system information"),
        ("q", "🚪 Exit", "Return to command line")
    ]
    
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    table.add_column("Choice", style="bold cyan", width=8)
    table.add_column("Option", style="bright_white", width=25)
    table.add_column("Description", style="dim", width=35)
    
    for choice, option, description in options:
        table.add_row(choice, option, description)
    
    console.print(table, justify="center")
    console.print()
    
    while True:
        choice = console.input("[bold cyan]Select option[/]: ").strip().lower()
        
        if choice in ["1", "2", "3", "4", "5", "q"]:
            return choice
        else:
            console.print("[red]Invalid choice. Please enter 1-5 or q.[/]")

def display_quick_stats():
    """Display quick statistics view"""
    console = Console()
    
    # Try to import main module stats
    try:
        from main import stations, access_points, packets_buffer
        stations_count = len(stations) if stations else 0
        aps_count = len(access_points) if access_points else 0
        packets_count = len(packets_buffer) if packets_buffer else 0
    except:
        stations_count = 0
        aps_count = 0 
        packets_count = 0
    
    stats_table = Table(title="📊 5T3W Current Statistics", box=box.DOUBLE_EDGE)
    stats_table.add_column("Metric", style="cyan", width=25)
    stats_table.add_column("Count", style="bright_green", width=15)
    stats_table.add_column("Status", style="yellow", width=20)
    
    stats_table.add_row("📱 Stations Detected", str(stations_count), "🟢 Active" if stations_count > 0 else "🔴 None")
    stats_table.add_row("📶 Access Points", str(aps_count), "🟢 Active" if aps_count > 0 else "🔴 None")
    stats_table.add_row("📡 Packets Captured", str(packets_count), "📈 Current Session")
    stats_table.add_row("🔍 Port Scans", "0", "💤 Idle")
    stats_table.add_row("🚨 Vulnerabilities", "0", "💤 No Scans Yet")
    
    console.print()
    console.print(stats_table, justify="center")
    console.print()
    console.print("[dim]Press Enter to continue...[/]", justify="center")
    input()

def display_targets():
    """Display discovered targets"""
    console = Console()
    
    # Try to get real targets
    try:
        from main import stations, access_points
        real_stations = list(stations) if stations else []
        real_aps = list(access_points) if access_points else []
    except:
        real_stations = []
        real_aps = []
    
    targets_table = Table(title="🎯 Discovered WiFi Targets", box=box.DOUBLE_EDGE)
    targets_table.add_column("Type", style="cyan", width=15)
    targets_table.add_column("MAC Address", style="bright_white", width=20)
    targets_table.add_column("Status", style="green", width=15)
    targets_table.add_column("Notes", style="dim", width=20)
    
    current_time = datetime.now().strftime("%H:%M:%S")
    
    for ap in real_aps:
        if ap and ap != "Unknown":
            targets_table.add_row("📶 Access Point", ap, "🟢 Active", f"Detected {current_time}")
    
    for station in real_stations:
        if station and station != "Unknown":
            targets_table.add_row("📱 Station", station, "🟢 Active", f"Detected {current_time}")
    
    console.print()
    if targets_table.row_count == 0:
        console.print(Panel(
            "[yellow]🔍 No targets discovered yet.[/]\n"
            "[dim]Start WiFi monitoring to detect devices.[/]",
            title="Target Discovery",
            border_style="yellow"
        ), justify="center")
    else:
        console.print(targets_table, justify="center")
    
    console.print()
    console.print("[dim]Press Enter to continue...[/]", justify="center")
    input()

def display_system_info():
    """Display system information"""
    console = Console()
    
    import platform
    import psutil
    
    info_table = Table(title="⚙️  System Information", box=box.DOUBLE_EDGE)
    info_table.add_column("Component", style="cyan", width=20)
    info_table.add_column("Details", style="bright_white", width=40)
    
    info_table.add_row("🖥️  Platform", f"{platform.system()} {platform.release()}")
    info_table.add_row("🐍 Python", platform.python_version())
    info_table.add_row("💾 Memory", f"{psutil.virtual_memory().percent:.1f}% used")
    info_table.add_row("💽 CPU", f"{psutil.cpu_percent(interval=1):.1f}% usage")
    info_table.add_row("📂 Working Dir", os.getcwd())
    info_table.add_row("👤 User", os.getenv("USER", "Unknown"))
    
    console.print()
    console.print(info_table, justify="center")
    console.print()
    console.print("[dim]Press Enter to continue...[/]", justify="center")
    input()

def run_tui_dashboard():
    """Run the full TUI dashboard"""
    tui = WiFiMonitorTUI()
    tui.run()

def main_tui():
    """Main TUI entry point"""
    console = Console()
    
    try:
        while True:
            choice = create_interactive_menu()
            
            if choice == "1":
                console.print("[green]🚀 Starting live dashboard...[/]")
                time.sleep(1)
                run_tui_dashboard()
                break
            elif choice == "2":
                display_quick_stats()
            elif choice == "3":
                display_targets()
            elif choice == "4":
                console.print("[yellow]📋 Activity log feature coming soon![/]")
                time.sleep(2)
            elif choice == "5":
                display_system_info()
            elif choice == "q":
                console.print("[cyan]👋 Goodbye![/]")
                break
                
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  TUI interrupted by user[/]")
    except Exception as e:
        console.print(f"\n[red]❌ TUI error: {e}[/]")

if __name__ == "__main__":
    main_tui()
