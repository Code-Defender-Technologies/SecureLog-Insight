import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import winreg
import os
import threading
import win32evtlog
import win32evtlogutil
import csv  # Import the CSV module

# Function to safely extract event strings, handling missing or incomplete data
def safe_get_event_string(event, index):
    try:
        return event.Strings[index]
    except (IndexError, AttributeError):
        return "N/A"

# Function to read Windows Event Logs
def read_event_logs(log_type='System', num_records=10, login_events_only=False, remote_sessions_only=False):
    try:
        log_handle = win32evtlog.OpenEventLog(None, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        event_logs = []

        events = win32evtlog.ReadEventLog(log_handle, flags, 0)

        for event in events:
            if len(event_logs) >= num_records:
                break
            
            if login_events_only or remote_sessions_only:
                if event.EventID & 0xFFFF == 4624:  # Successful logon
                    username = safe_get_event_string(event, 5)  # Account Name
                    event_dict = {
                        'TimeGenerated': event.TimeGenerated.Format(),
                        'SourceName': event.SourceName,
                        'EventID': event.EventID & 0xFFFF,
                        'Username': username,
                    }
                    event_logs.append(event_dict)
            else:
                event_dict = {
                    'TimeGenerated': event.TimeGenerated.Format(),
                    'SourceName': event.SourceName,
                    'EventID': event.EventID & 0xFFFF,
                    'Description': win32evtlogutil.SafeFormatMessage(event, log_type)  # Get complete description
                }
                event_logs.append(event_dict)

        win32evtlog.CloseEventLog(log_handle)
        return event_logs

    except Exception as e:
        messagebox.showerror("Error", f"Error reading {log_type} logs: {e}")
        return []

# Function to fetch logs and display in the text area
def fetch_logs():
    log_type = log_type_combobox.get()
    try:
        num_records = int(num_records_entry.get())
    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid number for records.")
        return

    login_events_only = login_events_var.get()
    remote_sessions_only = remote_sessions_var.get()

    logs = read_event_logs(log_type=log_type, num_records=num_records, login_events_only=login_events_only, remote_sessions_only=remote_sessions_only)

    log_output_text.delete(1.0, tk.END)

    if not logs:
        log_output_text.insert(tk.END, "No logs found.")
        return

    for log in logs:
        log_output_text.insert(tk.END, f"Time: {log['TimeGenerated']}\n")
        log_output_text.insert(tk.END, f"Source: {log['SourceName']}\n")
        log_output_text.insert(tk.END, f"Event ID: {log['EventID']}\n")
        if 'Username' in log:
            log_output_text.insert(tk.END, f"User: {log['Username']}\n")
        else:
            log_output_text.insert(tk.END, f"Description: {log['Description']}\n")
        log_output_text.insert(tk.END, "-" * 50 + "\n")


# Function to export logs to CSV
def export_logs():
    logs = []  # Initialize an empty list to hold the logs

    # Read the logs from the text area
    log_output = log_output_text.get(1.0, tk.END).strip().split("\n")
    if not log_output or log_output[0] == "No logs found.":
        messagebox.showwarning("Export Warning", "No logs available to export.")
        return

    for line in log_output:
        if line.startswith("Time:"):
            log_entry = {
                'TimeGenerated': line.split("Time: ")[1].strip(),
                'SourceName': '',
                'EventID': '',
                'Username': '',
                'Description': '',
            }
            logs.append(log_entry)
        elif line.startswith("Source:"):
            logs[-1]['SourceName'] = line.split("Source: ")[1].strip()
        elif line.startswith("Event ID:"):
            logs[-1]['EventID'] = line.split("Event ID: ")[1].strip()
        elif line.startswith("User:"):
            logs[-1]['Username'] = line.split("User: ")[1].strip()
        elif line.startswith("Description:"):
            logs[-1]['Description'] = line.split("Description: ")[1].strip()

    # Prompt for file save location
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                               filetypes=[("CSV files", "*.csv"),
                                                          ("All files", "*.*")])
    if not file_path:  # If user cancels the file dialog
        return

    # Write to CSV
    try:
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=['TimeGenerated', 'SourceName', 'EventID', 'Username', 'Description'])
            writer.writeheader()
            for log in logs:
                writer.writerow({
                    'TimeGenerated': log.get('TimeGenerated', 'N/A'),
                    'SourceName': log.get('SourceName', 'N/A'),
                    'EventID': log.get('EventID', 'N/A'),
                    'Username': log.get('Username', 'N/A'),
                    'Description': log.get('Description', 'N/A'),
                })
        messagebox.showinfo("Export Success", f"Logs exported successfully to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Error", f"An error occurred while exporting logs: {e}")

# Function to handle checkbox state
def handle_checkbox_change():
    if login_events_var.get() or remote_sessions_var.get():
        log_type_combobox.set("Security")
    else:
        log_type_combobox.set("System")

# Function to search for remote connection tools
def search_remote_tools():
    remote_tools_found = []
    uninstall_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    search_keywords = ["TeamViewer", "AnyDesk", "VNC", "RemotePC"]

    def check_registry_key(hive, subkey):
        try:
            registry = winreg.ConnectRegistry(None, hive)
            key = winreg.OpenKey(registry, subkey)
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = subkey + "\\" + subkey_name
                    subkey_handle = winreg.OpenKey(registry, subkey_path)
                    display_name, _ = winreg.QueryValueEx(subkey_handle, "DisplayName")
                    for keyword in search_keywords:
                        if keyword.lower() in display_name.lower():
                            remote_tools_found.append(display_name)
                except FileNotFoundError:
                    pass
        except Exception as e:
            print(f"Error reading registry: {e}")

    for uninstall_path in uninstall_paths:
        check_registry_key(winreg.HKEY_LOCAL_MACHINE, uninstall_path)

    common_paths = [r"C:\Program Files", r"C:\Program Files (x86)"]
    for path in common_paths:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for dir_name in dirs:
                    for keyword in search_keywords:
                        if keyword.lower() in dir_name.lower():
                            remote_tools_found.append(dir_name)

    log_output_text.delete(1.0, tk.END)  # Clear previous results
    if remote_tools_found:
        log_output_text.insert(tk.END, "Found remote tools:\n")
        for tool in remote_tools_found:
            log_output_text.insert(tk.END, f"- {tool}\n")
        remote_sessions_checkbox.config(state=tk.NORMAL)  # Enable checkbox if tools found
    else:
        log_output_text.insert(tk.END, "No remote tools found.")
        remote_sessions_checkbox.config(state=tk.DISABLED)  # Disable checkbox if no tools found

# Function to start remote tool search in a separate thread
def threaded_search_remote_tools():
    # Lock buttons and checkboxes
    fetch_logs_button.config(state=tk.DISABLED)
    search_remote_tools_button.config(state=tk.DISABLED)
    login_events_checkbox.config(state=tk.DISABLED)
    remote_sessions_checkbox.config(state=tk.DISABLED)

    log_output_text.delete(1.0, tk.END)  # Clear previous results
    log_output_text.insert(tk.END, "Searching for remote tools...\n")

    # Ensure the GUI updates before running the search
    root.update_idletasks()

    search_remote_tools()

    # Unlock buttons and checkboxes after search
    fetch_logs_button.config(state=tk.NORMAL)
    search_remote_tools_button.config(state=tk.NORMAL)
    login_events_checkbox.config(state=tk.NORMAL)

# Create the main window
root = tk.Tk()
root.title("SecureLog Insight")  # Updated the title to the new tool name

# Disclaimer message
# Function to show the disclaimer
def show_disclaimer():
    disclaimer_text = (
        "Disclaimer for SecureLog Insight\n\n"
        "The tool SecureLog Insight is provided \"as is,\" without any guarantees or warranties of any kind, "
        "either express or implied, including but not limited to the implied warranties of merchantability, "
        "fitness for a particular purpose, or non-infringement.\n\n"
        "By using this tool, you acknowledge and agree that:\n\n"
        "No Liability: The developer, ByteDefenders Technology, shall not be held liable for any damages, losses, "
        "or issues that may arise from the use or inability to use this tool, including but not limited to direct, "
        "indirect, incidental, punitive, and consequential damages.\n\n"
        "No Guarantees: The functionality and performance of the tool are not guaranteed. The tool may not detect "
        "all relevant logs or may provide incomplete or inaccurate information.\n\n"
        "User Responsibility: It is the user's responsibility to verify the accuracy and completeness of any "
        "information obtained through the use of this tool. Users should exercise caution and diligence in "
        "interpreting the results and applying any actions based on the findings.\n\n"
        "Compliance with Laws: Users are responsible for ensuring that their use of this tool complies with all "
        "applicable laws and regulations.\n\n"
        "By using SecureLog Insight, you agree to these terms and acknowledge that you have read and understood "
        "this disclaimer."
    )
    
    def on_accept():
        disclaimer_window.destroy()
        root.deiconify()

    def on_decline():
        disclaimer_window.destroy()
        root.quit()  # Exit the application

    disclaimer_window = tk.Toplevel(root)
    disclaimer_window.title("Disclaimer")
    disclaimer_window.geometry("600x600")    
    disclaimer_window.resizable(False, False)

    disclaimer_label = tk.Label(disclaimer_window, text=disclaimer_text, justify=tk.LEFT, wraplength=580)
    disclaimer_label.pack(pady=10, padx=10)

    accept_button = ttk.Button(disclaimer_window, text="Accept", command=on_accept)
    accept_button.pack(side=tk.LEFT, padx=20, pady=20)

    decline_button = ttk.Button(disclaimer_window, text="Decline", command=on_decline)
    decline_button.pack(side=tk.RIGHT, padx=20, pady=20)

    root.withdraw()
show_disclaimer()

# Window size and styling
root.geometry("800x800")  # Increased size for better layout
style = ttk.Style()
style.configure("TFrame", background="#F0F0F0")
style.configure("TLabel", background="#F0F0F0", font=("Arial", 12))
style.configure("TButton", padding=6, relief="flat", background="#007BFF", foreground="black")  # Change text color to black
style.configure("TButton:hover", background="#0056b3")
style.configure("TCombobox", font=("Arial", 12))

# Main frame
main_frame = ttk.Frame(root)
main_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

# Header Label
header_label = ttk.Label(main_frame, text="ByteDefenders Technology", font=("Arial", 16, "bold"))
header_label.pack(pady=(10, 20))

# Log Type Section
log_type_frame = ttk.LabelFrame(main_frame, text="Log Type Selection", padding=(10, 10))
log_type_frame.pack(fill="x", padx=10, pady=10)

log_type_label = ttk.Label(log_type_frame, text="Log Type:")
log_type_label.pack(pady=(0, 5))

log_type_combobox = ttk.Combobox(log_type_frame, values=["System", "Application", "Security"], state="readonly")
log_type_combobox.current(0)
log_type_combobox.pack(pady=(0, 10))

num_records_label = ttk.Label(log_type_frame, text="Number of Records:")
num_records_label.pack(pady=(5, 0))

num_records_entry = ttk.Entry(log_type_frame)
num_records_entry.insert(0, "10")
num_records_entry.pack(pady=(0, 10))

# Event Filters Section
event_filters_frame = ttk.LabelFrame(main_frame, text="Event Filters", padding=(10, 10))
event_filters_frame.pack(fill="x", padx=10, pady=10)

login_events_var = tk.BooleanVar()
login_events_checkbox = ttk.Checkbutton(event_filters_frame, text="Login Events Only", variable=login_events_var, command=handle_checkbox_change)
login_events_checkbox.pack(anchor='w', padx=10, pady=(0, 5))

remote_sessions_var = tk.BooleanVar()
remote_sessions_checkbox = ttk.Checkbutton(event_filters_frame, text="Remote Sessions Only (RDP, TeamViewer)", variable=remote_sessions_var, command=handle_checkbox_change)
remote_sessions_checkbox.pack(anchor='w', padx=10, pady=(0, 10))

# Action Buttons Section
action_buttons_frame = ttk.Frame(main_frame)
action_buttons_frame.pack(pady=(10, 10))

fetch_logs_button = ttk.Button(action_buttons_frame, text="Fetch Logs", command=fetch_logs)
fetch_logs_button.pack(side=tk.LEFT, padx=5)

search_remote_tools_button = ttk.Button(action_buttons_frame, text="Search for Remote Tools", command=threaded_search_remote_tools)
search_remote_tools_button.pack(side=tk.LEFT, padx=5)

export_logs_button = ttk.Button(action_buttons_frame, text="Export Logs", command=export_logs)  # New Export button
export_logs_button.pack(side=tk.LEFT, padx=5)

# Log Output Section
log_output_frame = ttk.LabelFrame(main_frame, text="Log Output", padding=(10, 10)) 
log_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

log_output_text = tk.Text(log_output_frame, wrap=tk.WORD, height=30)  # Increased height for better visibility
log_output_text.pack(expand=True, fill="both")

# Start the GUI event loop
root.mainloop()
