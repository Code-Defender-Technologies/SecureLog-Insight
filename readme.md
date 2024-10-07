# SecureLog Insight

**SecureLog Insight** is a Windows-based tool designed to help IT administrators perform security audits by fetching and analyzing Windows Event Logs. The tool supports filtering login events, searching for remote connection tools, and exporting logs in CSV format for further analysis.

## Features

- **Fetch Windows Event Logs**: Retrieve logs from the Application, Security, or System event logs.
- **Filter Events**: Option to filter only successful login events or remote session logs.
- **Search for Remote Tools**: Detect remote access tools like TeamViewer, AnyDesk, VNC, and RemotePC installed on the system.
- **Export Logs to CSV**: Save fetched event logs to a CSV file for analysis and record-keeping.

## Prerequisites

- **Python 3.x**
- **Tkinter**: Used for the graphical user interface.
- **PyWin32**: Required for accessing Windows Event Logs.

  Install it using:

  ```bash
  pip install pywin32
