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

- **CSV Module:** Included in Python by default, used to export logs to CSV.

## Installation

Follow these steps to set up SecureLog Insight:

Clone the repository:

```bash
git clone https://github.com/Code-Defender-Technologies/SecureLog-Insight.git
```

Navigate to the project directory:

```bash
cd SecureLogInsight
```
Install the necessary dependencies:


```bash
pip install -r requirements.txt
```
Run the application:

```bash
python securelog_insight.py
```


## Usage

### Log Retrieval

1. Select Log Type: Choose between Application, Security, or System logs from the dropdown.
2. Set Number of Records: Specify the number of event logs to retrieve.
3. Apply Event Filters:

 - **Login Events Only:** Check this to filter only successful login events.
 - **Remote Sessions Only:** Check this to filter remote session logs (e.g., RDP, TeamViewer).

### Searching for Remote Tools

Click the "Search for Remote Tools" button to scan the system for remote access software like TeamViewer, AnyDesk, VNC, or RemotePC. Results will be displayed in the log output area.

### Export Logs
After fetching the logs, you can export them to a CSV file by clicking the "Export Logs to CSV" button. The logs will be saved in a format compatible with most SIEM systems for further analysis.

### Error Handling
If no logs are found, the tool will display a "No logs found" message.
If invalid input is entered for the number of records, an error message will be displayed.
If the log output is empty, exporting will be disabled to prevent empty files from being created.

## CSV Export
The exported logs will be saved in a CSV format with the following structure:

TimeGenerated: The time when the event occurred.
SourceName: The source of the event (e.g., system component).
EventID: The unique identifier for the event.
Description: A detailed description of the event (or user information for login events).
The CSV can be easily imported into SIEM systems for further security analysis and monitoring.

## License
This project is licensed under the MIT License. See the LICENSE file for details.






