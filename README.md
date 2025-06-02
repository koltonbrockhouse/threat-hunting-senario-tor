<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/koltonbrockhouse/threat-hunting-senario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Analysis of the `DeviceFileEvents` table revealed user `kolton` downloaded a Tor installer. Subsequent activity included copying numerous Tor-related files to the desktop and creating a file named `tor-shopping-list.txt` in the same location. The initial search targeted files containing the string `tor`.
These events began at: `2025-06-02T17:12:50.2942182Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "koltonproject2"
| where FileName contains "tor"
| order by Timestamp desc
| where InitiatingProcessAccountName == "kolton"
| where Timestamp >= datetime(2025-06-02T17:12:50.2942182Z)
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/8e461cf5-a46b-47b7-b904-9b37f43a394f)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-14.5.3.exe`.. Based on the logs returned, At `2025-06-02T17:14:22.8073816Z`, a user named `kolton` on the device `koltonproject2` launched the Tor Browser from their Downloads folder. The specific file executed was `tor-browser-windows-x86_64-portable-14.5.3.exe`, and it was run with the `/S` command-line argument, likely indicating a silent or unattended extraction/installation process.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "koltonproject2"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/84832c51-213c-4882-be62-8ae2531ea7fb)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

User `kolton` launched the Tor browser, as indicated by entries in the `DeviceProcessEvents` table at `2025-06-02T17:15:13.2531223Z`. Following this, multiple instances of `firefox.exe` (associated with Tor) and `tor.exe` were subsequently initiated.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/d1e940e8-15e7-4400-a0e2-ebba37f30627)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

An investigation of the `DeviceNetworkEvents` table revealed Tor browser usage for establishing connections via known ports. At, `2025-06-02T17:16:15.0874854Z`, user `kolton` on device `koltonproject2` unsuccessfully connected from `tor.exe` to the remote IP address `31.14.252.98` on port `9001`, but the attempt to connect was made.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "koltonproject2"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```
![image](https://github.com/user-attachments/assets/62b4661d-5bb8-48c9-ba8d-8505f91cf1f5)

---

## Timeline of Events:

-   **Timestamp:** `2025-06-02T17:12:50.2942182Z`
    -   **Event:** On `koltonproject2`, user `kolton` initiated file activities related to Tor, including downloading a Tor installer, copying numerous Tor-related files to the desktop, and creating a file named `tor-shopping-list.txt`.
    -   **Action:** File download, copy, and creation detected.
    -   **File Path:** Multiple Tor-related files in `Downloads` and `Desktop`, including `tor-shopping-list.txt`.

-   **Timestamp:** `2025-06-02T17:14:22.8073816Z`
    -   **Event:** On `koltonproject2`, user `kolton` launched the Tor Browser executable `tor-browser-windows-x86_64-portable-14.5.3.exe` from their Downloads folder with the `/S` command-line argument.
    -   **Action:** Process created (Tor Browser executable launch).
    -   **File Path:** `C:\Users\kolton\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

-   **Timestamp:** `2025-06-02T17:15:13.2531223Z`
    -   **Event:** On `koltonproject2`, user `kolton` directly launched the Tor browser, which subsequently initiated multiple associated processes, including `firefox.exe` and `tor.exe`.
    -   **Action:** Process creation (Tor Browser and associated processes).
    -   **File Path:** Not applicable (multiple processes initiated: `firefox.exe`, `tor.exe`).

-   **Timestamp:** `2025-06-02T17:15:48.0000000Z`
    -   **Event:** On `koltonproject2`, user `kolton`'s `firefox.exe` successfully established a local connection to `127.0.0.1` on port `9150`.
    -   **Action:** Network connection succeeded.
    -   **File Path:** `firefox.exe` (initiating process).

-   **Timestamp:** `2025-06-02T17:16:15.0874854Z`
    -   **Event:** On `koltonproject2`, user `kolton`'s `tor.exe` attempted an unsuccessful connection to the remote IP address `31.14.252.98` on port `9001`.
    -   **Action:** Network connection attempted (unsuccessful).
    -   **File Path:** `tor.exe` (initiating process).

## Summary of Events:

On June 2, 2025, user `kolton` on the device `koltonproject2` engaged in activities related to the Tor Browser. This began with the download and file-related actions of a Tor installer, followed by the execution of the Tor Browser executable. Subsequently, the Tor browser and its associated processes (`firefox.exe` and `tor.exe`) were launched. A successful local connection was observed from `firefox.exe` to `127.0.0.1` on port `9150`, indicating the Tor browser's local proxy was active. Finally, `tor.exe` attempted an external connection to `31.14.252.98` on port `9001`, which was reported as unsuccessful.

---

## Response Taken

TOR usage was confirmed on endpoint `koltonproject2` by the user `Kolton`. The device was isolated and the user's direct manager was notified.

---
