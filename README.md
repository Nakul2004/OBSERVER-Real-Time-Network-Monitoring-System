# OBSERVER-Real-Time-Network-Monitoring-System

## 🌟 Project Overview

**TrafficAnalyzer** is a high-performance, cross-platform tool designed for deep, real-time monitoring and analysis of local network traffic. Built using C++ for speed, it provides granular visibility into network activity, focusing on **per-device usage**, **protocol distribution**, and **Layer 7 (Domain) identification**.

The system utilizes a multi-threaded architecture, delivering live statistics to a modern, interactive **React.js** dashboard via **WebSockets**.

The continuous growth of network complexity requires sophisticated tools for granular, device-level monitoring and analysis. This project, **TrafficAnalyzer v2.0**, addresses this by developing a high-performance, cross-platform application capable of capturing, dissecting, aggregating, and visualizing live network packet data, specifically focusing on **per-device usage and domain visibility**.

The system is built on **C++** for performance, utilizes **Npcap/WinPcap** for raw packet capture, and features an expanded dissection layer to extract **MAC addresses, ports, and (where feasible) visited domains (L7 data)**. The backend uses the **Crow** C++ web framework for **REST API** access and **WebSockets** for live data streaming, logging all data to a **SQLite** database. The visualization layer is a modern, responsive **React.js dashboard** powered by Tailwind CSS. The core function is to provide immediate, actionable insights into network utilization and security status.


## ✨ Key Features

* **Granular Packet Capture:** Captures and extracts detailed network metadata, including **IP Address, MAC Address, Transport Ports**, and estimated **Domain (L7)** data.
* **Per-Device Aggregation:** Automatically groups and summarizes traffic usage based on unique **Device (IP/MAC)** pairs.
* **Intelligent Adapter Selection:** Automatically detects and selects the most active Ethernet or Wi-Fi network interface for sniffing.
* **Dual Backend API:** Uses a **WebSocket** server for low-latency, real-time dashboard updates and a **REST API** endpoint for accessing historical log data.
* **Persistent Logging:** Logs all detailed packet metadata into a lightweight **SQLite** database.
* **Modern React Dashboard:** Provides interactive visualization and filters (by device, time, and protocol).
* **Actionable Interface:** Includes UI elements to simulate triggering **alerts** for high usage and options to **flag/block** suspicious device traffic.


## Technology Stack / Platform Specification (Development & Deployment)

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend Core** | **C++17/20** | High-performance packet dissection and aggregation. |
| **Build System** | **CMake** | Cross-platform build configuration and dependency management. |
| **Dependencies** | **vcpkg** | Manages C++ libraries (Crow, SQLite3). |
| **Packet Capture** | **Npcap / WinPcap** | Raw packet data acquisition (requires Admin rights). |
| **Web Server** | **Crow C++ Web Framework** | REST API and WebSocket server implementation. |
| **Database** | **SQLite3** | Lightweight, file-based, thread-safe persistent logging. |
| **Frontend** | **React.js** | Interactive, component-based dashboard logic. |


## 🛠️ Setup and Build Instructions

Follow these steps precisely to set up the environment and build the executable (`TrafficAnalyzer.exe`).

### Prerequisites (Install These First)

1.  **C++ Compiler (Visual Studio):** Install **Visual Studio Community** edition. Select the workload: **`Desktop development with C++`**.
2.  **CMake:** Download and install CMake. **Check the option: `Add CMake to the system PATH for all users`**.
3.  **Npcap Drivers:** Download and install the official Npcap installer. **Check the box: `Install Npcap in WinPcap API-compatible Mode`**.
4.  **vcpkg Tool:**
    * Create a folder: `C:\Dev`.
    * Download the **vcpkg repository ZIP** from GitHub.
    * Unzip the vcpkg folder into `C:\Dev`, resulting in: `C:\Dev\vcpkg`.

### Build Steps (Using Command Prompt)

Follow these steps in an **Administrator Command Prompt**.


```bash
# 1a. Build the vcpkg tool itself
C:\Dev\vcpkg\bootstrap-vcpkg.bat

# 1b. Install the project dependencies
C:\Dev\vcpkg\vcpkg install crow sqlite3 nlohmann-json

# 2a. Go to the project directory
cd C:\Dev\TrafficAnalyzer

# 2b. Run CMake to configure the build (This automatically creates the 'build' folder)
# NOTE: Replace C:/Dev/vcpkg with your actual vcpkg path if different.
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake

# 2c. Build the project using the configuration (creates the .exe file)
cmake --build build --config Release

cd C:\Dev\TrafficAnalyzer\build\Release
TrafficAnalyzer.exe
http://localhost:8080/frontend/index.html
