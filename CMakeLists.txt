cmake_minimum_required(VERSION 3.16)

project(TrafficAnalyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ----------------------------------------------------------------------------
# Dependencies (Found via vcpkg or system)
# ----------------------------------------------------------------------------

find_package(nlohmann_json CONFIG REQUIRED)
set(NLOHMANN_JSON_TARGET nlohmann_json::nlohmann_json)

find_package(Crow CONFIG REQUIRED)
set(CROW_TARGET Crow::Crow)

find_package(unofficial-sqlite3 CONFIG REQUIRED)
set(SQLITE_TARGET unofficial::sqlite3::sqlite3)

# Source files
set(SOURCE_FILES
    src/main.cpp
    src/Analyzer.cpp
    src/Database.cpp
)

add_executable(TrafficAnalyzer ${SOURCE_FILES})
target_include_directories(TrafficAnalyzer PRIVATE src)

# Link dependency libs
target_link_libraries(TrafficAnalyzer PRIVATE
    ${SQLITE_TARGET}
    ${CROW_TARGET}
    ${NLOHMANN_JSON_TARGET}
)

# --- Find Npcap SDK (Windows-Only) ---
# Set the path to your extracted Npcap SDK
set(NPCAP_SDK_PATH "C:/NPCAP_DIR")

message(STATUS "Searching for Npcap SDK in: ${NPCAP_SDK_PATH}")

# Windows: search for Npcap in user-specified path, common locations, + env vars
find_path(PCAP_INCLUDE_DIR pcap.h
    PATHS
        "${NPCAP_SDK_PATH}/Include"             # User-specified path
        $ENV{NPCAP_DIR}/Include                # Environment variable
        "C:/Npcap/Include"                     # Default Npcap install
        "C:/Program Files/Npcap SDK/Include"   # Default Npcap SDK install
        $ENV{WPCAP_DIR}/Include                # Fallback for old WinPcap
)

find_library(WPCAP_LIB NAMES wpcap WinPcap
    PATHS
        "${NPCAP_SDK_PATH}/Lib/x64"            # User-specified path (64-bit)
        "${NPCAP_SDK_PATH}/Lib"               # User-specified path (32-bit)
        $ENV{NPCAP_DIR}/Lib/x64
        $ENV{NPCAP_DIR}/Lib
        "C:/Npcap/Lib/x64"
        "C:/Npcap/Lib"
        "C:/Program Files/Npcap SDK/Lib/x64"
        "C:/Program Files/Npcap SDK/Lib"
        $ENV{WPCAP_DIR}/Lib
)

find_library(PACKET_LIB NAMES Packet
    PATHS
        "${NPCAP_SDK_PATH}/Lib/x64"            # User-specified path (64-bit)
        "${NPCAP_SDK_PATH}/Lib"               # User-specified path (32-bit)
        $ENV{NPCAP_DIR}/Lib/x64
        $ENV{NPCAP_DIR}/Lib
        "C:/Npcap/Lib/x64"
        "C:/Npcap/Lib"
        "C:/Program Files/Npcap SDK/Lib/x64"
        "C:/Program Files/Npcap SDK/Lib"
        $ENV{WPCAP_DIR}/Lib
)

# Check if libraries were found and link them
if(PCAP_INCLUDE_DIR AND WPCAP_LIB)
    message(STATUS "Found Npcap Include: ${PCAP_INCLUDE_DIR}")
    message(STATUS "Found wpcap.lib: ${WPCAP_LIB}")

    target_include_directories(TrafficAnalyzer PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(TrafficAnalyzer PRIVATE ${WPCAP_LIB})

    if(PACKET_LIB)
        message(STATUS "Found Packet.lib: ${PACKET_LIB}")
        target_link_libraries(TrafficAnalyzer PRIVATE ${PACKET_LIB})
    else()
        message(WARNING "Could not find Packet.lib. Linking may fail.")
        # Note: Npcap SDK 1.10+ may not require linking Packet.lib explicitly
    endif()

else()
    message(FATAL_ERROR
        "Npcap/WinPcap not found.\n"
        "Searched in: ${NPCAP_SDK_PATH}, $ENV{NPCAP_DIR}, and default locations.\n"
        "Ensure the path is correct and contains:\n"
        "  - Include: pcap.h\n"
        "  - Lib: wpcap.lib and Packet.lib\n"
    )
endif()

# ----------------------------------------------------------------------------
# Post-Build: Copy Frontend (optional)
# ----------------------------------------------------------------------------

if(EXISTS ${CMAKE_SOURCE_DIR}/frontend/index.html)
    add_custom_command(TARGET TrafficAnalyzer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            $<TARGET_FILE_DIR:TrafficAnalyzer>/frontend
    )
    add_custom_command(TARGET TrafficAnalyzer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/frontend/index.html
            $<TARGET_FILE_DIR:TrafficAnalyzer>/frontend/index.html
    )
endif()
