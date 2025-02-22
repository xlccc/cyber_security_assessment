cmake_minimum_required(VERSION 3.10)

project(MyCppProject)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 设置 vcpkg 的工具链文件，用于集成 vcpkg 管理的库
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "/home/c/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# 设置 vcpkg 的路径
set(VCPKG_DIR "/home/c/vcpkg")

# 添加 vcpkg 的 include 和 library 路径
include_directories(${VCPKG_DIR}/installed/x64-linux/include)
link_directories(${VCPKG_DIR}/installed/x64-linux/lib)

# 查找并加载必要的库
find_package(cpprestsdk CONFIG REQUIRED)
find_package(libssh CONFIG REQUIRED)
find_package(ICU REQUIRED COMPONENTS uc i18n io data)
find_package(SQLite3 REQUIRED)
find_package(uchardet CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(hiredis CONFIG REQUIRED)

# 添加 MySQL Connector/C++
find_package(unofficial-mysql-connector-cpp CONFIG REQUIRED)


# 手动设置Python路径
set(Python_EXECUTABLE "/usr/bin/python3.8")
set(Python_ROOT_DIR "/usr")
set(Python_INCLUDE_DIR "/usr/include/python3.8")
set(Python_LIBRARY "/usr/lib/x86_64-linux-gnu/libpython3.8.so")

find_package(Python 3.8 COMPONENTS Interpreter Development REQUIRED)

# 输出调试信息
message(STATUS "cpprest_INCLUDE_DIRS: ${cpprestsdk_INCLUDE_DIRS}")
message(STATUS "LIBSSH_INCLUDE_DIRS: ${libssh_INCLUDE_DIRS}")
message(STATUS "LIBSSH_LIBRARIES: ${libssh_LIBRARIES}")
message(STATUS "ICU_INCLUDE_DIRS: ${ICU_INCLUDE_DIRS}")
message(STATUS "ICU_LIBRARIES: ${ICU_LIBRARIES}")
message(STATUS "ICU_DATA: ${ICU_DATA}")
message(STATUS "SQLite3_INCLUDE_DIRS: ${SQLite3_INCLUDE_DIRS}")
message(STATUS "SQLite3_LIBRARIES: ${SQLite3_LIBRARIES}")
message(STATUS "Python_VERSION: ${Python_VERSION}")
message(STATUS "Python_INCLUDE_DIRS: ${Python_INCLUDE_DIRS}")
message(STATUS "Python_LIBRARIES: ${Python_LIBRARIES}")

# 包含目录
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/database
    ${CMAKE_SOURCE_DIR}/utils
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/scan
    ${cpprestsdk_INCLUDE_DIRS}
    ${libssh_INCLUDE_DIRS}
    ${ICU_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
    ${Python_INCLUDE_DIRS}
)

# 设置源文件和头文件
set(SOURCES
    Command_Excute.cpp
    convert_string_t.cpp
    database/DatabaseManager.cpp
    Login.cpp
    main_1.cpp
    main.cpp
    Padding.cpp
    utils/utils.cpp
    scan/portScan.cpp
    scan/utils_scan.cpp
    ServerManager.cpp
    scan/poc_check.cpp
    database/db_config.cpp
    "database/DatabaseHandler.cpp"
    scan/hostDiscovery.cpp
    utils/threadPool.cpp)
 "database/DatabaseHandler.cpp" "run/mysql_scan.cpp")

set(HEADERS
    Command_Excute.h
    convert_string_t.h
    database/DatabaseManager.h
    database/db_config.h
    database/poc.h
    Event.h
    Event_h.h
    Login.h
    Padding.h
    utils/utils.h
    scan/portScan.h
    scan/scan_struct.h
    scan/utils_scan.h
    ServerManager.h
    scan/poc_check.h
    "scan/config.h"
    "database/DatabaseHandler.h" "database/mysql_connection_pool.h"
    scan/config.h 
    scan/hostDiscovery.h
    utils/threadPool.h)
    scan/config.h
 "database/DatabaseHandler.h" "database/mysql_connection_pool.h"
    multipart_form_data.h "run/mysql_scan.h")

# 添加可执行文件
add_executable(MyCppProject ${SOURCES} ${HEADERS})

# 链接必要的库到 C++ 项目
target_link_libraries(MyCppProject PRIVATE 
    cpprestsdk::cpprest 
    cpprestsdk::cpprestsdk_zlib_internal
    cpprestsdk::cpprestsdk_boost_internal
    cpprestsdk::cpprestsdk_openssl_internal
    ssh
    ${ICU_LIBRARIES}
    ${SQLite3_LIBRARIES}
    ${Python_LIBRARIES}
    uchardet::libuchardet
    unofficial::mysql-connector-cpp::connector  # 修正了此行
    resolv  # 确保添加这一行
    nlohmann_json::nlohmann_json
    hiredis::hiredis)

# 支持 Unicode 文件名和路径
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finput-charset=UTF-8 -fexec-charset=UTF-8")
