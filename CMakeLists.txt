cmake_minimum_required(VERSION 3.10)

project(MyCppProject)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 设置 vcpkg 的工具链文件，用于集成 vcpkg 管理的库
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "/vcpkg/scripts/buildsystems/vcpkg.cmake")
endif()

# 设置 vcpkg 的路径
set(VCPKG_DIR "/vcpkg")

# 添加 vcpkg 的 include 和 library 路径
include_directories(${VCPKG_DIR}/installed/x64-linux/include)
link_directories(${VCPKG_DIR}/installed/x64-linux/lib)

# 查找并加载必要的库
#find_package(cpprestsdk CONFIG REQUIRED)
#find_package(libssh CONFIG REQUIRED)
find_package(cpprestsdk REQUIRED)
find_package(libssh REQUIRED)
find_package(ICU REQUIRED COMPONENTS uc i18n io data)
find_package(SQLite3 REQUIRED)

# 输出调试信息
message(STATUS "cpprest_INCLUDE_DIRS: ${cpprest_INCLUDE_DIRS}")
message(STATUS "LIBSSH_INCLUDE_DIRS: ${LIBSSH_INCLUDE_DIRS}")
message(STATUS "LIBSSH_LIBRARIES: ${LIBSSH_LIBRARIES}")
message(STATUS "ICU_INCLUDE_DIRS: ${ICU_INCLUDE_DIRS}")
message(STATUS "ICU_LIBRARIES: ${ICU_LIBRARIES}")
message(STATUS "ICU_DATA: ${ICU_DATA}")

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/database
    ${CMAKE_SOURCE_DIR}/utils
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/scan
    ${cpprest_INCLUDE_DIRS}
    ${LIBSSH_INCLUDE_DIRS}
    ${ICU_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
)

set(SOURCES
    Command_Excute.cpp
    convert_string_t.cpp
    database/DatabaseManager.cpp
    database/db.cpp
    Login.cpp
    main_1.cpp
    main.cpp
    Padding.cpp
    utils/utils.cpp
    scan/portScan.cpp
    scan/utils_scan.cpp
    ServerManager.cpp
)

set(HEADERS
    Command_Excute.h
    convert_string_t.h
    database/DatabaseManager.h
    database/db_config.h
    database/db.h
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
)

add_executable(MyCppProject ${SOURCES} ${HEADERS})

target_link_libraries(MyCppProject PRIVATE 
    cpprestsdk::cpprest 
    ssh
    ${ICU_LIBRARIES}
    ${SQLite3_LIBRARIES}
)


