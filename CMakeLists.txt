# 指定所需的最低 CMake 版本
cmake_minimum_required(VERSION 3.10)

# 定义项目名称
project(MyCppProject)

# 设置 C++ 标准为 C++14，并且强制要求支持该标准
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 设置 vcpkg 的工具链文件，用于集成 vcpkg 管理的库
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "/vcpkg/scripts/buildsystems/vcpkg.cmake")
endif()

# 查找并加载必要的库
find_package(cpprestsdk REQUIRED)
find_package(libssh REQUIRED)
find_package(ICU REQUIRED COMPONENTS uc i18n io data)
find_package(SQLite3 REQUIRED)

# 输出调试信息
message(STATUS "LIBSSH_INCLUDE_DIRS: ${LIBSSH_INCLUDE_DIRS}")
message(STATUS "LIBSSH_LIBRARIES: ${LIBSSH_LIBRARIES}")
message(STATUS "ICU_INCLUDE_DIRS: ${ICU_INCLUDE_DIRS}")
message(STATUS "ICU_LIBRARIES: ${ICU_LIBRARIES}")
message(STATUS "ICU_DATA: ${ICU_DATA}")

# 将 include 目录添加到编译器的搜索路径中
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/database
    ${CMAKE_SOURCE_DIR}/utils
    ${LIBSSH_INCLUDE_DIRS}  # 添加 libssh 头文件目录
    ${ICU_INCLUDE_DIRS}     # 添加 icu 头文件目录
    ${SQLite3_INCLUDE_DIRS} # 添加 sqlite3 头文件目录
)

# 设置源文件列表
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
)

# 设置头文件列表（可选）
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
)

# 添加可执行文件 MyCppProject，并包含所有源文件和头文件
add_executable(MyCppProject ${SOURCES} ${HEADERS})

# 将 cpprestsdk、libssh、ICU 和 SQLite3 库链接到 MyCppProject 可执行文件
target_link_libraries(MyCppProject PRIVATE 
    cpprestsdk::cpprest 
    ssh  # 指定 libssh 库
    ${ICU_LIBRARIES}      # 添加 icu 库链接
    ${SQLite3_LIBRARIES}  # 添加 sqlite3 库链接
)
