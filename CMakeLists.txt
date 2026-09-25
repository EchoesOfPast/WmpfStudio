cmake_minimum_required(VERSION 3.20)
set(FZWY_VERSION "0.1.0" CACHE STRING "App version")
project(WmpfStudio VERSION ${FZWY_VERSION} LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets Network WebSockets)

# WMPF offset tables, embedded as Qt resources.
set(WMPF_OFFSET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/res/wmpf-offsets/win32")
file(GLOB WMPF_OFFSET_FILES "${WMPF_OFFSET_DIR}/addresses.*.json")
list(SORT WMPF_OFFSET_FILES)
list(LENGTH WMPF_OFFSET_FILES WMPF_OFFSET_COUNT)
set(_wmpf_qrc "<RCC>\n  <qresource prefix=\"/wmpf-offsets/win32\">\n")
foreach(_f ${WMPF_OFFSET_FILES})
    get_filename_component(_fn "${_f}" NAME)
    file(RELATIVE_PATH _rel "${CMAKE_CURRENT_BINARY_DIR}" "${_f}")
    string(APPEND _wmpf_qrc "    <file alias=\"${_fn}\">${_rel}</file>\n")
endforeach()
string(APPEND _wmpf_qrc "  </qresource>\n</RCC>\n")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wmpf_offsets.qrc" "${_wmpf_qrc}")
message(STATUS "WMPF offset tables: ${WMPF_OFFSET_COUNT} versions embedded")

# Hook DLL injected into the WeChat process.
# Two hard constraints (violating either causes LoadLibrary to fail):
#  1. Must statically link MinGW runtime: the target process (WeChat)
#     does not have libstdc++-6.dll / libgcc_s_seh-1.dll / libwinpthread-1.dll.
#  2. No Qt in this DLL: the WeChat process has no Qt6Core.dll.
add_library(FzwyHook SHARED
    src/wmpf/hook/FzwyHook.cpp
    src/wmpf/x64len.cpp
)
set_target_properties(FzwyHook PROPERTIES
    OUTPUT_NAME "FzwyHook"
    PREFIX ""                 # MinGW adds a "lib" prefix by default; strip it
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
target_include_directories(FzwyHook PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/wmpf")
target_link_options(FzwyHook PRIVATE -static -static-libgcc -static-libstdc++)
target_link_libraries(FzwyHook PRIVATE bcrypt)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(FzwyHook PRIVATE -s)
    add_link_options(-s)
endif()

set(WMPF_SOURCES
    src/wmpf/x64len.h
    src/wmpf/x64len.cpp
    src/wmpf/WmpfOffsets.h
    src/wmpf/WmpfOffsets.cpp
    src/wmpf/WmpfProbe.h
    src/wmpf/WmpfProbe.cpp
    src/wmpf/WmpfInject.h
    src/wmpf/WmpfInject.cpp
    src/wmpf/WarRemoteDebug.h
    src/wmpf/WarRemoteDebug.cpp
    src/wmpf/WmpfChannel.h
    src/wmpf/WmpfChannel.cpp
    src/wmpf/WmpfSession.h
    src/wmpf/WmpfSession.cpp
)

add_executable(WmpfStudio WIN32
    src/studio/main.cpp
    src/studio/StudioWindow.h
    src/studio/StudioWindow.cpp
    src/CdpClient.h
    src/CdpClient.cpp
    src/Config.h
    src/Config.cpp
    src/JobThread.h
    src/WxPkg.h
    src/WxPkg.cpp
    ${WMPF_SOURCES}
    res/app.qrc
    ${CMAKE_CURRENT_BINARY_DIR}/wmpf_offsets.qrc
)
add_dependencies(WmpfStudio FzwyHook)
set_target_properties(WmpfStudio PROPERTIES
    OUTPUT_NAME "WmpfStudio"
    WIN32_EXECUTABLE TRUE
)
target_link_libraries(WmpfStudio PRIVATE
    Qt6::Widgets
    Qt6::Network
    Qt6::WebSockets
    bcrypt
)

# Deploy: Qt6 runtime + MinGW runtime.
get_target_property(_qmake_exe Qt6::qmake IMPORTED_LOCATION)
get_filename_component(_qt_bin "${_qmake_exe}" DIRECTORY)
get_filename_component(_mingw_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)

find_program(WINDEPLOYQT_EXE NAMES windeployqt windeployqt6
             HINTS "${_qt_bin}" NO_DEFAULT_PATH)
if(NOT WINDEPLOYQT_EXE)
    find_program(WINDEPLOYQT_EXE NAMES windeployqt windeployqt6)
endif()

set(DEPLOY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dist/WmpfStudio")

if(WINDEPLOYQT_EXE)
    add_custom_target(deploy
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${DEPLOY_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "$<TARGET_FILE:WmpfStudio>" "${DEPLOY_DIR}/WmpfStudio.exe"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "$<TARGET_FILE:FzwyHook>" "${DEPLOY_DIR}/FzwyHook.dll"
        COMMAND "${WINDEPLOYQT_EXE}"
                --release --no-compiler-runtime --no-system-d3d-compiler
                --no-opengl-sw --no-quick-import --no-translations
                --skip-plugin-types qmltooling,designer
                --dir "${DEPLOY_DIR}" "${DEPLOY_DIR}/WmpfStudio.exe"
        COMMAND "${CMAKE_COMMAND}" -E remove_directory "${DEPLOY_DIR}/translations"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "${_mingw_bin}/libgcc_s_seh-1.dll"
                "${_mingw_bin}/libstdc++-6.dll"
                "${_mingw_bin}/libwinpthread-1.dll"
                "${DEPLOY_DIR}/"
        DEPENDS WmpfStudio FzwyHook
        COMMENT "Deploy to ${DEPLOY_DIR} (Qt6 + MinGW runtime + hook DLL)"
        VERBATIM
    )
else()
    message(WARNING "windeployqt not found, skipping deploy target")
endif()
