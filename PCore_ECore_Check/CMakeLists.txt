# CMakeList.txt : PCore_ECore_Check の CMake プロジェクト。ソースを含めて、次を定義します:
# プロジェクト専用ロジックはこちらです。
#

# ソースをこのプロジェクトの実行可能ファイルに追加します。
add_executable (PCore_ECore_Check "PCore_ECore_Check.cpp" "PCore_ECore_Check.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET PCore_ECore_Check PROPERTY CXX_STANDARD 20)
endif()

# Find the Ole32 library
find_library(OLE32_LIBRARY Ole32)
find_library(WBEMUUID_LIBRARY wbemuuid)

# Link against the Ole32 library
target_link_libraries(PCore_ECore_Check PRIVATE ${OLE32_LIBRARY})
target_link_libraries(PCore_ECore_Check PRIVATE ${WBEMUUID_LIBRARY})