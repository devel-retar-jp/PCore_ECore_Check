# CMakeList.txt : isPrime の CMake プロジェクト。ソースを含めて、次を定義します:
# プロジェクト専用ロジックはこちらです。
#

# ソースをこのプロジェクトの実行可能ファイルに追加します。
add_executable (isPrime "isPrime.cpp" "isPrime.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET isPrime PROPERTY CXX_STANDARD 20)
endif()

# TODO: テストを追加し、必要な場合は、ターゲットをインストールします。

# Find the Ole32 library
#find_library(OLE32_LIBRARY Ole32)
#find_library(WBEMUUID_LIBRARY wbemuuid)

# Link against the Ole32 library
#target_link_libraries(PCore_ECore_Check PRIVATE ${OLE32_LIBRARY})
#target_link_libraries(PCore_ECore_Check PRIVATE ${WBEMUUID_LIBRARY})