cmake_minimum_required(VERSION 3.15...4.00)
project(main LANGUAGES C)
set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/main)
set(PHDRS ${CMAKE_CURRENT_SOURCE_DIR}/src/include)
set(DEPS ${CMAKE_CURRENT_SOURCE_DIR}/vendors)
add_subdirectory(${DEPS}/ptools ${DEPS}/ptools/build)
add_executable(main 
        ${SRC}/pilot.c
        ${SRC}/parse.c
        ${SRC}/print.c)
target_include_directories(main PRIVATE ${PHDRS})
target_link_libraries(main ptools)