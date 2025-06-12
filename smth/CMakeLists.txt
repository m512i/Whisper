cmake_minimum_required(VERSION 3.10)
project(cleany)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(cleany
    main.c
    cleany.c
)

target_link_libraries(cleany
    ntdll
) 