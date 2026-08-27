# NIST KAT generation apps
foreach(SVARIANT ${SVARIANT_S})
    string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
    add_executable(PQCgenKAT_sign_${SVARIANT_LOWER} PQCgenKAT_sign.c)
    target_link_libraries(PQCgenKAT_sign_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_test_nistapi)
    target_include_directories(PQCgenKAT_sign_${SVARIANT_LOWER} PRIVATE ../include)
endforeach()

# Examples with NIST API
foreach(SVARIANT ${SVARIANT_S})
    string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
    add_executable(example_nistapi_${SVARIANT_LOWER} example_nistapi.c)
    target_link_libraries(example_nistapi_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi)
    target_include_directories(example_nistapi_${SVARIANT_LOWER} PRIVATE ../include ../src/${SVARIANT_LOWER})
endforeach()

# Benchmarking tool 
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        # Added 19/6 Fast non-deterministic randomness - binary output
        add_executable(benchmark_binary_${SVARIANT_LOWER} benchmark_binary.c)
        target_link_libraries(benchmark_binary_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi)
        target_include_directories(benchmark_binary_${SVARIANT_LOWER} PRIVATE ../include ../src/common/generic/include)
        target_compile_definitions(benchmark_binary_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
    endforeach()

# Stack high-water probe -- links exactly as benchmark_binary so the measured
# code is the same code the timing sweep measures.
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        add_executable(stack_probe_${SVARIANT_LOWER} stack_probe.c)
        target_link_libraries(stack_probe_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi)
        target_include_directories(stack_probe_${SVARIANT_LOWER} PRIVATE ../include ../src/common/generic/include)
        target_compile_definitions(stack_probe_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
    endforeach()