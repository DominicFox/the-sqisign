if (ENABLE_SIGN)

    # NIST KAT generation apps
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        add_executable(PQCgenKAT_sign_${SVARIANT_LOWER} PQCgenKAT_sign.c)
        target_link_libraries(PQCgenKAT_sign_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_test_nistapi)
        target_include_directories(PQCgenKAT_sign_${SVARIANT_LOWER} PRIVATE ../include)
        target_compile_definitions(PQCgenKAT_sign_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
    endforeach()

    # pqm4 KAT generation apps
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        add_executable(PQCgenKAT_sign_pqm4_${SVARIANT_LOWER} PQCgenKAT_sign_pqm4.c)
        target_link_libraries(PQCgenKAT_sign_pqm4_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_test_nistapi)
        target_include_directories(PQCgenKAT_sign_pqm4_${SVARIANT_LOWER} PRIVATE ../include)
        target_compile_definitions(PQCgenKAT_sign_pqm4_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
    endforeach()

    # Examples with NIST API
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        add_executable(example_nistapi_${SVARIANT_LOWER} example_nistapi.c)
        target_link_libraries(example_nistapi_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi)
        target_include_directories(example_nistapi_${SVARIANT_LOWER} PRIVATE ../include ../src/${SVARIANT_LOWER})
        target_compile_definitions(example_nistapi_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
        add_test(sqisign_test_nistapi_${SVARIANT_LOWER} example_nistapi_${SVARIANT_LOWER})
    endforeach()

    # Benchmarking tool - 19/6 - Added _test_nistapi rather than just _nistapi to use their randomness generator for reproducibility (MIGHT BE SLOWER)
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        add_executable(benchmark_${SVARIANT_LOWER} benchmark.c)
        target_link_libraries(benchmark_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi) 
        target_include_directories(benchmark_${SVARIANT_LOWER} PRIVATE ../include ../src/common/generic/include)
        target_compile_definitions(benchmark_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})

        # Added 19/6 Slow deterministic randomness - terminal output
        add_executable(benchmark_det_${SVARIANT_LOWER} benchmark.c)
        target_link_libraries(benchmark_det_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_test_nistapi) 
        target_include_directories(benchmark_det_${SVARIANT_LOWER} PRIVATE ../include ../src/common/generic/include)
        target_compile_definitions(benchmark_det_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})

        # Added 19/6 Fast non-deterministic randomness - binary output
        add_executable(benchmark_binary_${SVARIANT_LOWER} benchmark_binary.c)
        target_link_libraries(benchmark_binary_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi) 
        target_include_directories(benchmark_binary_${SVARIANT_LOWER} PRIVATE ../include ../src/common/generic/include)
        target_compile_definitions(benchmark_binary_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})

        # Added 16/6 - Output binary benchmark tool for telemetry data collection
        # 19/6 - Added _test_nistapi rather than just _nistapi to use their randomness generator for reproducibility
        # Slow deterministic output - binary output
        add_executable(benchmark_binary_det_${SVARIANT_LOWER} benchmark_binary.c)
        target_link_libraries(benchmark_binary_det_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_test_nistapi)
        target_include_directories(benchmark_binary_det_${SVARIANT_LOWER} PRIVATE ../include ../src/common/generic/include)
        target_compile_definitions(benchmark_binary_det_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
    endforeach()

    # Stack high-water probe -- links exactly as benchmark_binary so the
    # measured code is the same code the timing sweep measures (LTO included).
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        add_executable(stack_probe_${SVARIANT_LOWER} stack_probe.c)
        target_link_libraries(stack_probe_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi)
        target_include_directories(stack_probe_${SVARIANT_LOWER} PRIVATE ../include ../src/common/generic/include)
        target_compile_definitions(stack_probe_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
    endforeach()

    # Fuzzing tool -- signature generation
    foreach(SVARIANT ${SVARIANT_S})
        string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
        add_executable(fuzz_sign_${SVARIANT_LOWER} fuzz_sign.c)
        target_link_libraries(fuzz_sign_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi)
        target_include_directories(fuzz_sign_${SVARIANT_LOWER} PRIVATE ../include)
        target_compile_definitions(fuzz_sign_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
    endforeach()

endif()

# Fuzzing tool -- signature verification
foreach(SVARIANT ${SVARIANT_S})
    string(TOLOWER ${SVARIANT} SVARIANT_LOWER)
    add_executable(fuzz_verify_${SVARIANT_LOWER} fuzz_verify.c)
    target_link_libraries(fuzz_verify_${SVARIANT_LOWER} PRIVATE sqisign_${SVARIANT_LOWER}_nistapi)
    target_include_directories(fuzz_verify_${SVARIANT_LOWER} PRIVATE ../include ../src/precomp/ref/${SVARIANT_LOWER}/include)
    target_compile_definitions(fuzz_verify_${SVARIANT_LOWER} PUBLIC SQISIGN_VARIANT=${SVARIANT_LOWER})
endforeach()
