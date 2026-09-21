foreach(t test_api test_kat test_interop test_encoding)
  add_executable(${t} ${t}.c)
  target_link_libraries(${t} PRIVATE sdc_static)
  add_test(NAME ${t} COMMAND ${t})
  # Tests choose providers explicitly; don't let the caller's env change that.
  set_tests_properties(${t} PROPERTIES ENVIRONMENT "SDC_PROVIDER=")
endforeach()

# Same application code, backend chosen purely by environment.
if(SDC_BUILD_EXAMPLES)
  foreach(p ${SDC_PROVIDERS})
    add_test(NAME example_${p} COMMAND sdc_demo)
    set_tests_properties(example_${p} PROPERTIES ENVIRONMENT "SDC_PROVIDER=${p}")
  endforeach()
endif()
