foreach(t test_api test_kat)
  add_executable(${t} ${t}.c)
  target_link_libraries(${t} PRIVATE sdc_static)
  add_test(NAME ${t} COMMAND ${t})
  # Tests choose providers explicitly; don't let the caller's env change that.
  set_tests_properties(${t} PROPERTIES ENVIRONMENT "SDC_PROVIDER=")
endforeach()
