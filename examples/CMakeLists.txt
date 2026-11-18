add_executable(sdc_demo sdc_demo.c)
target_link_libraries(sdc_demo PRIVATE sdc)

foreach(ex sdc_providers sdc_hashsum sdc_filecrypt sdc_seal sdc_signtool sdc_kex_demo)
  add_executable(${ex} ${ex}.c)
  target_link_libraries(${ex} PRIVATE sdc)
endforeach()
