set(fcgid_SRCS
    fcgi_header.c
    fcgi.c
    main.c
   )

add_executable(fcgid ${fcgid_SRCS})
target_link_libraries(fcgid phenom ssl)

install(TARGETS fcgid DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
