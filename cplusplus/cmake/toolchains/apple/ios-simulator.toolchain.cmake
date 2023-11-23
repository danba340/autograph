set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_OSX_SYSROOT "iphonesimulator")

set(CMAKE_OSX_DEPLOYMENT_TARGET
    "16.0"
    CACHE STRING "Minimum iOS deployment target")
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -arch ${CMAKE_OSX_ARCHITECTURES} -mios-simulator-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}"
)
set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -arch ${CMAKE_OSX_ARCHITECTURES} -mios-simulator-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}"
)
set(CMAKE_XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET
    "${CMAKE_OSX_DEPLOYMENT_TARGET}")

set(CMAKE_XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2")

set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_C_ARCHIVE_FINISH
    "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
set(CMAKE_CXX_ARCHIVE_FINISH
    "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
