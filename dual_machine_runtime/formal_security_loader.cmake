include("${CMAKE_CURRENT_LIST_DIR}/formal_security_capability.cmake")
if(NOT DEFINED VFDUAL_FORMAL_SECURITY_IMPLEMENTED OR
        NOT "${VFDUAL_FORMAL_SECURITY_IMPLEMENTED}" MATCHES "^(ON|OFF)$")
    message(FATAL_ERROR "Formal security capability must be exactly ON or OFF")
endif()
if(VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY AND
        NOT VFDUAL_FORMAL_SECURITY_IMPLEMENTED)
    message(FATAL_ERROR
        "Formal secure data plane is not implemented; refusing to build a release candidate")
endif()
set(VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT
    "visionforge-formal-security-loader-v1"
    CACHE INTERNAL "Executed formal security loader contract" FORCE)
