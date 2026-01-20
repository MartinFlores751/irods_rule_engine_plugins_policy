# include all cmake files for rule engine plugins for this repository
include(irods_dev_policy_composition_framework.cmake)

if (BUILD_AND_PACKAGE_EXAMPLE)
  include(example/policy_engine_example.cmake)
endif()
