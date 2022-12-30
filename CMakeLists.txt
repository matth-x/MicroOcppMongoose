set(AO_MG_SRC
    src/ArduinoOcppMongooseClient_c.cpp
    src/ArduinoOcppMongooseClient.cpp
)

idf_component_register(SRCS ${AO_MG_SRC}
                       INCLUDE_DIRS "src"
                       REQUIRES mbedtls mongoose ArduinoOcpp)

target_compile_definitions(${COMPONENT_LIB} PRIVATE 
    AO_CA_CERT_USE_FILE=0)
