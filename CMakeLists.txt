set(AO_MG_SRC
    src/AOcppMongooseClient_c.cpp
    src/AOcppMongooseClient.cpp
)

idf_component_register(SRCS ${AO_MG_SRC}
                       INCLUDE_DIRS "src")

target_compile_definitions(${COMPONENT_LIB} PRIVATE 
    AO_CA_CERT_USE_FILE=0)
