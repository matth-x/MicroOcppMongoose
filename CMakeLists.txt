# matth-x/ArduinoOcppMongoose
# Copyright Matthias Akstaller 2019 - 2023
# MIT License

cmake_minimum_required(VERSION 3.15)

set(AO_MG_SRC
    src/ArduinoOcppMongooseClient_c.cpp
    src/ArduinoOcppMongooseClient.cpp
)

if(ESP_PLATFORM)

    idf_component_register(SRCS ${AO_MG_SRC}
                        INCLUDE_DIRS "src"
                        REQUIRES mbedtls mongoose ArduinoOcpp)

    target_compile_definitions(${COMPONENT_LIB} PRIVATE 
        AO_CA_CERT_USE_FILE=0)

    return()
endif()

add_library(ArduinoOcppMongoose ${AO_MG_SRC})

target_include_directories(ArduinoOcppMongoose PUBLIC
                            "./src"
                            "../mongoose"
                            )

target_compile_definitions(ArduinoOcppMongoose PRIVATE
    AO_CA_CERT_USE_FILE=0
    )

target_link_libraries(ArduinoOcppMongoose PUBLIC ArduinoOcpp)
