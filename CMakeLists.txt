# matth-x/ArduinoOcppMongoose
# Copyright Matthias Akstaller 2019 - 2023
# MIT License

cmake_minimum_required(VERSION 3.15)

set(AO_MG_SRC
    src/ArduinoOcppMongooseClient_c.cpp
    src/ArduinoOcppMongooseClient.cpp
    src/FtpClient.cpp
)

if(ESP_PLATFORM)

    idf_component_register(SRCS ${AO_MG_SRC}
                        INCLUDE_DIRS "src"
                        REQUIRES esp_timer mbedtls mongoose ArduinoOcpp)

    target_compile_definitions(${COMPONENT_LIB} PRIVATE 
        )

    return()
endif()

add_library(ArduinoOcppMongoose ${AO_MG_SRC})

target_include_directories(ArduinoOcppMongoose PUBLIC
                            "./src"
                            "../mongoose"
                            )

target_compile_definitions(ArduinoOcppMongoose PRIVATE
    )

target_link_libraries(ArduinoOcppMongoose PUBLIC ArduinoOcpp)
