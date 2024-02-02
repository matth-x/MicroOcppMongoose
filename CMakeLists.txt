# matth-x/MicroOcppMongoose
# Copyright Matthias Akstaller 2019 - 2023
# MIT License

cmake_minimum_required(VERSION 3.15)

set(MO_MG_SRC
    src/MicroOcppMongooseClient_c.cpp
    src/MicroOcppMongooseClient.cpp
)

if(ESP_PLATFORM)

    idf_component_register(SRCS ${MO_MG_SRC}
                        INCLUDE_DIRS "src"
                        REQUIRES esp_timer mbedtls mongoose MicroOcpp)

    target_compile_definitions(${COMPONENT_LIB} PRIVATE 
        )

    return()
endif()

add_library(MicroOcppMongoose ${MO_MG_SRC})

target_include_directories(MicroOcppMongoose PUBLIC
                            "./src"
                            "../mongoose"
                            )

target_compile_definitions(MicroOcppMongoose PRIVATE
)

target_link_libraries(MicroOcppMongoose PUBLIC MicroOcpp)
