cmake_minimum_required(VERSION 3.12)

project("Mosquitto OTP Plugin")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb")

add_library(mosq_otp_plugin SHARED src/main.c)
add_executable(mosq_otp_client src/sample_auth_client.c)
add_executable(mosq_otp_client_v2 src/sample_auth_client_v2.c)
add_executable(puf_test src/puf_testing.c)
target_link_libraries(mosq_otp_plugin mosquitto cotp cjson sqlite3)
target_link_libraries(mosq_otp_client mosquitto cotp cjson)
target_link_libraries(mosq_otp_client_v2 mosquitto cotp cjson)
target_link_libraries(puf_test cotp cjson)
# add_executable(mosq_otp_plugin src/main.c)
