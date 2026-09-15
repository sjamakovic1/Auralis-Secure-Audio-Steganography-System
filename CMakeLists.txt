cmake_minimum_required(VERSION 3.20)

project(StegoWAV LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(stegowav_core STATIC
    src/wav/WavReader.cpp
    src/wav/WavWriter.cpp
    src/audio/PcmBuffer.cpp
    src/payload/PayloadCodec.cpp
    src/steganography/LsbSteganography.cpp
    src/application/EmbedService.cpp
    src/application/ExtractService.cpp
    src/crypto/bigint/BigInteger.cpp
    src/crypto/random/SecureRandom.cpp
    src/crypto/prime/MillerRabin.cpp
    src/crypto/prime/PrimeGenerator.cpp
    src/crypto/rsa/RsaKeyGenerator.cpp
    src/crypto/rsa/RsaPrimitive.cpp
    src/crypto/rsa/RsaConversion.cpp
    src/crypto/hash/Sha256.cpp
    src/crypto/mgf/Mgf1.cpp
    src/crypto/oaep/OaepCodec.cpp
    src/crypto/rsa/RsaOaep.cpp
    src/crypto/aes/Aes256.cpp
    src/crypto/padding/Pkcs7.cpp
    src/crypto/aes/Aes256Cbc.cpp
    src/crypto/hybrid/HybridCipher.cpp
    src/crypto/hybrid/HybridPackageCodec.cpp
    src/crypto/rsa/RsaKeyCodec.cpp
    src/crypto/rsa/RsaKeyFile.cpp
)

target_include_directories(stegowav_core PUBLIC include)

add_executable(stegowav src/main.cpp)
target_link_libraries(stegowav PRIVATE stegowav_core)

if(WIN32)
    target_link_libraries(stegowav_core PUBLIC bcrypt)

    add_executable(stegowav_gui WIN32
        src/gui/GuiMain.cpp
        src/gui/MainWindow.cpp
        src/gui/KeyGenerationDialog.cpp
        src/gui/Settings.cpp
        src/gui/Theme.cpp
    )
    set_target_properties(stegowav_gui PROPERTIES OUTPUT_NAME Auralis)
    target_compile_definitions(stegowav_gui PRIVATE UNICODE _UNICODE)
    target_link_libraries(stegowav_gui PRIVATE stegowav_core comdlg32 comctl32)
    if(MINGW)
        target_link_options(stegowav_gui PRIVATE -municode -static)
    endif()
endif()
