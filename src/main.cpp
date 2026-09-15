#include "stegowav/application/EmbedService.hpp"
#include "stegowav/application/ExtractService.hpp"
#include "stegowav/crypto/bigint/BigInteger.hpp"
#include "stegowav/crypto/rsa/RsaKeyFile.hpp"
#include "stegowav/crypto/rsa/RsaKeyGenerator.hpp"
#include "stegowav/wav/WavReader.hpp"
#include "stegowav/wav/WavWriter.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

void printUsage()
{
    std::cout
        << "StegoWAV\n\n"
        << "Usage:\n"
        << "  stegowav generate-keys <modulusBits> <publicExponent> "
           "<publicKeyFile> <privateKeyFile>\n"
        << "  stegowav embed <inputWav> <outputWav> <publicKeyFile> <message>\n"
        << "  stegowav embed-file <inputWav> <outputWav> <publicKeyFile> <messageFile>\n"
        << "  stegowav extract <inputWav> <privateKeyFile>\n"
        << "  stegowav extract-file <inputWav> <privateKeyFile> <outputMessageFile>\n\n"
        << "Commands:\n"
        << "  generate-keys   Generate an RSA key pair.\n"
        << "  embed           Encrypt and hide a message inside a WAV file.\n"
        << "  embed-file      Encrypt and hide the complete contents of a message file.\n"
        << "  extract         Extract and decrypt a message from a WAV file.\n"
        << "  extract-file    Extract and decrypt a message into a binary file.\n";
}

template<typename UnsignedInteger>
UnsignedInteger parseUnsigned(std::string_view text, const char* errorMessage)
{
    UnsignedInteger value{};
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto result = std::from_chars(begin, end, value, 10);
    if (text.empty()
        || result.ec != std::errc{}
        || result.ptr != end) {
        throw std::invalid_argument(errorMessage);
    }
    return value;
}

std::vector<std::byte> stringToBytes(std::string_view text)
{
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char character : text) {
        bytes.push_back(static_cast<std::byte>(
            static_cast<unsigned char>(character)));
    }
    return bytes;
}

std::string bytesToString(const std::vector<std::byte>& bytes)
{
    std::string text;
    text.reserve(bytes.size());
    for (const std::byte byte : bytes) {
        text.push_back(static_cast<char>(
            std::to_integer<unsigned char>(byte)));
    }
    return text;
}

void runGenerateKeys(char* argv[])
{
    const std::size_t modulusBits = parseUnsigned<std::size_t>(
        argv[2], "Invalid RSA modulus bit length.");
    if (modulusBits == 0) {
        throw std::invalid_argument("Invalid RSA modulus bit length.");
    }

    const std::uint64_t exponentValue = parseUnsigned<std::uint64_t>(
        argv[3], "Invalid RSA public exponent.");
    const stegowav::crypto::bigint::BigInteger publicExponent{exponentValue};
    const std::filesystem::path publicKeyPath(argv[4]);
    const std::filesystem::path privateKeyPath(argv[5]);

    const auto keyPair = stegowav::crypto::rsa::RsaKeyGenerator::generate(
        modulusBits, publicExponent);
    stegowav::crypto::rsa::RsaKeyFile::savePublic(
        publicKeyPath, keyPair.publicKey());
    stegowav::crypto::rsa::RsaKeyFile::savePrivate(
        privateKeyPath, keyPair.privateKey());

    std::cout << "RSA key pair generated successfully.\n"
              << "Public key:  " << publicKeyPath.string() << '\n'
              << "Private key: " << privateKeyPath.string() << '\n';
}

std::vector<std::byte> readMessageFile(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open message file: " + path.string());
    }

    std::vector<std::byte> bytes;
    std::array<std::byte, 65536> buffer;
    for (;;) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + file.gcount());
        if (file.bad() || (file.fail() && !file.eof())) {
            throw std::runtime_error("Could not read message file: " + path.string());
        }
        if (file.eof()) break;
    }
    return bytes;
}

void runEmbed(char* argv[], bool fromFile)
{
    const std::filesystem::path inputWavPath(argv[2]);
    const std::filesystem::path outputWavPath(argv[3]);
    const std::filesystem::path publicKeyPath(argv[4]);
    const auto message = fromFile
        ? readMessageFile(std::filesystem::path(argv[5]))
        : stringToBytes(argv[5]);

    const auto publicKey = stegowav::crypto::rsa::RsaKeyFile::loadPublic(
        publicKeyPath);
    const stegowav::wav::WavReader reader;
    auto wavFile = reader.read(inputWavPath);

    stegowav::application::EmbedService::embed(
        wavFile, message, publicKey);

    const stegowav::wav::WavWriter writer;
    writer.write(wavFile, outputWavPath);

    std::cout << "Message encrypted and embedded successfully.\n"
              << "Output WAV: " << outputWavPath.string() << '\n';
}

void writeMessageFile(const std::filesystem::path& path,
                      const std::vector<std::byte>& bytes)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw std::runtime_error("Could not open output message file: " + path.string());
    }
    for (std::size_t offset = 0; offset < bytes.size();) {
        const auto count = std::min<std::size_t>(65536, bytes.size() - offset);
        file.write(reinterpret_cast<const char*>(bytes.data() + offset),
                   static_cast<std::streamsize>(count));
        if (!file) {
            throw std::runtime_error("Could not write output message file: " + path.string());
        }
        offset += count;
    }
    file.close();
    if (!file) {
        throw std::runtime_error("Could not finish writing output message file: " + path.string());
    }
}

void runExtract(char* argv[], bool toFile)
{
    const std::filesystem::path inputWavPath(argv[2]);
    const std::filesystem::path privateKeyPath(argv[3]);

    const auto privateKey = stegowav::crypto::rsa::RsaKeyFile::loadPrivate(
        privateKeyPath);
    const stegowav::wav::WavReader reader;
    auto wavFile = reader.read(inputWavPath);

    const auto plaintext = stegowav::application::ExtractService::extract(
        wavFile, privateKey);
    if (toFile) {
        const std::filesystem::path outputMessagePath(argv[4]);
        writeMessageFile(outputMessagePath, plaintext);
        std::cout << "Message extracted and decrypted successfully.\n"
                  << "Output message file: " << outputMessagePath.string() << '\n';
    } else {
        std::cout << "Message:\n" << bytesToString(plaintext) << '\n';
    }
}

} // namespace

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printUsage();
        return 1;
    }

    const std::string_view command(argv[1]);
    if ((command == "generate-keys" || command == "embed" || command == "embed-file")
        && argc != 6) {
        std::cerr << "Error: Incorrect number of arguments.\n";
        printUsage();
        return 1;
    }
    if ((command == "extract" && argc != 4)
        || (command == "extract-file" && argc != 5)) {
        std::cerr << "Error: Incorrect number of arguments.\n";
        printUsage();
        return 1;
    }
    if (command != "generate-keys" && command != "embed"
        && command != "embed-file" && command != "extract"
        && command != "extract-file") {
        std::cerr << "Error: Unknown command.\n";
        printUsage();
        return 1;
    }

    try {
        if (command == "generate-keys") {
            runGenerateKeys(argv);
        } else if (command == "embed" || command == "embed-file") {
            runEmbed(argv, command == "embed-file");
        } else {
            runExtract(argv, command == "extract-file");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
