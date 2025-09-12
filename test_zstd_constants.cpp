#include <iostream>
#include <zstd.h>

// Test constants
#define COMPRESSION_ALGORITHM_ZLIB 0
#define COMPRESSION_ALGORITHM_ZSTD 1

#ifndef CLIENT_ZSTD_COMPRESSION
#define CLIENT_ZSTD_COMPRESSION 0x04000000
#endif

int main() {
    std::cout << "Testing zstd compression constants and functionality..." << std::endl;
    
    // Test constants
    std::cout << "COMPRESSION_ALGORITHM_ZLIB: " << COMPRESSION_ALGORITHM_ZLIB << std::endl;
    std::cout << "COMPRESSION_ALGORITHM_ZSTD: " << COMPRESSION_ALGORITHM_ZSTD << std::endl;
    std::cout << "CLIENT_ZSTD_COMPRESSION: 0x" << std::hex << CLIENT_ZSTD_COMPRESSION << std::dec << std::endl;
    
    // Test zstd basic functionality
    const char* test_data = "Hello, World! This is a test string for zstd compression.";
    size_t test_data_size = strlen(test_data);
    
    // Compress
    size_t compressed_size = ZSTD_compressBound(test_data_size);
    char* compressed_data = new char[compressed_size];
    
    size_t actual_compressed_size = ZSTD_compress(compressed_data, compressed_size, test_data, test_data_size, 6);
    
    if (ZSTD_isError(actual_compressed_size)) {
        std::cout << "Compression failed: " << ZSTD_getErrorName(actual_compressed_size) << std::endl;
        delete[] compressed_data;
        return 1;
    }
    
    std::cout << "Original size: " << test_data_size << " bytes" << std::endl;
    std::cout << "Compressed size: " << actual_compressed_size << " bytes" << std::endl;
    
    // Decompress
    char* decompressed_data = new char[test_data_size + 1];
    size_t decompressed_size = ZSTD_decompress(decompressed_data, test_data_size, compressed_data, actual_compressed_size);
    
    if (ZSTD_isError(decompressed_size)) {
        std::cout << "Decompression failed: " << ZSTD_getErrorName(decompressed_size) << std::endl;
        delete[] compressed_data;
        delete[] decompressed_data;
        return 1;
    }
    
    decompressed_data[decompressed_size] = '\0';
    
    std::cout << "Decompressed size: " << decompressed_size << " bytes" << std::endl;
    std::cout << "Original data: " << test_data << std::endl;
    std::cout << "Decompressed data: " << decompressed_data << std::endl;
    
    if (strcmp(test_data, decompressed_data) == 0) {
        std::cout << "SUCCESS: Data matches after compression/decompression!" << std::endl;
    } else {
        std::cout << "ERROR: Data does not match!" << std::endl;
        delete[] compressed_data;
        delete[] decompressed_data;
        return 1;
    }
    
    delete[] compressed_data;
    delete[] decompressed_data;
    
    return 0;
}
