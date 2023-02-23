# C++ Utils

## PWT (Protobuf Web Token)

This is a C++ library for encoding and decoding web tokens using Protocol Buffers (protobuf) and OpenSSL. The library provides a simple and efficient way to create and verify web tokens.

### Installation

To use this library, you'll need to have the following dependencies installed on your system:
- Protocol Buffers (protobuf)  
- OpenSSL  
- GTest (If you want to run the unit test)  
- Google benchmark (If you want to run the benchmark test)  

Once you have these dependencies installed, you can build the library using CMake:
```
mkdir build && cd build
cmake ..
make
```

### Usage

To use the library in your C++ project, you'll need to include the `pwt.h` header file and link against the `Wind::WindStatic` or `Wind::WindShared` to your project. In cmake, you can write like this:
```
find_package(wind REQUIRED)

add_library(${PROJECT_NAME}...)
target_link_libraries(${PROJECT_NAME} PRIVATE WindStatic)
```
#### Quick Start
Here are some samples:

- Create a new token:  
    ```cpp
    #include <pwt.h>
    #include <iostream>

    int main() {
        // Create a token
        try {
            auto s = ::wind::utils::pwt::CreatePWTInstance()
                        .SetExp(3600)
                        .AddPayloadCustomField("userID", "1234546")
                        .AddPayloadCustomField("userName", "wind")
                        .Encode();
        } catch (std::exception& e) {
            std::cout << e.what() << std::endl;
        }

        // Do something with the token
        std::cout << s << std::endl;

        return 0;
    }
    ```
- Get a new PWT object, encode and decode:  
    ```cpp
    #include <pwt.h>
    #include <iostream>
    #include <string>

    int main() {
        // Create a token
        auto pwt_obj = ::wind::utils::pwt::PWTInstance();
        // Add claims
        // ...
        std::string token;

        try {
            // Encode
            token = pwt_obj.Encode();
        } catch (std::exception& e) {
            std::cout << e.what() << std::endl;
        }

        // Decode with itself
        if (pwt_obj.Decode(token)) {
            std::cout << "Decode success" << std::endl;
        } else {
            std::cout << "Decode failed" << std::endl;
        }

        // Use the decoded claims
        std::cout << pwt_obj.GetPwk() << std::endl;
        std::cout << pwt_obj.GetPayloadCustomField("key") << std::endl;

        // Decode with other PWT object
        auto pwt_obj2 = ::wind::utils::pwt::PWTInstance();
        // Copy algorithm
        pwt_obj2.CopyAlgorithm(pwt_obj);

        if (pwt_obj2.Decode(token)) {
            std::cout << "Decode success" << std::endl;
        } else {
            std::cout << "Decode failed" << std::endl;
        }

        // Use the decoded claims
        auto custom_fields = pwt_obj2.GetPayloadCustomFields();
        
        // Do something else...

        return 0;
    }
    ```

### Unit Test
- [Code coverage report](CoverageReport/index.html)  

### Benchmark Test
The library comes with benchmark tests that compare its Encode and Decode performance to the jwt-cpp library. To run the benchmark tests, modify the CmakeLists.txt:
```
option(BUILD_TESTS "Build tests" OFF)
```
to
```
option(BUILD_TESTS "Build tests" ON)
```
and then run the wind_test executable. The benchmark results will be output to the console. Or see the result in [PWT benchmark](docs/pwt_benchmark.md).

***
## License
This library is licensed under the MIT License. See the LICENSE file for more information.