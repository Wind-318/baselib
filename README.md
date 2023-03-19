# Wind C++ Utils

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/2fd79761fbd446fb9c85377bf2b9820d)](https://www.codacy.com/gh/Wind-318/wind/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Wind-318/wind&amp;utm_campaign=Badge_Grade) [![codecov](https://img.shields.io/codecov/c/github/Wind-318/wind)](https://codecov.io/gh/Wind-318/wind) [![LICENCE](https://img.shields.io/github/license/Wind-318/wind)](./LICENCE) [![workflow](https://img.shields.io/github/actions/workflow/status/Wind-318/wind/alpine.yml)](https://github.com/Wind-318/wind/actions) [![alpine](https://img.shields.io/badge/alpine-passing-brightgreen)](https://github.com/Wind-318/wind/actions/workflows/alpine.yml) [![stars](https://img.shields.io/github/stars/Wind-318/wind?style=plastic)](https://github.com/Wind-318/wind/stargazers) [![Download](https://img.shields.io/github/downloads/Wind-318/wind/total)](https://github.com/Wind-318/wind/releases/)

## PWT - Protobuf Web Token
Written in C++17, the PWT namespace uses Protocol Buffers (protobuf) and OpenSSL to efficiently encode and decode complex network tokens. It provides a simple and efficient solution for handling long web tokens.

### Installation
- #### Linux
  - To use this library in linux, you'll need to have the following dependencies installed on your system:
    - Protocol Buffers (protobuf, preferably the latest version)
    - OpenSSL
    - GTest (required for running unit tests)
    - Google benchmark (required for running benchmark tests)

    You can install these dependencies on an alpine system using the following command:
    ```
    apk add --no-cache cmake gcc g++ make git openssl openssl-dev protobuf-dev protobuf gtest-dev gtest benchmark-dev benchmark
    ```

  - Download the library using git:
    ```
    git clone https://github.com/Wind-318/wind.git
    ```
  - Build the library using CMake::
    ```
    mkdir build && cd build
    cmake ..
    make && make install
    ```

  - Use the library in your CMake project:
    ```
    find_package(Protobuf REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_package(Wind REQUIRED)

    add_executable(${PROJECT_NAME} main.cc)

    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_link_libraries(${PROJECT_NAME} PRIVATE protobuf::libprotoc protobuf::libprotobuf protobuf::libprotobuf-lite)
    target_link_libraries(${PROJECT_NAME} PRIVATE Wind::wind)
    ```

- #### macOS
    Todo
    
- #### Windows
    vcpkg: Todo

### Quick Start
You can see the detailed version on [here](docs/utils/pwt.md).  
Here are some samples:  
Create a new token:
```cpp
#include <wind/utils/pwt.h>
#include <iostream>
#include <stdexcept>
#include <string>

int main() {
    std::string s;
    // Create a token
    try {
        s = ::wind::utils::pwt::CreatePWTInstance()
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
Get a new PWT object, encode and decode:  
```cpp
#include <wind/utils/pwt.h>
#include <iostream>
#include <stdexcept>
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

    if (pwt_obj.IsExpired()) {
        // handle
    }

    if (pwt_obj.IsTokenValid(token)) {
        // handle
    }

    // Decode with itself
    if (pwt_obj.Decode(token)) {
        std::cout << "Decode success" << std::endl;
    } else {
        std::cout << "Decode failed" << std::endl;
    }

    // Use the decoded claims
    std::cout << pwt_obj.GetPWK() << std::endl;
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

### Test
To run the tests, modify the CmakeLists.txt:
```
option(BUILD_TESTS "Build tests" OFF)
```
to
```
option(BUILD_TESTS "Build tests" ON)
```
and then run the wind_test executable. The benchmark results can see in [PWT benchmark](docs/utils/pwt.md).

### Todo List
- [ ] Complete documentation;

***
## License
This library is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more information.
