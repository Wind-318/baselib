# Wind C++ Utils

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/2fd79761fbd446fb9c85377bf2b9820d)](https://www.codacy.com/gh/Wind-318/wind/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Wind-318/wind&amp;utm_campaign=Badge_Grade) [![codecov](https://img.shields.io/codecov/c/github/Wind-318/wind)](https://codecov.io/gh/Wind-318/wind) [![](https://img.shields.io/github/license/Wind-318/wind)](./LICENCE) [![](https://img.shields.io/github/actions/workflow/status/Wind-318/wind/main.yml)](https://github.com/Wind-318/wind/actions) [![](https://img.shields.io/github/stars/Wind-318/wind?style=plastic)](https://github.com/Wind-318/wind/stargazers)

## PWT - Protobuf Web Token

This is a C++ 17 library that uses Protocol Buffers (protobuf) and OpenSSL to efficiently encode and decode complex web tokens. It provides a simple and high-performance solution for processing long web tokens.

### Todo List
- Complete the documentation
- Implement multi-thread support
- Ensure thread safety

### Benchmark Test
The library comes with benchmark tests that compare its Encode and Decode performance to the jwt-cpp library. To run the benchmark tests, modify the CmakeLists.txt:
```
option(BUILD_TESTS "Build tests" OFF)
```
to
```
option(BUILD_TESTS "Build tests" ON)
```
and then run the wind_test executable. The benchmark results will be output to the console. Or see the result in [PWT benchmark](docs/utils/pwt_benchmark.md).

### Compile Instructions

To use this library, you'll need to have the following dependencies installed on your system:

- Protocol Buffers (protobuf, preferably the latest version)
- OpenSSL
- GTest (required for running unit tests)
- Google benchmark (required for running benchmark tests)

Once you have these dependencies installed, you can build the library using CMake:
```
mkdir build && cd build
cmake ..
make
```

### Installation
Todo

### Quick Start
Here are some samples:

Create a new token:
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
Get a new PWT object, encode and decode:  
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

***
## License
This library is licensed under the MIT License. See the LICENSE file for more information.
