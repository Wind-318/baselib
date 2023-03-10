# PWT - Protobuf Web Token
The PWT namespace provides functionality for creating and managing PWT (Protobuf Web Token) instances in C++.
## Import
```Cpp
#include <wind/utils/pwt.h>
```

### PWTInstance
The PWTInstance class template can be used to create PWT instances, which consist of a header, a payload, and a crypto algorithm. The class template takes three template parameters:
- Header: the type of the header, which must be derived from PWTHeaderBase;
- Payload: the type of the payload, which must be derived from PWTPayloadBase;
- Algorithm: the type of the crypto algorithm, which must be derived from AlgorithmBase;
    ```Cpp
    /**
     * @brief The PWT class.
     *
     * @tparam Header Template parameter for the header, which must be derived from PWTHeader.
     * @tparam Payload Template parameter for the payload, which must be derived from PWTPayload.
     * @tparam Algorithm Template parameter for the crypto algorithm, which must be derived from Algorithm.
     */
    template <typename Header = PWTHeaderBase, typename Payload = PWTPayloadBase, typename Algorithm = ::wind::utils::encrypt::AlgorithmBase>
    class PWTInstance {
    private:
        // A unique pointer to the header, pointing to a derived class of PWTHeader.
        std::unique_ptr<PWTHeader> header_;
        // A unique pointer to the payload, pointing to a derived class of PWTPayload.
        std::unique_ptr<PWTPayload> payload_;
        // A unique pointer to the crypto algorithm, pointing to a derived class of Algorithm.
        std::unique_ptr<::wind::utils::encrypt::Algorithm> crypto_;
    };
    ```
The PWTInstance class is thread-safe and can be moved or copied using default methods like std::move and copy constructors. It also provides a clone() method to make a copy of the instance:
```Cpp
// Create a new instance.
auto p1 = CreatePWTInstance();

// Copy
auto p2(p1);
// Move
auto p3(std::move(p1));
// Copy
p3 = p2;
// Move
p3 = std::move(p2);
// Clone
auto p4 = p1.clone();
```
To decode a PWT instance, the algorithm of the decoder instance should match the algorithm of the encoder instance. This can be achieved by copying the algorithm from the encoder instance to the decoder instance using the CopyAlgorithm() method:
```Cpp
// Create a new PWTInstance.
auto p5 = CreatePWTInstance();
// Add a custom header field.
p5.AddHeaderCustomField("key", "value");

std::string token;
try {
    token = p5.Encode();
} catch (...) {
    // Handle error
}

// Another PWTInstance
auto p6 = CreatePWTInstance();
// Copy algorithm
p6.CopyAlgorithm(p5);
// If success, return true.
if (p6.Decode(token)) {
    // Do something.
} else {
    // Do something.
}

// Get the data
auto value = p6.GetHeaderCustomField("key");
std::cout << value << std::endl;
```

### PWTPool
The PWTPool class provides a thread-safe pool to manage PWTInstances. The class provides the following methods:
- Get(): gets an available PWTInstance owned by std::shared_ptr from the pool;
- Put(pwt): returns a used PWTInstance to the pool;
- CopyAlgorithm(pwt): copies the algorithm from the given PWTInstance to all available instances in the pool;

Here is some usage code:
```Cpp
// Point default max PWT instances to 50, default is 100.
::wind::utils::pwt::PWTPool pool(50);
// This will print 50.
std::cout << pool.GetMaxSize() << std::endl;
// This will print 25.
std::cout << pool.GetCurrentSize() << std::endl;
// Get an instance, the Get method will return a shared_ptr point to PWTInstance.
auto pwt_ist1 = pool.Get();
auto pwt_ist2 = pool.Get();
// This will print 23.
std::cout << pool.GetAvailableSize();
// This will print 2.
std::cout << pool.GetUsedSize();
// Add custom field.
pwt_ist1->AddHeaderCustomField("key", "value");
std::string token;
try {
    token = pwt_ist1->Encode();
} catch (...) {
    // Handle error
}

if (pwt_ist2->Decode(token)) {
    std::cout << pwt_ist2->GetHeaderCustomField("key");
} else {
    // Do something.
}

// Copy algorithm from pwt_ist1, it will copy algorithm to the avaliable 23 instances, because they're already same, it will not work
pool.CopyAlgorithm(pwt_ist1);

// Put used PWT instances back to pool.
pool.Put(pwt_ist1)
    .Put(pwt_ist2);
```

### Benchmark
Run on (8 X 2400.69 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x4)
  L1 Instruction 32 KiB (x4)
  L2 Unified 256 KiB (x4)
  L3 Unified 8192 KiB (x1)
***WARNING*** Library was built as DEBUG. Timings may be affected.
|                  Benchmark                  |   Time    |    CPU    | Iterations |
| :-----------------------------------------: | :-------: | :-------: | :--------: |
|     BM_atomic_map_range/iterations:1000     | 169819 ns | 171875 ns |    1000    |
|    BM_atomic_map_range_s/iterations:1000    | 393298 ns | 390625 ns |    1000    |
|  BM_atomic_map_range_short/iterations:1000  | 40045 ns  | 15625 ns  |    1000    |
| BM_atomic_map_range_s_short/iterations:1000 | 19275 ns  | 15625 ns  |    1000    |
|     BM_pwt_pool_encode/iterations:1000      | 70830 ns  | 62500 ns  |    1000    |
|        BM_pwt_encode/iterations:1000        | 71437 ns  | 78125 ns  |    1000    |
|     BM_pwt_pool_decode/iterations:1000      | 78609 ns  | 78125 ns  |    1000    |
|        BM_pwt_decode/iterations:1000        | 167832 ns | 171875 ns |    1000    |