## PWT Encode and Decode method benchmark result(compare to jwt-cpp)
- Run on (8 X 2400.5 MHz CPU s)
- CPU Caches:
  - L1 Data 32 KiB (x4)
  - L1 Instruction 32 KiB (x4)
  - L2 Unified 256 KiB (x4)
  - L3 Unified 8192 KiB (x1)
- Library was built as DEBUG. Timings may be affected.
  
|                 Benchmark                  |   Time    |    CPU    | Iterations |
| :----------------------------------------: | :-------: | :-------: | :--------: |
|       BM_PWT_encode/iterations:1000        | 40551 ns  | 46875 ns  |    1000    |
|     BM_jwt_cpp_encode/iterations:1000      | 101333 ns | 78125 ns  |    1000    |
|       BM_PWT_decode/iterations:1000        | 136245 ns | 140625 ns |    1000    |
|    BM_PWT_repeat_decode/iterations:1000    | 32262 ns  | 31250 ns  |    1000    |
|     BM_jwt_cpp_decode/iterations:1000      | 85122 ns  | 93750 ns  |    1000    |
|       BM_PWT_encode/iterations:10000       | 36316 ns  | 35938 ns  |   10000    |
|     BM_jwt_cpp_encode/iterations:10000     | 61581 ns  | 62500 ns  |   10000    |
|       BM_PWT_decode/iterations:10000       | 128902 ns | 128125 ns |   10000    |
|   BM_PWT_repeat_decode/iterations:10000    | 29366 ns  | 29688 ns  |   10000    |
|     BM_jwt_cpp_decode/iterations:10000     | 79255 ns  | 79688 ns  |   10000    |
|     BM_PWT_encode_long/iterations:1000     | 47991 ns  | 46875 ns  |    1000    |
|   BM_jwt_cpp_encode_long/iterations:1000   | 183896 ns | 187500 ns |    1000    |
|     BM_PWT_decode_long/iterations:1000     | 152416 ns | 156250 ns |    1000    |
| BM_PWT_repeat_decode_long/iterations:1000  | 40489 ns  | 46875 ns  |    1000    |
|   BM_jwt_cpp_decode_long/iterations:1000   | 551475 ns | 546875 ns |    1000    |
|    BM_PWT_encode_long/iterations:10000     | 38284 ns  | 39062 ns  |   10000    |
|  BM_jwt_cpp_encode_long/iterations:10000   | 173660 ns | 173438 ns |   10000    |
|    BM_PWT_decode_long/iterations:10000     | 136191 ns | 135938 ns |   10000    |
| BM_PWT_repeat_decode_long/iterations:10000 | 36425 ns  | 35938 ns  |   10000    |
|  BM_jwt_cpp_decode_long/iterations:10000   | 545635 ns | 543750 ns |   10000    |
