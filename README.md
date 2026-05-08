# Constant-Time AES-128 Implementation

A high-performance, side-channel resistant implementation of the Advanced Encryption Standard (AES-128) developed in C. This project eliminates secret-dependent memory accesses to mitigate cache-timing attacks while maintaining an execution profile nearly identical to optimized, table-based libraries like OpenSSL.

---

## Project Objective

Standard AES implementations often rely on precomputed lookup tables (S-boxes and T-tables) to accelerate cryptographic transformations. These tables introduce data-dependent memory access patterns, allowing an attacker to reconstruct secret keys by observing cache-timing variations. 

The objective of this implementation was to satisfy the following constraints:
* **Zero secret-dependent memory accesses** during the encryption process.
* **Constant-time execution**, ensuring every operation takes an identical number of clock cycles regardless of the secret key or plaintext.
* **Elimination of lookup tables**, replaced by algebraic logic circuits executed entirely within CPU registers.

---

## Technical Implementation and Security Optimizations

### Bitsliced Architecture
The 128-bit AES state is transposed into 8 separate uint32_t slices. By packing the i-th bit of all 16 bytes into a single register, logical operations (AND, XOR) can process the entire AES state simultaneously. This architecture facilitates massively parallel bitwise arithmetic, providing a foundation for constant-time processing.

### Tower Field Arithmetic and Boyar-Peralta Circuit
To compute the SubBytes transformation without lookup tables, the multiplicative inverse in GF(2^8) is calculated algebraically. The implementation utilizes a Tower Field boolean logic circuit (Boyar-Peralta) that maps elements down to smaller subfields:

GF(2^8) -> GF(2^4)^2 -> GF(2^2)^2 -> GF(2)

This streamlines the inversion into three logic stages:
* **Linear mapping** into the Canright tower field using XOR.
* **Non-linear Galois field inversion** using multiplication via AND.
* **Linear mapping back** with the AES affine transform using XOR.

### Performance Optimizations
* **SWAR (SIMD Within A Register):** Leverages bitwise logical operations across the transposed state to maintain high throughput despite the lack of hardware acceleration.
* **Round Key Caching:** Transposing round keys incurs overhead; the implementation detects identical master keys and caches the fully bitsliced round key schedule for subsequent operations.
* **Loop Unrolling:** The 10 rounds of AES-128 are fully unrolled to eliminate branch misprediction penalties and loop control overhead.

---

## Performance Evaluation

The implementation was profiled against the OpenSSL reference implementation, modeling memory access times at 5 clock cycles.

| Metric | OpenSSL (Reference) | Custom (Bitsliced) | Ratio (Custom/OpenSSL) |
| :--- | :--- | :--- | :--- |
| Total Cycles | 2,095,673 | 2,107,181 | 1.0055 |
| CPI | 2.5001 | 2.4838 | N/A |
| Instructions | 838,236 | 848,370 | N/A |

**Summary:** The secure implementation introduces a minimal 0.55% cycle overhead compared to OpenSSL while effectively eliminating cache-timing leakage vectors.

---

## Repository Structure

| File | Description |
| :--- | :--- |
| AES_code_128.c | Core implementation featuring bitslicing, tower-field, and optimized transformations. |
| analysis.c | Memory trace generator used for security profiling. |
| check.py | Leakage testing script to verify constant-time access patterns. |
| Project Problem Statement.pdf | Detailed requirements and security constraints for the assignment. |
| ass3_project.pdf | Comprehensive performance report and implementation methodology. |

---

## How to Run

### Prerequisites
* GCC or Clang compiler.
* Python 3 (for leakage testing).

### Testing
To verify functional correctness and ensure zero secret-dependent memory access patterns, run the provided check script:

```bash
python3 check.py
