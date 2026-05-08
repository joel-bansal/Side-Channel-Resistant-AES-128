#include <openssl/aes.h>
#include <stdint.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define AES_FORCE_INLINE static inline __attribute__((always_inline))
#define AES_RESTRICT __restrict__
#define AES_LIKELY(x) __builtin_expect(!!(x), 1)
#define AES_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define AES_MEMCPY __builtin_memcpy
#else
#define AES_FORCE_INLINE static inline
#define AES_RESTRICT
#define AES_LIKELY(x) (x)
#define AES_UNLIKELY(x) (x)
#define AES_MEMCPY memcpy
#endif

#define AES_ROUNDS 10

typedef struct {
    unsigned int rd_key[4 * (AES_ROUNDS + 1)];
    int rounds;
} AES_KEY_Custom;

typedef struct {
    uint32_t slice[8];
} AES_state;

AES_FORCE_INLINE void LoadBytes(AES_state * AES_RESTRICT s, const unsigned char * AES_RESTRICT data16) {
    unsigned char rm[16];
    rm[0]  = data16[0]; rm[1]  = data16[4]; rm[2]  = data16[8];  rm[3]  = data16[12];
    rm[4]  = data16[1]; rm[5]  = data16[5]; rm[6]  = data16[9];  rm[7]  = data16[13];
    rm[8]  = data16[2]; rm[9]  = data16[6]; rm[10] = data16[10]; rm[11] = data16[14];
    rm[12] = data16[3]; rm[13] = data16[7]; rm[14] = data16[11]; rm[15] = data16[15];

    uint64_t d0, d1;
    AES_MEMCPY(&d0, rm, 8);
    AES_MEMCPY(&d1, rm + 8, 8);

#define PACK_SLICE(i) do { \
        uint64_t a = (d0 >> (i)) & UINT64_C(0x0101010101010101); \
        uint64_t b = (d1 >> (i)) & UINT64_C(0x0101010101010101); \
        a = (a ^ (a >> 7)) & UINT64_C(0x0003000300030003); \
        b = (b ^ (b >> 7)) & UINT64_C(0x0003000300030003); \
        a = (a ^ (a >> 14)) & UINT64_C(0x0000000F0000000F); \
        b = (b ^ (b >> 14)) & UINT64_C(0x0000000F0000000F); \
        a = (a ^ (a >> 28)) & UINT64_C(0x00000000000000FF); \
        b = (b ^ (b >> 28)) & UINT64_C(0x00000000000000FF); \
        s->slice[i] = (uint32_t)a | ((uint32_t)b << 8); \
    } while (0)

    PACK_SLICE(0); PACK_SLICE(1); PACK_SLICE(2); PACK_SLICE(3);
    PACK_SLICE(4); PACK_SLICE(5); PACK_SLICE(6); PACK_SLICE(7);
#undef PACK_SLICE
}

AES_FORCE_INLINE void SaveBytes(unsigned char * AES_RESTRICT data16, const AES_state * AES_RESTRICT s) {
    uint64_t d0 = 0, d1 = 0;

#define UNPACK_SLICE(i) do { \
        uint64_t a = (uint8_t)(s->slice[i] & 0xFF); \
        uint64_t b = (uint8_t)((s->slice[i] >> 8) & 0xFF); \
        a = (a ^ (a << 28)) & UINT64_C(0x0000000F0000000F); \
        b = (b ^ (b << 28)) & UINT64_C(0x0000000F0000000F); \
        a = (a ^ (a << 14)) & UINT64_C(0x0003000300030003); \
        b = (b ^ (b << 14)) & UINT64_C(0x0003000300030003); \
        a = (a ^ (a <<  7)) & UINT64_C(0x0101010101010101); \
        b = (b ^ (b <<  7)) & UINT64_C(0x0101010101010101); \
        d0 |= (a << (i)); \
        d1 |= (b << (i)); \
    } while (0)

    UNPACK_SLICE(0); UNPACK_SLICE(1); UNPACK_SLICE(2); UNPACK_SLICE(3);
    UNPACK_SLICE(4); UNPACK_SLICE(5); UNPACK_SLICE(6); UNPACK_SLICE(7);
#undef UNPACK_SLICE

    unsigned char rm[16];
    AES_MEMCPY(rm,     &d0, 8);
    AES_MEMCPY(rm + 8, &d1, 8);

    data16[0] = rm[0]; data16[4] = rm[1]; data16[8] = rm[2]; data16[12]= rm[3];
    data16[1] = rm[4]; data16[5] = rm[5]; data16[9] = rm[6]; data16[13]= rm[7];
    data16[2] = rm[8]; data16[6] = rm[9]; data16[10]= rm[10];data16[14]= rm[11];
    data16[3] = rm[12];data16[7] = rm[13];data16[11]= rm[14];data16[15]= rm[15];
}

AES_FORCE_INLINE void SubBytes(AES_state * AES_RESTRICT s) {
    uint32_t U0=s->slice[7], U1=s->slice[6], U2=s->slice[5], U3=s->slice[4];
    uint32_t U4=s->slice[3], U5=s->slice[2], U6=s->slice[1], U7=s->slice[0];
    uint32_t T1,T2,T3,T4,T5,T6,T7,T8,T9,T10,T11,T12,T13,T14,T15,T16;
    uint32_t T17,T18,T19,T20,T21,T22,T23,T24,T25,T26,T27,D;
    uint32_t M1,M6,M11,M13,M15,M20,M21,M22,M23,M25;
    uint32_t M37,M38,M39,M40,M41,M42,M43,M44,M45;
    uint32_t M46,M47,M48,M49,M50,M51,M52,M53,M54;
    uint32_t M55,M56,M57,M58,M59,M60,M61,M62,M63;

    T1=U0^U3; T2=U0^U5; T3=U0^U6; T4=U3^U5; T5=U4^U6;
    T6=T1^T5; T7=U1^U2; T8=U7^T6; T9=U7^T7; T10=T6^T7;
    T11=U1^U5; T12=U2^U5; T13=T3^T4; T14=T6^T11; T15=T5^T11;
    T16=T5^T12; T17=T9^T16; T18=U3^U7; T19=T7^T18; T20=T1^T19;
    T21=U6^U7; T22=T7^T21; T23=T2^T22; T24=T2^T10; T25=T20^T17;
    T26=T3^T16; T27=T1^T12; D=U7;

    M1=T13&T6; M6=T3&T16; M11=T1&T15; M13=(T4&T27)^M11;
    M15=(T2&T10)^M11; M20=T14^M1^(T23&T8)^M13;
    M21=(T19&D)^M1^T24^M15; M22=T26^M6^(T22&T9)^M13;
    M23=(T20&T17)^M6^M15^T25; M25=M22&M20;
    M37=M21^((M20^M21)&(M23^M25)); M38=M20^M25^(M21|(M20&M23));
    M39=M23^((M22^M23)&(M21^M25)); M40=M22^M25^(M23|(M21&M22));
    M41=M38^M40; M42=M37^M39; M43=M37^M38; M44=M39^M40;
    M45=M42^M41; M46=M44&T6;  M47=M40&T8;  M48=M39&D;   M49=M43&T16;
    M50=M38&T9;  M51=M37&T17; M52=M42&T15; M53=M45&T27; M54=M41&T10;
    M55=M44&T13; M56=M40&T23; M57=M39&T19; M58=M43&T3;  M59=M38&T22;
    M60=M37&T20; M61=M42&T1;  M62=M45&T4;  M63=M41&T2;

    uint32_t L0=M61^M62, L1=M50^M56, L2=M46^M48;
    uint32_t L3=M47^M55, L4=M54^M58, L5=M49^M61;
    uint32_t L6=M62^L5,  L7=M46^L3,  L8=M51^M59;
    uint32_t L9=M52^M53, L10=M53^L4, L11=M60^L2;
    uint32_t L12=M48^M51,L13=M50^L0, L14=M52^M61;
    uint32_t L15=M55^L1, L16=M56^L0, L17=M57^L1;
    uint32_t L18=M58^L8, L19=M63^L4, L20=L0^L1;
    uint32_t L21=L1^L7,  L22=L3^L12, L23=L18^L2;
    uint32_t L24=L15^L9, L25=L6^L10, L26=L7^L9;
    uint32_t L27=L8^L10, L28=L11^L14,L29=L11^L17;

    s->slice[7] = ( L6^L24)    & 0xFFFF;
    s->slice[6] = (~(L16^L26)) & 0xFFFF;
    s->slice[5] = (~(L19^L28)) & 0xFFFF;
    s->slice[4] = ( L6^L21)    & 0xFFFF;
    s->slice[3] = ( L20^L22)   & 0xFFFF;
    s->slice[2] = ( L25^L29)   & 0xFFFF;
    s->slice[1] = (~(L13^L27)) & 0xFFFF;
    s->slice[0] = (~(L6^L23))  & 0xFFFF;
}

AES_FORCE_INLINE void ShiftRows(AES_state * AES_RESTRICT s) {
    const uint32_t M0  = 0x000F, M1L = 0x0010, M1R = 0x00E0;
    const uint32_t M2L = 0x0300, M2R = 0x0C00, M3L = 0x7000, M3R = 0x8000;

    for (int i = 0; i < 8; i++) {
        uint32_t v = s->slice[i];
        s->slice[i] = (
            (v & M0) | ((v & M1L) << 3) | ((v & M1R) >> 1) |
            ((v & M2L) << 2) | ((v & M2R) >> 2)| ((v & M3L) << 1) | ((v & M3R) >> 3) 
        ) & 0xFFFF;
    }
}

#define ROT16(x,b) (uint32_t)( (((x) >> ((b)*4)) | ((x) << (16-(b)*4))) & 0xFFFF )

AES_FORCE_INLINE void MixColumns(AES_state * AES_RESTRICT s) {
    uint32_t s0=s->slice[0], s1=s->slice[1], s2=s->slice[2], s3=s->slice[3];
    uint32_t s4=s->slice[4], s5=s->slice[5], s6=s->slice[6], s7=s->slice[7];

    uint32_t s0_01=s0^ROT16(s0,1), s0_123=ROT16(s0_01,1)^ROT16(s0,3);
    uint32_t s1_01=s1^ROT16(s1,1), s1_123=ROT16(s1_01,1)^ROT16(s1,3);
    uint32_t s2_01=s2^ROT16(s2,1), s2_123=ROT16(s2_01,1)^ROT16(s2,3);
    uint32_t s3_01=s3^ROT16(s3,1), s3_123=ROT16(s3_01,1)^ROT16(s3,3);
    uint32_t s4_01=s4^ROT16(s4,1), s4_123=ROT16(s4_01,1)^ROT16(s4,3);
    uint32_t s5_01=s5^ROT16(s5,1), s5_123=ROT16(s5_01,1)^ROT16(s5,3);
    uint32_t s6_01=s6^ROT16(s6,1), s6_123=ROT16(s6_01,1)^ROT16(s6,3);
    uint32_t s7_01=s7^ROT16(s7,1), s7_123=ROT16(s7_01,1)^ROT16(s7,3);

    s->slice[0] = s7_01^s0_123;
    s->slice[1] = s7_01^s0_01^s1_123;
    s->slice[2] = s1_01^s2_123;
    s->slice[3] = s7_01^s2_01^s3_123;
    s->slice[4] = s7_01^s3_01^s4_123;
    s->slice[5] = s4_01^s5_123;
    s->slice[6] = s5_01^s6_123;
    s->slice[7] = s6_01^s7_123;
}

AES_FORCE_INLINE void AddRoundKey(AES_state * AES_RESTRICT s, const AES_state * AES_RESTRICT rk) {
    s->slice[0]^=rk->slice[0]; s->slice[1]^=rk->slice[1];
    s->slice[2]^=rk->slice[2]; s->slice[3]^=rk->slice[3];
    s->slice[4]^=rk->slice[4]; s->slice[5]^=rk->slice[5];
    s->slice[6]^=rk->slice[6]; s->slice[7]^=rk->slice[7];
}

static int cache_initialized = 0;
static AES_state cached_rounds[AES_ROUNDS + 1];
static unsigned int cached_key[4] = {0};

AES_FORCE_INLINE int CachedKeyMatches(const AES_KEY_Custom *AES_RESTRICT enc_key) {
    if (AES_UNLIKELY(!cache_initialized)) return 0;
    return (enc_key->rd_key[0] == cached_key[0]) &&
           (enc_key->rd_key[1] == cached_key[1]) &&
           (enc_key->rd_key[2] == cached_key[2]) &&
           (enc_key->rd_key[3] == cached_key[3]);
}

#define AES_ROUND_STEP(s, rk) do { \
    SubBytes(s); ShiftRows(s); MixColumns(s); AddRoundKey(s, rk); \
} while(0)

void AES_encrypt_custom(const unsigned char * AES_RESTRICT plaintext,
                        unsigned char * AES_RESTRICT ciphertext,
                        const AES_KEY_Custom * AES_RESTRICT enc_key) {
    
    if (AES_UNLIKELY(!CachedKeyMatches(enc_key))) {
        cached_key[0] = enc_key->rd_key[0];
        cached_key[1] = enc_key->rd_key[1];
        cached_key[2] = enc_key->rd_key[2];
        cached_key[3] = enc_key->rd_key[3];

        for (int r = 0; r <= AES_ROUNDS; r++) {
            unsigned char rk_bytes[16];
            for (int w = 0; w < 4; w++) {
                unsigned int word = enc_key->rd_key[r*4 + w];
                rk_bytes[w*4+0] = (unsigned char)(word);
                rk_bytes[w*4+1] = (unsigned char)(word >> 8);
                rk_bytes[w*4+2] = (unsigned char)(word >> 16);
                rk_bytes[w*4+3] = (unsigned char)(word >> 24);
            }
            LoadBytes(&cached_rounds[r], rk_bytes);
        }
        cache_initialized = 1;
    }

    AES_state s;
    const AES_state* rk = cached_rounds;
    
    LoadBytes(&s, plaintext);
    AddRoundKey(&s, &rk[0]);

    AES_ROUND_STEP(&s, &rk[1]);
    AES_ROUND_STEP(&s, &rk[2]);
    AES_ROUND_STEP(&s, &rk[3]);
    AES_ROUND_STEP(&s, &rk[4]);
    AES_ROUND_STEP(&s, &rk[5]);
    AES_ROUND_STEP(&s, &rk[6]);
    AES_ROUND_STEP(&s, &rk[7]);
    AES_ROUND_STEP(&s, &rk[8]);
    AES_ROUND_STEP(&s, &rk[9]);

    SubBytes(&s);
    ShiftRows(&s);
    AddRoundKey(&s, &rk[10]);

    SaveBytes(ciphertext, &s);
}

void AES_code(unsigned char plaintext[16], unsigned char ciphertext[16], AES_KEY *enc_key) {
    AES_encrypt_custom(plaintext, ciphertext, (AES_KEY_Custom *)enc_key); 
}
