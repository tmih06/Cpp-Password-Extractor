#ifndef NO_STRING_HPP
#define NO_STRING_HPP

#include <string>

namespace mlcg {
    constexpr uint32_t modulus() {
        return 0x7fffffff;
    }

    template<size_t N>
    constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
        auto value{ iv };
        for (size_t i{ 0 }; i < N; i++) {
            value = (value & (~static_cast<unsigned int>(0xFF << 8))) | ((value & 0xFF) ^ entropy[i]);
            value = value << 8 | value >> ((sizeof(value) * 8) - 8);
        }
        while (value > modulus()) value = value >> 1;
        return value << 1 | 1;
    }

    constexpr uint32_t prng(const uint32_t input) {
        return (input * 48271) % modulus();
    }
}

template<typename T, size_t N>
struct encrypted {
    int seed;
    T data[N];
};

template<size_t N>
constexpr auto crypt(const char(&input)[N], const uint32_t seed = 0) {
    encrypted<char, N> blob{};
    blob.seed = seed;
    for (uint32_t index{ 0 }, stream{ seed }; index < N; index++) {
        blob.data[index] = input[index] ^ stream;
        stream = mlcg::prng(stream);
    }
    return blob;
}

#define enc(STRING) ([] {                                     \
    constexpr auto _{ crypt(STRING, mlcg::seed(__FILE__, __LINE__)) }; \
    return std::string{ crypt(_.data, _.seed).data };                  \
}())

#endif // NO_STRING_HPP