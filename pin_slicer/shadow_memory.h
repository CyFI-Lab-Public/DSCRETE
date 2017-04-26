#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H

#include <stdint.h>
#include <string.h>
#undef NDEBUG
#include <cassert>

template <int n>
struct MASK {
    static const uint64_t value = static_cast<uint64_t>(-1) >> (64 - n);
};

template <class ShadowByte, int addressBits, int indexBits, int nIndex>
class _ShadowMemory
{
    typedef _ShadowMemory<ShadowByte, addressBits - indexBits, indexBits, nIndex - 1> ShadowPage;

    ShadowPage* pages [1 << indexBits];

public:
    _ShadowMemory() {
        memset (pages, 0, sizeof(pages));
    }
    
    inline bool
    get(const uint64_t addr, ShadowByte &ret) {
        assert (addr == (addr & MASK<addressBits>::value));

        uint64_t idx = addr >> (addressBits - indexBits);
        uint64_t off = addr &  MASK<addressBits - indexBits>::value;

        if (pages[idx] == NULL) return false;
        return pages[idx]->get(off, ret);
    }

    inline void
    set(const uint64_t addr, const ShadowByte& b) {
        assert (addr == (addr & MASK<addressBits>::value));

        uint64_t idx = addr >> (addressBits - indexBits);
        uint64_t off = addr &  MASK<addressBits - indexBits>::value;

        if (pages[idx] == NULL)
            pages[idx] = new ShadowPage();
        pages[idx]->set(off, b);
    }
};

template <class ShadowByte, int addressBits, int indexBits>
class _ShadowMemory<ShadowByte, addressBits, indexBits, 0>
{
    ShadowByte bytes[1 << addressBits];

public:
    inline bool
    get(const uint64_t addr, ShadowByte &ret) {
        assert (addr == (addr & MASK<addressBits>::value));
        ret = bytes[addr];
        return true;
    }
    
    inline void
    set(const uint64_t addr, const ShadowByte& b) {
        assert (addr == (addr & MASK<addressBits>::value));
        bytes[addr] = b;
    }
};

template <class ShadowByte>
struct ShadowMemory
{
    typedef _ShadowMemory<ShadowByte, 64, 12, 4> ShadowMemory64;
};

#endif
