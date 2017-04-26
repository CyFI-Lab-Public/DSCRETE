#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H

#include <stdint.h>
#include <map>

template <class ShadowByte>
class _ShadowMemory
{
    struct ShadowRangeElem {
      uint64_t end;
      ShadowByte val;
    };
    typedef map<uint64_t, ShadowRangeElem> ShadowPage; // key is the start of the range
    typedef typename ShadowPage::iterator SPiterator;
    typedef typename ShadowPage::value_type SPvalue_type;

    ShadowPage page;

public:
    inline bool
    get(const uint64_t addr, ShadowByte& ret) {
        SPiterator it = page.upper_bound(addr);
        if(it == page.begin()) return false;
        it--;
        if(it == page.begin()) return false;
        // it->first <= addr so addr must either be it's range or before the next element in page
        if(addr > it->second.end) return false;
        ret = it->second.val;
        return true;
    }

    inline void
    set(const uint64_t addr, const ShadowByte& b) {
        SPiterator it = page.upper_bound(addr);
        if(it == page.begin())
        {
          ShadowRangeElem e = {addr, b};
          page.insert(it, SPvalue_type(addr, e)); 
          return;
        }

        SPiterator next_it = it--;
        if(it == page.begin())
        {
          ShadowRangeElem e = {addr, b};
          page.insert(next_it, SPvalue_type(addr, e)); 
          return;
        }

        // it is <= addr and next_it is the element after it. 
        if (addr <= it->second.end)
        {  // addr is within it's range.
          if(!(b == it->second.val))
          {
            if(addr == it->first)
            { // this coveres it->first == it->second.end too
              if(it->second.end > it->first)
              { // push back the other elements in it's range
                page.insert(next_it, SPvalue_type(it->first + 1, it->second));
              }
              SPiterator orig_it = it--;
              if(addr == it->second.end + 1 && b == it->second.val)
              { // addr actually belongs to the set right before it!
                if (next_it != page.end() && addr == next_it->first - 1 && b == next_it->second.val)
                { // but the guy after addr ALSO belongs with it!
                  it->second.end = next_it->second.end;
                  page.erase(next_it);
                }
                else
                {
                  it->second.end++;
                }
                page.erase(orig_it);
              }
              else
              {
                orig_it->second.end = addr;
                orig_it->second.val = b;
              }
            }
            else if(addr == it->second.end)
            { // it->first != it->second.end here because of above
              it->second.end--;
              if(next_it != page.end() && addr == next_it->first - 1 && b == next_it->second.val)
              { // addr actually belongs with the next range!
                page.insert(next_it, SPvalue_type(addr, next_it->second));
                page.erase(next_it);
              }
              else
              { 
                ShadowRangeElem e = {addr, b};
                page.insert(next_it, SPvalue_type(addr, e));
              }
            }
            else // it->first < addr < it->second.end
            {
              ShadowRangeElem e = it->second;
              it->second.end = addr - 1;
              it = page.insert(next_it, SPvalue_type(addr+1, e));
              e.end = addr;
              e.val = b;
              page.insert(it, SPvalue_type(addr, e));
            }
          } // else do nothing...
        }
        else if (addr == it->second.end + 1 && b == it->second.val)
        { // addr is just past the end of it's range, but belongs with it.
          if (next_it != page.end() && addr == next_it->first - 1 && b == next_it->second.val)
          { // but the guy after addr ALSO belongs with it!
            it->second.end = next_it->second.end;
            page.erase(next_it);
          }
          else
            it->second.end++;
        }
        else if (next_it != page.end() && addr == next_it->first - 1 && b == next_it->second.val)
        { // addr is just before the next range and belongs with the next range (it++)
          page.insert(next_it, SPvalue_type(addr, next_it->second));
          page.erase(next_it);
        }
        else
        { // addr is in the middle of nowhere...
          ShadowRangeElem e = {addr, b};
          page.insert(next_it, SPvalue_type(addr, e)); 
        }
    }
};

template <class ShadowByte>
struct ShadowMemory
{
    typedef _ShadowMemory<ShadowByte> ShadowMemory64;
};

#endif // SHADOW_MEMORY_H
