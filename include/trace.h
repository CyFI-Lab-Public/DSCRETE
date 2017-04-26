#ifndef TRACE_H
#define TRACE_H

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string>
#include "output.h"

struct SLICETRACE {
    struct TRACEENTRY {
        uint64_t addr;
        uint64_t inst;
//        uint64_t pid;
//        uint64_t tid;
        uint64_t offset_dep;
        operator II() const { return II(addr, inst); }
    };
    struct DEPENDENCY {
        uint64_t ndep;
        DEP dependencies[0];
    };

    uint64_t size = 0;
    TRACEENTRY* entries = 0;
    uint8_t* deps = 0;

    std::string directory;

    void Import (const std::string& directory);
    DEPENDENCY& get_dep(uint64_t i) const { return *(DEPENDENCY*)(deps + entries[i].offset_dep); }
};

typedef SLICETRACE::TRACEENTRY TRACEENTRY;
typedef SLICETRACE::DEPENDENCY DEPENDENCY;

void SLICETRACE::Import(const std::string& directory)
{
    FILE *fp;
    int fd;
    void *ptr;

    this->directory = directory;

    assert (EXISTS(directory + "/__trace_i.out"));
    assert (EXISTS(directory + "/__trace_d.out"));

    std::string filename_i = directory + "/__trace_i.out";
    std::string filename_d = directory + "/__trace_d.out";

    fp = fopen(filename_i.c_str(), "rb");
    size = READ<uint64_t>(fp);
    fclose(fp);

    LOG(format("TRACE %s : size %lu\n") % filename_i % size);

    fd = open(filename_i.c_str(), O_RDONLY);
    ptr = mmap(0, size * sizeof(TRACEENTRY) + sizeof(size), PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED)
      LOG("MMAP failed");
    assert (ptr != MAP_FAILED);
    close(fd);

    entries = (TRACEENTRY*)((uint64_t*)ptr + 1);

    fd = open(filename_d.c_str(), O_RDONLY);
    struct stat buf;
    assert (fstat(fd, &buf) == 0);

    ptr = mmap(0, buf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    assert (ptr != MAP_FAILED);
    deps = (uint8_t*)ptr;
}
#endif
