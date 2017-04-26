#include "pin.H"

#include <utility>
#include <sys/mman.h>
#include <sys/stat.h>
#include "pin_address_translator.h"
#include "pin_scan.h"
#include "pin_forensix_scanner.h"
#include "pin_helper.h"
#include "analysis_datatypes.h"
#include "readwrite.h"
#include "output.h"
#include <errno.h>
#include <string.h>

#define PRINT_SCANNER_STATS

#define FILE_OUTPUT
#ifdef FILE_OUTPUT
# define FILE_OUTPUT_DIR "./scan_output_files"
#endif

//#define DEBUG_MEM_INFO

INT32
PIN_Scan::MapMemImg(const char *MemImgFileName)
{
  //assert(maps);
  LOG(format("MemImgFileName: %s\n") % MemImgFileName);
  
  MemImgFile = fopen(MemImgFileName, "rb+");
  if(!MemImgFile) {
    LOG("Could not open Memory Image File!\n");
    return -1;
  }
  
  ADDRINT map_addr;
  for(file_line l : maps)
  {
    LOG(format("Mapping: %s @ %lx-%lx (%ld bytes).\n") 
          % l.name % l.start % (l.start + l.len) % l.len);
    // may need to macro this out if we ever port to Winblows.
    map_addr = (ADDRINT)mmap((void *)l.start, l.len, 
                           PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_FIXED,
                           fileno(MemImgFile), l.file_offset);
    if(map_addr != l.start) {
      LOG(format("Mapping Error! %s\n") % strerror(errno));
      return -3;
    }
  }

  LOG("Successfully Mapped Memoriy Image!\n");
  return 0;
}

static inline bool is_page_aligned(ADDRINT &a)
{
  static ADDRINT page_sz = sysconf(_SC_PAGESIZE);
  return !(a & (page_sz - 1));
}

// name, start, len, file offset
VOID PIN_Scan::parse_mem_info(string& filename)
{
  FILE *f_mem_info = fopen(filename.c_str(), "rt");
#define BUFFER_SZ (1024)
  char line[BUFFER_SZ];
  memset(line, 0, BUFFER_SZ);
  while(fgets(line, BUFFER_SZ, f_mem_info) != NULL)
  {
    file_line f = {"", 0,0,0,0};
    char buf[BUFFER_SZ];
    memset(buf, 0, BUFFER_SZ);
    sscanf(line, "%s\t%lx->%ld->%lx\n", buf, &f.start, &f.len, &f.file_offset);
    if(buf[0] == '!') continue;
    f.end = f.start + f.len;
    f.name = buf;
    f.scannable = (f.name.find("^scan^") != string::npos);

    if(!::is_page_aligned(f.start)) {
      LOG("Memory Image start offset not page aligned!\n");
      LOG(format(">> %s @ %lx for %ld bytes.\n") % f.name % f.start % f.len);
      return;
    }
    
    // try to merge?
    bool merged = false;
    for(vector<file_line>::iterator it = maps.begin();
        it != maps.end(); it++)
    {
      if(it->name == f.name && (it->start + it->len == f.start) && 
         (it->file_offset + it->len == f.file_offset))
      {
        it->len += f.len;
#ifdef DEBUG_MEM_INFO
        LOG(format("Merge: %s @ %lx-%lx-%lx (%ld bytes).\n") 
              % it->name % it->start % f.start % (f.start+f.len) % it->len);
#endif
        merged = true;
        break;
      }
    }
    if(!merged) { 
#ifdef DEBUG_MEM_INFO
      LOG(format("Map: %s @ %lx-%lx (%ld bytes).\n") 
            % f.name % f.start % (f.start + f.len) % f.len);
#endif
      maps.push_back(f);
    }
  }
}

#define alloc_multiproc_shared_mem(size) \
    mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_LOCKED, -1, 0)
INT32
PIN_Scan::Init(string MemImgFile, string MemInfoFile)
{
  f_output = fopen("__matches.out", "wt");
  f_crash = fopen("__matches.partial.out", "wt");
  //bool b = f_output != NULL;
  //bool b2 = f_crash != NULL;
  //assert(b && b2);
  f_output_Mutex = (PIN_MUTEX*)alloc_multiproc_shared_mem(sizeof(PIN_MUTEX));
  f_crash_Mutex = (PIN_MUTEX*)alloc_multiproc_shared_mem(sizeof(PIN_MUTEX));
  PIN_MutexInit(f_output_Mutex);
  PIN_MutexInit(f_crash_Mutex);
  Finished_Scanning = false;
  Current_Map = 0; // this will be set to MemImgOffset in Prime()
  Current_Address = 0; // this will be set to MemImgOffset in Prime()
#ifdef FILE_OUTPUT
  system("mkdir -p " FILE_OUTPUT_DIR);
#endif
  parse_mem_info(MemInfoFile);
  if(maps.empty()) return -5;
  int ret = MapMemImg(MemImgFile.c_str());
  return ret;
}

VOID PIN_Scan::Fini()
{
  if(fclose(f_output))
    LOG("f_matches Close Error?");
  if(fclose(f_crash))
    LOG("f_crash Close Error?");
  for(auto map : maps) {
    if(munmap((void *)map.start, map.len))
      LOG("MemImg Unmap Error?");
  }
  if(fclose(MemImgFile))
    LOG("MemImgFile Close Error?");
}

BOOL
PIN_Scan::Go_To_Next_Map()
{
  Current_Map++;
  while(Current_Map < maps.size() && !(maps[Current_Map].scannable)) { Current_Map++; }
  if(Current_Map < maps.size()) {
    Current_Address = maps[Current_Map].start;
    return true;
  } else
    return false;
}

VOID
PIN_Scan::Prime_Tool()
{
  while(Current_Map < maps.size() && !(maps[Current_Map].scannable)) { Current_Map++; }
  Current_Address = maps[Current_Map].start;
}
  
VOID PIN_Scan::Buffer(const char* buf, ADDRINT len)
{
  char * temp = new char[output_buffer_len + len];
  memcpy(temp, output_buffer, output_buffer_len);
  memcpy(temp+output_buffer_len, buf, len);
  output_buffer_len += len;
  delete output_buffer;
  output_buffer = temp;
}

VOID PIN_Scan::BufferFront(const char* buf, ADDRINT len)
{
  char * temp = new char[output_buffer_len + len];
  memcpy(temp, buf, len);
  memcpy(temp+len, output_buffer, output_buffer_len);
  output_buffer_len += len;
  delete output_buffer;
  output_buffer = temp;
}

VOID
PIN_Scan::Start_Single_Scan(ADDRINT* replace_addr, ADDRINT scan_id)
{
#if AGGRESSIVE_LOGGING > 0
  ADDRINT old = *(replace_addr);
#endif
  *(replace_addr) = Current_Address;
  current_scan_id = scan_id;
#if AGGRESSIVE_LOGGING > 0
  LOG(format("(%d) Replace %lx -> %lx\n") % PIN_GetPid() % old % *(replace_addr));
#endif
  Started_Scanning = true;
  saw_output = false;
}

VOID
PIN_Scan::MemoryOutput(VOID * safe_buffer, ADDRINT size)
{
  if(size == 0) return;
#ifdef FILE_OUTPUT
  char filename[1024];
  snprintf(filename, 1024, FILE_OUTPUT_DIR "/s_%d_0x%lx.data",
           current_scan_id, Current_Address);
  FILE * f_out = fopen(filename, "w");
  //assert(f_out != NULL);
  fwrite(safe_buffer, 1, size, f_out);
  fflush(f_out);
  fclose(f_out);
  string s = (format("%s\n") % filename).str();
  Buffer(s.c_str(), s.length());
#else
  Buffer((char*)safe_buffer, size);
#endif
  saw_output = true;
}

VOID
PIN_Scan::Abort_Single_Scan()
{
  if(saw_output)
    Flush_Buffer(f_crash_Mutex, f_crash);
}

VOID
PIN_Scan::Stop_Single_Scan()
{
  if(saw_output)
    Flush_Buffer(f_output_Mutex, f_output);
}

BOOL
PIN_Scan::Done()
{
  return Finished_Scanning;
}

VOID
PIN_Scan::Go_To_Next_Address()
{
  auto map = maps[Current_Map];
  if(Current_Address < (map.start + map.len))
    Current_Address++;
  else
    Finished_Scanning = !Go_To_Next_Map();
#ifdef PRINT_SCANNER_STATS
  ADDRINT n_addrs = Current_Address - map.start;
  if(n_addrs % (map.len / 100) == 0)
  {
    LOG(format("%d%% of %d\n") 
         % (((n_addrs * 100) / map.len) + 1)
         % Current_Map);
  }
#endif
}

bool
PIN_Scan::Set_Next_Address(ADDRINT addr)
{
  ADDRINT map = Map_Index_For_Addr(addr);
  if(map < maps.size()) {
    Current_Map = map;
    Current_Address = addr;
    return true;
  } else
    return false;
}

ADDRINT
PIN_Scan::Map_Index_For_Addr(ADDRINT a)
{
  for(ADDRINT i = 0; i < maps.size(); i++)
  {
    auto map = maps[i];
    if(map.scannable && map.start <= a && a < map.start + map.len)
    {
      return i;
    }
  }
  return maps.size();
}

BOOL 
PIN_Scan::Addr_In_Heap(ADDRINT a)
{
  return Map_Index_For_Addr(a) < maps.size();
}

VOID
PIN_Scan::Flush_Buffer(PIN_MUTEX* mutex, FILE* file)
{
  string s=(format("%ld===== Scanning from %lx:\n") 
              % current_scan_id % Current_Address).str();
  BufferFront((char*)s.c_str(), s.length());
  const char nl[2] = "\n";
  Buffer((char*)nl, 1);
  PIN_MutexLock(mutex);
  fwrite(output_buffer, 1, output_buffer_len, file);
  fflush(file);
  PIN_MutexUnlock(mutex);
}


