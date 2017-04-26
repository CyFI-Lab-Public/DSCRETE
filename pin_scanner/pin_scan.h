#ifndef PIN_SCAN_H
#define PIN_SCAN_H


#include <vector>
#include <map>
#include <utility>

#include "pin.H"


class PIN_Scan
{
  FILE* MemImgFile; // mem img file mapped at MemImg addr.

  struct file_line {
   string name;
   ADDRINT start;
   ADDRINT len;
   ADDRINT end;
   ADDRINT file_offset;
   bool scannable;
  };
  INT32 MapMemImg(const char *MemImgFileName);
  VOID parse_mem_info(string& filename);
  inline void default_init();

  vector<file_line> maps;
  
  ADDRINT Current_Map;
  ADDRINT Current_Address; // Address currently being scanned or 
                          // will be scanned at next call to StartNextScan()
  UINT32 current_scan_id = 0;
  bool Finished_Scanning = false;
  bool Started_Scanning = false;
  bool saw_output = false;
  char* output_buffer = NULL;
  ADDRINT output_buffer_len = 0;
  FILE* f_output = 0;
  FILE* f_crash = 0;
  PIN_MUTEX *f_output_Mutex;
  PIN_MUTEX *f_crash_Mutex;

  VOID Buffer(const char*, ADDRINT);
  VOID BufferFront(const char*, ADDRINT);
  VOID Flush_Buffer(PIN_MUTEX* , FILE* );
  BOOL Go_To_Next_Map();
  ADDRINT Map_Index_For_Addr(ADDRINT a);
public:

  inline ADDRINT Get_Current_Address() { return Current_Address; };

  INT32 Init(string MemImgFile, string MemInfoFile);
  BOOL Addr_In_Heap(ADDRINT a);
    
  VOID Prime_Tool(); 
  VOID Fini();

  VOID Start_Single_Scan(ADDRINT* replace_addr, ADDRINT scan_id);
  inline BOOL Is_Scanning() { return Started_Scanning; };
  BOOL Scanning_Output();
  
  VOID MemoryOutput(VOID * safe_buffer, ADDRINT size);
  VOID MemoryInput(VOID * safe_buffer, ADDRINT size);

  VOID Stop_Single_Scan();
  VOID Abort_Single_Scan();
  VOID Go_To_Next_Address();
  BOOL Set_Next_Address(ADDRINT);
  BOOL Done();
};
#endif // PIN_SCAN_H
