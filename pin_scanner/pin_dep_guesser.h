#include "pin.H"
#include "pin_scan.h"
#include "pin_forensix_scanner.h"
#include "pin_address_translator.h"
vector<ClosurePoint> Make_Guesses(const string& analysis_directory, PIN_Scan*, double percent,
                                  const PIN_Address_Translator& trans);
vector<ClosurePoint> TryFindGuessFile(const string& analysis_dir);
VOID OutputGuessFile(const string& analysis_dir, const vector<ClosurePoint>& guesses);
