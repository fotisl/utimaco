// TMS320C64x.td - Describe the TMS320C64x architecture
// Fotis Loukos <me@fotisl.com>

include "llvm/Target/Target.td"

include "TMS320C64xRegisterInfo.td"
include "TMS320C64xInstrInfo.td"
include "TMS320C64xCallingConv.td"

// Processors
class Proc<string Name, list<SubtargetFeature> Features>
    : Processor<Name, NoItineraries, Features>;

def : Proc<"generic", []>;

// Instruction Set
def TMS320C64xInstrInfo : InstrInfo;

def TMS320C64x : Target {
    let InstructionSet = TMS320C64xInstrInfo;
}
