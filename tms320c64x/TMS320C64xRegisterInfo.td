// TMS320C64xRegisterInfo.td - TMS320C64x Register Defs

// We use the reserved condition b111 to signify that this register cannot be
// used for a conditional operation.
class TMS320C64xReg<string n, bits<5> num, bit file, bits<3> condition = 7> : Register<n> {
    let HWEncoding{15-5} = 0;
    let HWEncoding{4-0} = num;
    field bit File = file;
    field bits<3> Condition = condition;
    let Namespace = "TMS320C64x";
}

class TMS320C64xControlReg<string n, bits<5> num, list<string> altNames = []> : Register<n, altNames> {
    let HWEncoding{15-5} = 0;
    let HWEncoding{4-0} = num;
    let Namespace = "TMS320C64x";
}

// Registers

// DwarfRegNum values are arbitrary!
def A0  : TMS320C64xReg<"A0",  0,  0, 6>, DwarfRegNum<[0]>;
def A1  : TMS320C64xReg<"A1",  1,  0, 4>, DwarfRegNum<[1]>;
def A2  : TMS320C64xReg<"A2",  2,  0, 5>, DwarfRegNum<[2]>;
def A3  : TMS320C64xReg<"A3",  3,  0>, DwarfRegNum<[3]>;
def A4  : TMS320C64xReg<"A4",  4,  0>, DwarfRegNum<[4]>;
def A5  : TMS320C64xReg<"A5",  5,  0>, DwarfRegNum<[5]>;
def A6  : TMS320C64xReg<"A6",  6,  0>, DwarfRegNum<[6]>;
def A7  : TMS320C64xReg<"A7",  7,  0>, DwarfRegNum<[7]>;
def A8  : TMS320C64xReg<"A8",  8,  0>, DwarfRegNum<[8]>;
def A9  : TMS320C64xReg<"A9",  9,  0>, DwarfRegNum<[9]>;
def A10 : TMS320C64xReg<"A10", 10, 0>, DwarfRegNum<[10]>;
def A11 : TMS320C64xReg<"A11", 11, 0>, DwarfRegNum<[11]>;
def A12 : TMS320C64xReg<"A12", 12, 0>, DwarfRegNum<[12]>;
def A13 : TMS320C64xReg<"A13", 13, 0>, DwarfRegNum<[13]>;
def A14 : TMS320C64xReg<"A14", 14, 0>, DwarfRegNum<[14]>;
def A15 : TMS320C64xReg<"A15", 15, 0>, DwarfRegNum<[15]>;
def A16 : TMS320C64xReg<"A16", 16, 0>, DwarfRegNum<[16]>;
def A17 : TMS320C64xReg<"A17", 17, 0>, DwarfRegNum<[17]>;
def A18 : TMS320C64xReg<"A18", 18, 0>, DwarfRegNum<[18]>;
def A19 : TMS320C64xReg<"A19", 19, 0>, DwarfRegNum<[19]>;
def A20 : TMS320C64xReg<"A20", 20, 0>, DwarfRegNum<[20]>;
def A21 : TMS320C64xReg<"A21", 21, 0>, DwarfRegNum<[21]>;
def A22 : TMS320C64xReg<"A22", 22, 0>, DwarfRegNum<[22]>;
def A23 : TMS320C64xReg<"A23", 23, 0>, DwarfRegNum<[23]>;
def A24 : TMS320C64xReg<"A24", 24, 0>, DwarfRegNum<[24]>;
def A25 : TMS320C64xReg<"A25", 25, 0>, DwarfRegNum<[25]>;
def A26 : TMS320C64xReg<"A26", 26, 0>, DwarfRegNum<[26]>;
def A27 : TMS320C64xReg<"A27", 27, 0>, DwarfRegNum<[27]>;
def A28 : TMS320C64xReg<"A28", 28, 0>, DwarfRegNum<[28]>;
def A29 : TMS320C64xReg<"A29", 29, 0>, DwarfRegNum<[29]>;
def A30 : TMS320C64xReg<"A30", 30, 0>, DwarfRegNum<[30]>;
def A31 : TMS320C64xReg<"A31", 31, 0>, DwarfRegNum<[31]>;
def B0  : TMS320C64xReg<"B0",  0,  1, 1>, DwarfRegNum<[32]>;
def B1  : TMS320C64xReg<"B1",  1,  1, 2>, DwarfRegNum<[33]>;
def B2  : TMS320C64xReg<"B2",  2,  1, 3>, DwarfRegNum<[34]>;
def B3  : TMS320C64xReg<"B3",  3,  1>, DwarfRegNum<[35]>;
def B4  : TMS320C64xReg<"B4",  4,  1>, DwarfRegNum<[36]>;
def B5  : TMS320C64xReg<"B5",  5,  1>, DwarfRegNum<[37]>;
def B6  : TMS320C64xReg<"B6",  6,  1>, DwarfRegNum<[38]>;
def B7  : TMS320C64xReg<"B7",  7,  1>, DwarfRegNum<[39]>;
def B8  : TMS320C64xReg<"B8",  8,  1>, DwarfRegNum<[40]>;
def B9  : TMS320C64xReg<"B9",  9,  1>, DwarfRegNum<[41]>;
def B10 : TMS320C64xReg<"B10", 10, 1>, DwarfRegNum<[42]>;
def B11 : TMS320C64xReg<"B11", 11, 1>, DwarfRegNum<[43]>;
def B12 : TMS320C64xReg<"B12", 12, 1>, DwarfRegNum<[44]>;
def B13 : TMS320C64xReg<"B13", 13, 1>, DwarfRegNum<[45]>;
def B14 : TMS320C64xReg<"B14", 14, 1>, DwarfRegNum<[46]>;
def B15 : TMS320C64xReg<"B15", 15, 1>, DwarfRegNum<[47]>;
def B16 : TMS320C64xReg<"B16", 16, 1>, DwarfRegNum<[48]>;
def B17 : TMS320C64xReg<"B17", 17, 1>, DwarfRegNum<[49]>;
def B18 : TMS320C64xReg<"B18", 18, 1>, DwarfRegNum<[50]>;
def B19 : TMS320C64xReg<"B19", 19, 1>, DwarfRegNum<[51]>;
def B20 : TMS320C64xReg<"B20", 20, 1>, DwarfRegNum<[52]>;
def B21 : TMS320C64xReg<"B21", 21, 1>, DwarfRegNum<[53]>;
def B22 : TMS320C64xReg<"B22", 22, 1>, DwarfRegNum<[54]>;
def B23 : TMS320C64xReg<"B23", 23, 1>, DwarfRegNum<[55]>;
def B24 : TMS320C64xReg<"B24", 24, 1>, DwarfRegNum<[56]>;
def B25 : TMS320C64xReg<"B25", 25, 1>, DwarfRegNum<[57]>;
def B26 : TMS320C64xReg<"B26", 26, 1>, DwarfRegNum<[58]>;
def B27 : TMS320C64xReg<"B27", 27, 1>, DwarfRegNum<[59]>;
def B28 : TMS320C64xReg<"B28", 28, 1>, DwarfRegNum<[60]>;
def B29 : TMS320C64xReg<"B29", 29, 1>, DwarfRegNum<[61]>;
def B30 : TMS320C64xReg<"B30", 30, 1>, DwarfRegNum<[62]>;
def B31 : TMS320C64xReg<"B31", 31, 1>, DwarfRegNum<[63]>;

def AMR    : TMS320C64xControlReg<"AMR",     0>, DwarfRegNum<[64]>;
def CSR    : TMS320C64xControlReg<"CSR",     1>, DwarfRegNum<[65]>;
def DIER   : TMS320C64xControlReg<"DIER",   25>, DwarfRegNum<[66]>;
def DNUM   : TMS320C64xControlReg<"DNUM",   17>, DwarfRegNum<[67]>;
def ECR    : TMS320C64xControlReg<"ECR",    29, ["EFR"]>, DwarfRegNum<[68]>; // ECR when written, EFR when read
def GFPGFR : TMS320C64xControlReg<"GFPGFR", 24>, DwarfRegNum<[69]>;
def GPLYA  : TMS320C64xControlReg<"GPLYA",  22>, DwarfRegNum<[70]>;
def GPLYB  : TMS320C64xControlReg<"GPLYB",  23>, DwarfRegNum<[71]>;
def ICR    : TMS320C64xControlReg<"ICR",     3>, DwarfRegNum<[72]>;
def IER    : TMS320C64xControlReg<"IER",     4>, DwarfRegNum<[73]>;
def IERR   : TMS320C64xControlReg<"IERR",   31>, DwarfRegNum<[74]>;
def ILC    : TMS320C64xControlReg<"ILC",    13>, DwarfRegNum<[75]>;
def IRP    : TMS320C64xControlReg<"IRP",     6>, DwarfRegNum<[76]>;
def ISR    : TMS320C64xControlReg<"ISR",     2, ["IFR"]>, DwarfRegNum<[77]>; // ISR when written, IFR when read
def ISTP   : TMS320C64xControlReg<"ISTP",    5>, DwarfRegNum<[78]>;
def ITSR   : TMS320C64xControlReg<"ITSR",   27>, DwarfRegNum<[79]>;
def NRP    : TMS320C64xControlReg<"NRP",     7>, DwarfRegNum<[80]>;
def NTSR   : TMS320C64xControlReg<"NTSR",   28>, DwarfRegNum<[81]>;
def PCE1   : TMS320C64xControlReg<"PCE1",   16>, DwarfRegNum<[82]>;
def REP    : TMS320C64xControlReg<"REP",    15>, DwarfRegNum<[83]>;
def RILC   : TMS320C64xControlReg<"RILC",   14>, DwarfRegNum<[84]>;
def SSR    : TMS320C64xControlReg<"SSR",    21>, DwarfRegNum<[85]>;
def TSCH   : TMS320C64xControlReg<"TSCH",   11>, DwarfRegNum<[86]>;
def TSCL   : TMS320C64xControlReg<"TSCL",   10>, DwarfRegNum<[87]>;
def TSR    : TMS320C64xControlReg<"TSR",    26>, DwarfRegNum<[88]>;

// Register classes

// General purpose registers
def GPRegs : RegisterClass<"TMS320C64x", [i32], 32,
    (add A0, A1, A2, A3, A4, A5, A6, A7,
    A8, A9, A10, A11, A12, A13, A14, A15,
    A16, A17, A18, A19, A20, A21, A22, A23,
    A24, A25, A26, A27, A28, A29, A30, A31,
    B0, B1, B2, B3, B4, B5, B6, B7,
    B8, B9, B10, B11, B12, B13, B14, B15,
    B16, B17, B18, B19, B20, B21, B22, B23,
    B24, B25, B26, B27, B28, B29, B30, B31)>;

// Register file A
def AFRegs : RegisterClass<"TMS320C64x", [i32], 32,
    (add A0, A1, A2, A3, A4, A5, A6, A7,
    A8, A9, A10, A11, A12, A13, A14, A15,
    A16, A17, A18, A19, A20, A21, A22, A23,
    A24, A25, A26, A27, A28, A29, A30, A31)>;

// Register file B
def BFRegs : RegisterClass<"TMS320C64x", [i32], 32,
    (add B0, B1, B2, B3, B4, B5, B6, B7,
    B8, B9, B10, B11, B12, B13, B14, B15,
    B16, B17, B18, B19, B20, B21, B22, B23,
    B24, B25, B26, B27, B28, B29, B30, B31)>;

// Control registers
def ControlRegs : RegisterClass<"TMS320C64x", [i32], 32,
    (add AMR, CSR, DIER, DNUM, ECR, GFPGFR, GPLYA, GPLYB,
    ICR, IER, IERR, ILC, IRP, ISR, ISTP, ITSR, NRP, NTSR,
    PCE1, REP, RILC, SSR, TSCH, TSCL, TSR)>;
