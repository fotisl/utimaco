// TMS320C64xInstrInfo.td - TMS320C64x Instructions

// Include formats superclass
include "TMS320C64xInstrFormats.td"

// Functional unit .D

defm ADD : TMS320C64xInstD1_ri<0b010000, 0b010010,
    "ADD\t$src2, $src1, $dst", "ADD\t$src2, $src1, $dst">;

def ADD_d2_rrr : TMS320C64xInstD2<0b1010,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "ADD\t$src1, $src2, $dst",
    []>;

def ADD_d2_rir : TMS320C64xInstD2<0b1011,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, scst5:$src1 ),
    "ADD\t$src2, $src1, $dst",
    []>;

defm ADDAB : TMS320C64xInstD1_ri<0b110000, 0b110010,
    "ADDAB\t$src2, $src1, $dst", "ADDAB\t$src2, $src1, $dst">;

defm ADDAD : TMS320C64xInstD1_ri<0b111100, 0b111101,
    "ADDAD\t$src2, $src1, $dst", "ADDAD\t$src2, $src1, $dst">;

defm ADDAH : TMS320C64xInstD1_ri<0b110100, 0b110110,
    "ADDAH\t$src2, $src1, $dst", "ADDAH\t$src2, $src1, $dst">;

defm ADDAW : TMS320C64xInstD1_ri<0b111000, 0b111010,
    "ADDAW\t$src2, $src1, $dst", "ADDAW\t$src2, $src1, $dst">;

def ADD2_d2_rrr : TMS320C64xInstD2<0b0100,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "ADD2\t$src1, $src2, $dst",
    []>;

def AND_d2_rrr : TMS320C64xInstD2<0b0110,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "AND\t$src1, $src2, $dst",
    []>;

def AND_d2_rir : TMS320C64xInstD2<0b0111,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, scst5:$src1 ),
    "AND\t$src1, $src2, $dst",
    []>;

def ANDN_d2_rrr : TMS320C64xInstD2<0b0000,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "ANDN\t$src1, $src2, $dst",
    []>;

defm LDB : TMS320C64xInstD56_memld<0b010, "LDB">;

defm LDBU : TMS320C64xInstD56_memld<0b001, "LDBU">;

def LDDW_d7_mp : TMS320C64xInstD7<0b110,
    ( outs regpair5:$srcdst ),
    ( ins memop:$baseoffsetmodeunit ),
    "LDDW\t$baseoffsetmodeunit, $srcdst",
    []>;

defm LDH : TMS320C64xInstD56_memld<0b100, "LDH">;

defm LDHU : TMS320C64xInstD56_memld<0b000, "LDHU">;

def LDNDW_d8_mp : TMS320C64xInstD8<0b010,
    ( outs regpair4:$srcdst ),
    ( ins memopsc:$baseoffsetmodeunit ),
    "LDNDW\t$baseoffsetmodeunit, $srcdst",
    []>;

def LDNW_d5_mr : TMS320C64xInstD5<1, 0b011,
    ( outs GPRegs:$srcdst ),
    ( ins memop:$baseoffsetmodeunit ),
    "LDNW\t$baseoffsetmodeunit, $srcdst",
    []>;

defm LDW : TMS320C64xInstD56_memld<0b110, "LDW">;

def MVK_d1_rr : TMS320C64xInstD1<0b000000,
    ( outs GPRegs:$dst ),
    ( ins scst5:$src1 ),
    "MVK\t$src1, $dst",
    []>
{
    let Inst{22-18} = 0b00000;
}

def OR_d2_rrr : TMS320C64xInstD2<0b0010,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "OR\t$src1, $src2, $dst",
    []>;

def OR_d2_rir : TMS320C64xInstD2<0b0011,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, scst5:$src1 ),
    "OR\t$src1, $src2, $dst",
    []>;

defm STB : TMS320C64xInstD56_memst<0b011, "STB">;

def STDW_d7_pm : TMS320C64xInstD7<0b100,
    ( outs regpair5:$srcdst ),
    ( ins memop:$baseoffsetmodeunit ),
    "STDW\t$srcdst, $baseoffsetmodeunit",
    []>;

defm STH : TMS320C64xInstD56_memst<0b101, "STH">;

def STNDW_d8_pm : TMS320C64xInstD8<0b111,
    ( outs regpair4:$srcdst ),
    ( ins memopsc:$baseoffsetmodeunit ),
    "STNDW\t$srcdst, $baseoffsetmodeunit",
    []>;

def STNW_d5_rm : TMS320C64xInstD5<1, 0b101,
    ( outs GPRegs:$srcdst ),
    ( ins memop:$baseoffsetmodeunit ),
    "STNW\t$srcdst, $baseoffsetmodeunit",
    []>;

defm STW : TMS320C64xInstD56_memst<0b111, "STW">;

defm SUB : TMS320C64xInstD1_ri<0b010001, 0b010011,
    "SUB\t$src2, $src1, $dst", "SUB\t$src2, $src1, $dst">;

def SUB_d2_rrr : TMS320C64xInstD2<0b1100,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SUB\t$src1, $src2, $dst",
    []>;

defm SUBAB : TMS320C64xInstD1_ri<0b110001, 0b110011,
    "SUBAB\t$src2, $src1, $dst", "SUBAB\t$src2, $src1, $dst">;

defm SUBAH : TMS320C64xInstD1_ri<0b110101, 0b110111,
    "SUBAH\t$src2, $src1, $dst", "SUBAB\t$src2, $src1, $dst">;

defm SUBAW : TMS320C64xInstD1_ri<0b111001, 0b111011,
    "SUBAW\t$src2, $src1, $dst", "SUBAB\t$src2, $src1, $dst">;

def SUB2_d2_rrr : TMS320C64xInstD2<0b0101,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SUB2\t$src1, $src2, $dst",
    []>;

def XOR_d2_rrr : TMS320C64xInstD2<0b1110,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "XOR\t$src1, $src2, $dst",
    []>;

def XOR_d2_rir : TMS320C64xInstD2<0b1111,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, scst5:$src1 ),
    "XOR\t$src1, $src2, $dst",
    []>;

// Functional unit .L

def ABS_l1_rr : TMS320C64xInstL1x2<0b0011010,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "ABS\t$src2, $dst",
    []>
{
    let Inst{17-13} = 0b00000;
}

def ABS_l1_pp : TMS320C64xInstL1x2<0b0111000,
    ( outs regpair5:$dst ),
    ( ins regpair5:$src2 ),
    "ABS\t$src2, $dst",
    []>
{
    let Inst{17-13} = 0b00000;
}

def ABS2_l2_rr : TMS320C64xInstL2<0b00100,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "ABS2\t$src2, $dst",
    []>;

defm ADD : TMS320C64xInstL1_rrr_x2<0b0000011, "ADD">;

defm ADD : TMS320C64xInstL1_rrp_x2<0b0100011, "ADD">;

defm ADD : TMS320C64xInstL1_rpp<0b0100001, "ADD">;

defm ADD : TMS320C64xInstL1_irr<0b0000010, "ADD">;

defm ADD : TMS320C64xInstL1_ipp<0b0100000, "ADD">;

defm ADDU : TMS320C64xInstL1_rrp_x2<0b0101011, "ADDU">;

defm ADDU : TMS320C64xInstL1_rpp<0b0101001, "ADDU">;

defm ADD2 : TMS320C64xInstL1_rrr_x2<0b0000101, "ADD2">;

defm ADD4 : TMS320C64xInstL1_rrr_x2<0b1100101, "ADD4">;

defm AND : TMS320C64xInstL1_rrr_x2<0b1111011, "AND">;

defm AND : TMS320C64xInstL1_irr<0b1111010, "AND">;

defm ANDN : TMS320C64xInstL1_rrr_x2<0b1111100, "ANDN">;

defm CMPEQ : TMS320C64xInstL1_cmp<0b1010011, 0b1010010, 0b1010001, 0b1010000, "CMPEQ">;

defm CMPGT : TMS320C64xInstL1_cmp<0b1000111, 0b1000110, 0b1000101, 0b1000100, "CMPGT">;

defm GMPGTU : TMS320C64xInstL1_cmpu<0b1001111, 0b1001110, 0b1001101, 0b1001100, "CMPGTU">;

defm CMPLT : TMS320C64xInstL1_cmp<0b1010111, 0b1010110, 0b1010101, 0b1010100, "CMPLT">;

defm CMPLTU : TMS320C64xInstL1_cmpu<0b1011111, 0b1011110, 0b1011101, 0b1011100, "CMPLTU">;

defm LMBD : TMS320C64xInstL1_rrr_x2<0b1101011, "LMBD">;

defm LMBD : TMS320C64xInstL1_irr<0b1101010, "LMBD">;

defm MAX2 : TMS320C64xInstL1_rrr_x2<0b1000010, "MAX2">;

defm MAXU4 : TMS320C64xInstL1_rrr_x2<0b1000011, "MAXU4">;

defm MIN2 : TMS320C64xInstL1_rrr_x2<0b1000001, "MIN2">;

defm MINU4 : TMS320C64xInstL1_rrr_x2<0b1001000, "MINU4">;

def MVK_l2_ir : TMS320C64xInstL2<0b00101,
    ( outs GPRegs:$dst ),
    ( ins scst5:$src2 ),
    "MVK\t$src2, $dst",
    []>;

def NORM_l1_rr : TMS320C64xInstL1x2<0b1100011,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "NORM\t$src2, $dst",
    []>
{
    let Inst{17-13} = 0b00000;
}

def NORM_l1_pr : TMS320C64xInstL1x2<0b1100000,
    ( outs GPRegs:$dst ),
    ( ins regpair5:$src2 ),
    "NORM\t$src2, $dst",
    []>
{
    let Inst{17-13} = 0b00000;
}

defm OR : TMS320C64xInstL1_rrr_x2<0b1111111, "OR">;

defm OR : TMS320C64xInstL1_irr<0b1111110, "OR">;

defm PACK2 : TMS320C64xInstL1_rrr_x2<0b0000000, "PACK2">;

defm PACKH2 : TMS320C64xInstL1_rrr_x2<0b0011110, "PACKH2">;

defm PACKH4 : TMS320C64xInstL1_rrr_x2<0b1101001, "PACKH4">;

defm PACKHL2 : TMS320C64xInstL1_rrr_x2<0b0011100, "PACKHL2">;

defm PACKLH2 : TMS320C64xInstL1_rrr_x2<0b0011011, "PACKLH2">;

defm PACKL4 : TMS320C64xInstL1_rrr_x2<0b1101000, "PACKL4">;

defm SADD : TMS320C64xInstL1_rrr_x2<0b0010011, "SADD">;

defm SADD : TMS320C64xInstL1_rpp<0b0110001, "SADD">;

defm SADD : TMS320C64xInstL1_irr<0b0010010, "SADD">;

defm SADD : TMS320C64xInstL1_ipp<0b0110000, "SADD">;

def SAT_l1_pr : TMS320C64xInstL1x1<0b1000000,
    ( outs GPRegs:$dst ),
    ( ins regpair5:$src2 ),
    "SAT\t$src2, $dst",
    []>
{
    let Inst{17-13} = 0b00000;
}

defm SHLMB : TMS320C64xInstL1_rrr_x2<0b1100001, "SHLMB">;

defm SHRMB : TMS320C64xInstL1_rrr_x2<0b1100010, "SHRMB">;

defm SSUB : TMS320C64xInstL1_rrr_x2<0b0001111, "SSUB">;

defm SSUB : TMS320C64xInstL1_rrr_x1<0b0011111, "SSUB">;

defm SSUB : TMS320C64xInstL1_irr<0b0001110, "SSUB">;

defm SSUB : TMS320C64xInstL1_ipp<0b0101100, "SSUB">;

defm SUB : TMS320C64xInstL1_rrr_x2<0b0000111, "SUB">;

defm SUB : TMS320C64xInstL1_rrr_x1<0b0010111, "SUB">;

defm SUB : TMS320C64xInstL1_rrp_x2<0b0100111, "SUB">;

defm SUB : TMS320C64xInstL1_rrp_x1<0b0110111, "SUB">;

defm SUB : TMS320C64xInstL1_irr<0b0000110, "SUB">;

defm SUB : TMS320C64xInstL1_ipp<0b0100100, "SUB">;

defm SUBABS4 : TMS320C64xInstL1_rrr_x2<0b1011010, "SUBABS4">;

defm SUBC : TMS320C64xInstL1_rrr_x2<0b1001011, "SUBC">;

defm SUBU : TMS320C64xInstL1_rrp_x2<0b0101111, "SUBU">;

defm SUBU : TMS320C64xInstL1_rrp_x1<0b0111111, "SUBU">;

defm SUB2 : TMS320C64xInstL1_rrr_x2<0b0000100, "SUB2">;

defm SUB4 : TMS320C64xInstL1_rrr_x2<0b1100110, "SUB4">;

def SWAP4_l2_rr : TMS320C64xInstL2<0b00001,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "SWAP4\t$src2, $dst",
    []>;

def UNPKHU4_l2_rr : TMS320C64xInstL2<0b00011,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "UNPKHU4\t$src2, $dst",
    []>;

def UNPKLU4_l2_rr : TMS320C64xInstL2<0b00010,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "UNPKLU4\t$src2, $dst",
    []>;

defm XOR : TMS320C64xInstL1_rrr_x2<0b1101111, "XOR">;

defm XOR : TMS320C64xInstL1_irr<0b1101110, "XOR">;

// Functional unit .M

defm AVG2 : TMS320C64xInstM1_rrr<0b10011, "AVG2">;

defm AVGU4 : TMS320C64xInstM1_rrr<0b10010, "AVGU4">;

defm BITC4 : TMS320C64xInstM2_rr<0b11110, "BITC4">;

defm DEAL : TMS320C64xInstM2_rr<0b11101, "DEAL">;

defm DOTP2 : TMS320C64xInstM1_rrr<0b01100, "DOTP2">;

defm DOTP2 : TMS320C64xInstM1_rrp<0b01011, "DOTP2">;

defm DOTPN2 : TMS320C64xInstM1_rrr<0b01001, "DOTPN2">;

defm DOTPNRSU2 : TMS320C64xInstM1_rrr<0b00111, "DOTPNRSU2">;

/* DOTPNRUS2 is an alias of DOTPNRSU2 with src1 and src2 exchanged */

defm DOTPRSU2 : TMS320C64xInstM1_rrr<0b01101, "DOTPRSU2">;

/* DOTPRUS2 is an alias of DOTPRSU2 with src1 and src2 exchanged */

defm DOTPSU4 : TMS320C64xInstM1_rrr<0b00010, "DOTPSU4">;

/* DOTPUS4 is an alias of DOTPSU4 with src1 and src2 exchanged */

defm DOTPU4 : TMS320C64xInstM1_rrr<0b00110, "DOTPU4">;

defm GMPY4 : TMS320C64xInstM1_rrr<0b10001, "GMPY4">;

defm MPY : TMS320C64xInstM4_rrr<0b11001, "MPY">;

defm MPY : TMS320C64xInstM4_irr<0b11000, "MPY">;

defm MPYH : TMS320C64xInstM4_rrr<0b00001, "MPYH">;

defm MPYHI : TMS320C64xInstM1_rrp<0b10100, "MPYHI">;

defm MPYHIR : TMS320C64xInstM1_rrr<0b10000, "MPYHIR">;

defm MPYHL : TMS320C64xInstM4_rrr<0b01001, "MPYHL">;

defm MPYHLU : TMS320C64xInstM4_rrr<0b01111, "MPYHLU">;

defm MPYHSLU : TMS320C64xInstM4_rrr<0b01011, "MPYHSLU">;

defm MPYHSU : TMS320C64xInstM4_rrr<0b00011, "MPYHSU">;

defm MPYHU : TMS320C64xInstM4_rrr<0b00111, "MPYHU">;

defm MPYHULS : TMS320C64xInstM4_rrr<0b01101, "MPYHULS">;

defm MPYHUS : TMS320C64xInstM4_rrr<0b00101, "MPYHUS">;

/* MPYIH is an alias of MPYHI with src1 and src2 exchanged */

/* MPYIHR is an alias of MPYHIR with src1 and src2 exchanged */

/* MPYIL is an alias of MPYLI with src1 and src2 exchanged */

/* MPYILR is an alias of MPYLIR with src1 and src2 exchanged */

defm MPYLH : TMS320C64xInstM4_rrr<0b10001, "MPYLH">;

defm MPYLHU : TMS320C64xInstM4_rrr<0b10111, "MPYLHU">;

defm MPYLI : TMS320C64xInstM1_rrp<0b10101, "MPYLI">;

defm MPYLIR : TMS320C64xInstM1_rrr<0b01110, "MPYLIR">;

defm MPYLSHU : TMS320C64xInstM4_rrr<0b10011, "MPYLSHU">;

defm MPYLUHS : TMS320C64xInstM4_rrr<0b10101, "MPYLUHS">;

defm MPYSU : TMS320C64xInstM4_rrr<0b11011, "MPYSU">;

defm MPYSU : TMS320C64xInstM4_irr<0b11110, "MPYSU">;

defm MPYSU4 : TMS320C64xInstM1_rrp<0b00101, "MPYSU4">;

defm MPYU : TMS320C64xInstM4_rrr<0b11111, "MPYU">;

defm MPYU4 : TMS320C64xInstM1_rrp<0b00100, "MPYU4">;

defm MPYUS : TMS320C64xInstM4_rrr<0b11101, "MPYUS">;

/* MPYUS4 is an alias of MPYSU4 with src1 and src2 exchanged */

defm MPY2 : TMS320C64xInstM1_rrp<0b00000, "MPY2">;

defm MVD : TMS320C64xInstM2_rr<0b11010, "MVD">;

def ROTL_m1_rrr : TMS320C64xInstM1<0b11101,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "ROTL\t$src2, $src1, $dst",
    []>;

def ROTL_m1_rir : TMS320C64xInstM1<0b11110,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "ROTL\t$src2, $src1, $dst",
    []>;

defm SHFL : TMS320C64xInstM2_rr<0b11100, "SHFL">;

defm SMPY : TMS320C64xInstM4_rrr<0b11010, "SMPY">;

defm SMPYH : TMS320C64xInstM4_rrr<0b00010, "SMPYH">;

defm SMPYHL : TMS320C64xInstM4_rrr<0b01010, "SMPYHL">;

defm SMPYLH : TMS320C64xInstM4_rrr<0b10010, "SMPYLH">;

defm SMPY2 : TMS320C64xInstM1_rrp<0b00001, "SMPY2">;

defm SSHVL : TMS320C64xInstM1_rrr<0b11100, "SSHVL">;

defm SSHVR : TMS320C64xInstM1_rrr<0b11010, "SSHVR">;

defm XPND2 : TMS320C64xInstM2_rr<0b11001, "XPND2">;

defm XPND4 : TMS320C64xInstM2_rr<0b11000, "XPND4">;

// Functional unit .S

defm ADD : TMS320C64xInstS1_rrr<0b000111, "ADD">;

defm ADD : TMS320C64xInstS1_irr<0b000110, "ADD">;

def ADDK_s2_ir : TMS320C64xInstS2<
    ( outs GPRegs:$dst ),
    ( ins scst16:$const ),
    "ADDK\t$const, $dst",
    []>;

def ADDKPC_s3_iir : TMS320C64xInstS3<
    ( outs GPRegs:$dst ),
    ( ins pcrelscst7:$src1, ucst3:$src2 ),
    "ADDKPC\t$src1, $dst, $src2",
    []>;

defm ADD2 : TMS320C64xInstS1_rrr<0b000001, "ADD2">;

defm AND : TMS320C64xInstS1_rrr<0b011111, "AND">;

defm AND : TMS320C64xInstS1_irr<0b011110, "AND">;

defm ANDN : TMS320C64xInstS4_rrr<0b0110, "ANDN">;

def B_s5_i : TMS320C64xInstS5<
    ( outs ),
    ( ins pcrelscst21:$const ),
    "B\t$const",
    []>;

def B_s6_r : TMS320C64xInstS6<
    ( outs ),
    ( ins GPRegs:$src2 ),
    "B\t$src2",
    []>;

def B_s7_irp : TMS320C64xInstS7<0b110,
    ( outs ),
    ( ins ),
    "B\tIRP",
    []>;

def B_s7_nrp : TMS320C64xInstS7<0b111,
    ( outs ),
    ( ins ),
    "B\tNRP",
    []>;

def BDEC_s8_ir : TMS320C64xInstS8<0b1,
    ( outs ),
    ( ins GPRegs:$dst, pcrelscst10:$src ),
    "BDEC\t$src, $dst",
    []>;

def BNOP_s9_ii : TMS320C64xInstS9<
    ( outs ),
    ( ins pcrelscst12:$src2, ucst3:$src1 ),
    "BNOP\t$src2, $src1",
    []>;

def BNOP_s10_ri : TMS320C64xInstS10<
    ( outs ),
    ( ins GPRegs:$src2, ucst3:$src1 ),
    "BNOP\t$src2, $src1",
    []>;

def BPOS_s8_ir : TMS320C64xInstS8<0b0,
    ( outs ),
    ( ins GPRegs:$dst, pcrelscst10:$src ),
    "BPOS\t$src, $dst",
    []>;

defm CLR : TMS320C64xInstS115_bf<0b11, 0b111111, "CLR">;

defm CMPEQ2 : TMS320C64xInstS1_rrr<0b011101, "CMPEQ2">;

defm CMPEQ4 : TMS320C64xInstS1_rrr<0b011100, "CMPEQ4">;

defm CMPGT2 : TMS320C64xInstS1_rrr<0b010100, "CMPGT2">;

defm CMPGTU4 : TMS320C64xInstS1_rrr<0b010101, "CMPGTU4">;

/* CMPLT2 is an alias of CMPGT2 with src1 and src2 exchanged */

/* CMPLTU4 is an alias of CMPGTU4 with src1 and src2 exchanged */

defm EXT : TMS320C64xInstS115_bf<0b01, 0b101111, "EXT">;

defm EXTU : TMS320C64xInstS115_bf<0b00, 0b101011, "EXTU">;

def MVC_s1_rr : TMS320C64xInstS1X2<0b001111,
    ( outs GPRegs:$dst ),
    ( ins ControlRegs:$src2 ),
    "MVC\t$src2, $dst",
    []>
{
    let Inst{17-13} = 0b00000;
}

def MVC_s1_rr2 : TMS320C64xInstS1X2<0b001110,
    ( outs ControlRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "MVC\t$src2, $dst",
    []>
{
    let Inst{17-13} = 0b00000;
}

/* MVK is the same as MVKL (with the warning if compiling but we're creating a disassembler */

/* MVKH is the same as MVKLH but with a shifted constant */

def MVKL_s12_ir : TMS320C64xInstS12<0b0,
    ( outs GPRegs:$dst ),
    ( ins scst16:$const ),
    "MVK\t$const, $dst",
    []>;

def MVKLH_s12_ir : TMS320C64xInstS12<0b1,
    ( outs GPRegs:$dst ),
    ( ins scst16:$const ),
    "MVKLH\t$const, $dst",
    []>;

defm OR : TMS320C64xInstS1_rrr<0b011011, "OR">;

defm OR : TMS320C64xInstS1_irr<0b011010, "OR">;

defm PACK2 : TMS320C64xInstS4_rrr<0b1111, "PACK2">;

defm PACKH2 : TMS320C64xInstS1_rrr<0b001001, "PACKH2">;

defm PACKHL2 : TMS320C64xInstS1_rrr<0b001000, "PACKHL2">;

defm PACKLH2 : TMS320C64xInstS1_rrr<0b010000, "PACKLH2">;

defm SADD : TMS320C64xInstS1_rrr<0b100000, "SADD">;

defm SADD2 : TMS320C64xInstS4_rrr<0b0000, "SADD2">;

/* SADDSU2 is an alias of SADDUS2 with src1 and src2 exchanged */

defm SADDUS2 : TMS320C64xInstS4_rrr<0b0001, "SADDUS2">;

defm SADDU4 : TMS320C64xInstS4_rrr<0b0011, "SADDU4">;

defm SET : TMS320C64xInstS115_bf<0b10, 0b111011, "SET">;

def SHL_s1_rrr : TMS320C64xInstS1X1<0b110011,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SHL\t$src2, $src1, $dst",
    []>;

def SHL_s1_prp : TMS320C64xInstS1X1<0b110001,
    ( outs regpair5:$dst ),
    ( ins regpair5:$src2, GPRegs:$src1 ),
    "SHL\t$src2, $src1, $dst",
    []>;

def SHL_s1_rrp : TMS320C64xInstS1X1<0b010011,
    ( outs regpair5:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SHL\t$src2, $src1, $dst",
    []>;

def SHL_s1_rir : TMS320C64xInstS1X1<0b110010,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "SHL\t$src2, $src1, $dst",
    []>;

def SHL_s1_pip : TMS320C64xInstS1X1<0b110000,
    ( outs regpair5:$dst ),
    ( ins regpair5:$src2, ucst5:$src1 ),
    "SHL\t$src2, $src1, $dst",
    []>;

def SHL_s1_rip : TMS320C64xInstS1X1<0b010010,
    ( outs regpair5:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "SHL\t$src2, $src1, $dst",
    []>;

defm SHLMB : TMS320C64xInstS4_rrr<0b1001, "SHLMB">;

def SHR_s1_rrr : TMS320C64xInstS1X2<0b110111,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SHR\t$src2, $src1, $dst",
    []>;

def SHR_s1_prp : TMS320C64xInstS1X2<0b110101,
    ( outs regpair5:$dst ),
    ( ins regpair5:$src2, GPRegs:$src1 ),
    "SHR\t$src2, $src1, $dst",
    []>;

def SHR_s1_rir : TMS320C64xInstS1X2<0b110110,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "SHR\t$src2, $src1, $dst",
    []>;

def SHR_s1_pip : TMS320C64xInstS1X2<0b110100,
    ( outs regpair5:$dst ),
    ( ins regpair5:$src2, ucst5:$src1 ),
    "SHR\t$src2, $src1, $dst",
    []>;

def SHR2_s4_rrr : TMS320C64xInstS4<0b0111,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SHR2\t$src2, $src1, $dst",
    []>;

def SHR2_s1_rir : TMS320C64xInstS1X2<0b011000,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "SHR2\t$src2, $src1, $dst",
    []>;

defm SHRMB : TMS320C64xInstS4_rrr<0b1010, "SHRMB">;

def SHRU_s1_rrr : TMS320C64xInstS1X2<0b100111,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SHRU\t$src2, $src1, $dst",
    []>;

def SHRU_s1_prp : TMS320C64xInstS1X2<0b100101,
    ( outs regpair5:$dst ),
    ( ins regpair5:$src2, GPRegs:$src1 ),
    "SHRU\t$src2, $src1, $dst",
    []>;

def SHRU_s1_rir : TMS320C64xInstS1X2<0b100110,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "SHRU\t$src2, $src1, $dst",
    []>;

def SHRU_s1_pip : TMS320C64xInstS1X2<0b100100,
    ( outs regpair5:$dst ),
    ( ins regpair5:$src2, ucst5:$src1 ),
    "SHRU\t$src2, $src1, $dst",
    []>;

def SHRU2_s4_rrr : TMS320C64xInstS4<0b1000,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SHRU2\t$src2, $src1, $dst",
    []>;

def SHRU2_s1_rir : TMS320C64xInstS1X2<0b011001,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "SHRU2\t$src2, $src1, $dst",
    []>;

defm SPACK2 : TMS320C64xInstS4_rrr<0b0010, "SPACK2">;

defm SPACKU4 : TMS320C64xInstS4_rrr<0b0100, "SPACKU4">;

def SSHL_s1_rrr : TMS320C64xInstS1X2<0b100011,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SSHL\t$src2, $src1, $dst",
    []>;

def SSHL_s1_rir : TMS320C64xInstS1X2<0b100010,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, ucst5:$src1 ),
    "SSHL\t$src2, $src1, $dst",
    []>;

defm SUB : TMS320C64xInstS1_rrr<0b010111, "SUB">;

defm SUB : TMS320C64xInstS1_irr<0b010110, "SUB">;

def SUB_s4_rrr : TMS320C64xInstS4<0b0101,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2, GPRegs:$src1 ),
    "SUB\t$src2, $src1, $dst",
    []>;

defm SUB2 : TMS320C64xInstS1_rrr<0b010001, "SUB2">;

def UNPKHU4_s14_rr : TMS320C64xInstS14<0b00011,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "UNPKHU4\t$src2, $dst",
    []>;

def UNPKLU4_s14_rr : TMS320C64xInstS14<0b00010,
    ( outs GPRegs:$dst ),
    ( ins GPRegs:$src2 ),
    "UNPKLU4\t$src2, $dst",
    []>;

defm XOR : TMS320C64xInstS1_rrr<0b001011, "XOR">;

defm XOR : TMS320C64xInstS1_irr<0b001010, "XOR">;

// No functional unit

def NOP_n : TMS320C64xInstNop<
    ( outs ),
    ( ins nopop:$op),
    "NOP\t\t$op",
    []>;
