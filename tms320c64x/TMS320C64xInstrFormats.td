// TMS320C64xInstrFormats.td - TMS320C64x Instruction Formats

// Instruction pattern stuff

def ucst3 : Operand<i32>, PatLeaf<(imm), [{ return isInt<3>(N->getZExtValue()); }]>;

def ucst5 : Operand<i32>, PatLeaf<(imm), [{ return isInt<5>(N->getZExtValue()); }]>;

def ucst15 : Operand<i32>, PatLeaf<(imm), [{ return isInt<15>(N->getZExtValue()); }]>;

def scst5 : Operand<i32>, PatLeaf<(imm), [{ return isInt<5>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeScst5";
    let EncoderMethod = "EncodeScst5";
}

def scst16 : Operand<i32>, PatLeaf<(imm), [{ return isInt<16>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeScst16";
    let EncoderMethod = "EncodeScst16";
}

def pcrelscst7 : Operand<i32>, PatLeaf<(imm), [{ return isInt<7>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodePCRelScst7";
    let EncoderMethod = "EncodePCRelScst7";
}

def pcrelscst10 : Operand<i32>, PatLeaf<(imm), [{ return isInt<10>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodePCRelScst10";
    let EncoderMethod = "EncodePCRelScst10";
}

def pcrelscst12 : Operand<i32>, PatLeaf<(imm), [{ return isInt<12>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodePCRelScst12";
    let EncoderMethod = "EncodePCRelScst12";
}

def pcrelscst21 : Operand<i32>, PatLeaf<(imm), [{ return isInt<21>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodePCRelScst21";
    let EncoderMethod = "EncodePCRelScst21";
}

def memop : Operand<i32>, PatLeaf<(imm), [{ return isInt<15>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeMemOperand";
    let EncoderMethod = "EncodeMemOperand";
    let PrintMethod = "printMemOperand";
}

def memopsc : Operand<i32>, PatLeaf<(imm), [{ return isInt<16>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeMemOperandSc";
    let EncoderMethod = "EncodeMemOperandSc";
    let PrintMethod = "printMemOperand";
}

def memop2 : Operand<i32>, PatLeaf<(imm), [{ return isInt<16>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeMemOperand2";
    let EncoderMethod = "EncodeMemOperand2";
    let PrintMethod = "printMemOperand2";
}

def regpair5 : Operand<i32>, PatLeaf<(imm), [{ return isInt<5>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeRegPair5";
    let EncoderMethod = "EncodeRegPair5";
    let PrintMethod = "printRegPair";
}

def regpair4 : Operand<i32>, PatLeaf<(imm), [{ return isInt<4>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeRegPair4";
    let EncoderMethod = "EncodeRegPair4";
    let PrintMethod = "printRegPair";
}

def condreg : Operand<i32>, PatLeaf<(imm), [{ return isInt<3>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeCondRegister";
    let EncoderMethod = "EncodeCondRegister";
}

def condregzero : Operand<i32>, PatLeaf<(imm), [{ return isInt<1>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeCondRegisterZero";
    let EncoderMethod = "EncodeCondRegisterZero";
}

def sideop : Operand<i32>, PatLeaf<(imm), [{ return isInt<1>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeSide";
    let EncoderMethod = "EncodeSide";
}

def parallelop : Operand<i32>, PatLeaf<(imm), [{ return isInt<1>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeParallel";
    let EncoderMethod = "EncodeParallel";
}

// Two different crosspath operands, depending on which operand they affect
// Operand number is the number of the operand while it is parsed from the opcode.
def crosspathopx1 : Operand<i32>, PatLeaf<(imm), [{ return isInt<1>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeCrosspathX1";
    let EncoderMethod = "EncodeCrosspath";
}

def crosspathopx2 : Operand<i32>, PatLeaf<(imm), [{ return isInt<1>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeCrosspathX2";
    let EncoderMethod = "EncodeCrosspath";
}

def crosspathopx3 : Operand<i32>, PatLeaf<(imm), [{ return isInt<1>(N->getZExtValue()); }]>
{
    let DecoderMethod = "DecodeCrosspathX3";
    let EncoderMethod = "EncodeCrosspath";
}

def nopop : Operand<i32>, PatLeaf<(imm), [{
    uint32_t value = (uint32_t)N->getZExtValue();
    return ((value >= 0) && (value <= 8)) || (value == 15);
}]>
{
    let DecoderMethod = "DecodeNop";
    let EncoderMethod = "EncodeNop";
}

// Instruction format superclass
class TMS320C64xInst<dag outops, dag inops, string asmstr, list<dag> pattern> : Instruction {
    field bits<32> Inst;
    field bits<32> SoftFail = 0;
    bits<3> cond;
    bit condzero;
    bit side;
    bit parallel;

    let OutOperandList = outops;
    let InOperandList = !con(inops, (ins condreg:$cond, condregzero:$condzero, sideop:$side, parallelop:$parallel));
    let AsmString = asmstr;
    let Pattern = pattern;

    let Inst{31-29} = cond;
    let Inst{28} = condzero;
    let Inst{1} = side;
    let Inst{0} = parallel;
    let Size = 4;
    let isPredicable = 1;
    let hasSideEffects = 0;
    let Namespace = "TMS320C64x";
}

// Functional unit .D

class TMS320C64xInstD1<bits<6> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bits<6> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12-7} = op;
    let Inst{6-2} = 0b10000;
}

multiclass TMS320C64xInstD1_ri<bits<6> opVal1, bits<6> opVal2, string asmstr1, string asmstr2> {
    def _d1_rrr : TMS320C64xInstD1<opVal1, ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        asmstr1, []>;
    def _d1_rir : TMS320C64xInstD1<opVal2, ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, ucst5:$src1 ),
        asmstr2, []>;
}

class TMS320C64xInstD2<bits<4> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<4> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{9-6} = op;
    let Inst{11-10} = 0b10;
    let Inst{5-2} = 0b1100;
}

class TMS320C64xInstD3<bits<3> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> dst;
    bits<15> offset;
    bit unit;
    bits<3> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-8} = offset;
    let Inst{7} = unit;
    let Inst{6-4} = op;
    let Inst{3-2} = 0b11;
}

class TMS320C64xInstD4<bits<3> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> srcdst;
    bits<5> base;
    bits<3> op = opVal;

    let Inst{27-23} = srcdst;
    let Inst{22-18} = base;
    let Inst{9-7} = op;
    let Inst{17-10} = 0b00000001;
    let Inst{6-2} = 0b10000;
}

class TMS320C64xInstD5<bit rVal, bits<3> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> srcdst;
    bits<15> baseoffsetmodeunit;
    bit r = rVal;
    bits<3> op = opVal;

    let Inst{27-23} = srcdst;
    let Inst{22-9} = baseoffsetmodeunit{14-1};
    let Inst{8} = r;
    let Inst{7} = baseoffsetmodeunit{0};
    let Inst{6-4} = op;
    let Inst{3-2} = 0b01;
}

class TMS320C64xInstD6<bits<3> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> srcdst;
    bits<16> offsetunit;
    bits<3> op = opVal;

    let Inst{27-23} = srcdst;
    let Inst{22-7} = offsetunit;
    let Inst{6-4} = op;
    let Inst{3-2} = 0b11;
}

multiclass TMS320C64xInstD56_memld<bits<3> opVal, string asmstr> {
    def _d5_mr : TMS320C64xInstD5<0, opVal,
        ( outs GPRegs:$srcdst ),
        ( ins memop:$baseoffsetmodeunit ),
        !strconcat(asmstr, "\t$baseoffsetmodeunit, $srcdst"), []>;
    def _d6_mr : TMS320C64xInstD6<opVal,
        ( outs GPRegs:$srcdst ),
        ( ins memop2:$offsetunit ),
        !strconcat(asmstr, "\t$offsetunit, $srcdst"), []>;
}

multiclass TMS320C64xInstD56_memst<bits<3> opVal, string asmstr> {
    def _d5_rm : TMS320C64xInstD5<0, opVal,
        ( outs GPRegs:$srcdst ),
        ( ins memop:$baseoffsetmodeunit ),
        !strconcat(asmstr, "\t$srcdst, $baseoffsetmodeunit"), []>;
    def _d6_rm : TMS320C64xInstD6<opVal,
        ( outs GPRegs:$srcdst ),
        ( ins memop2:$offsetunit ),
        !strconcat(asmstr, "\t$srcdst, $offsetunit"), []>;
}

class TMS320C64xInstD7<bits<3> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> srcdst;
    bits<15> baseoffsetmodeunit;
    bits<3> op = opVal;

    let Inst{27-23} = srcdst;
    let Inst{22-9} = baseoffsetmodeunit{14-1};
    let Inst{7} = baseoffsetmodeunit{0};
    let Inst{6-4} = op;
    let Inst{8} = 0b1;
    let Inst{3-2} = 0b01;
}

class TMS320C64xInstD8<bits<3> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<4> srcdst;
    bits<16> baseoffsetmodeunit;
    bits<3> op = opVal;

    let Inst{27-24} = srcdst;
    let Inst{23-9} = baseoffsetmodeunit{15-1};
    let Inst{7} = baseoffsetmodeunit{0};
    let Inst{6-4} = op;
    let Inst{8} = 0b1;
    let Inst{3-2} = 0b01;
}

// Functional unit .L

// L1 with crosspath at src1
class TMS320C64xInstL1x1<bits<7> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx3:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<7> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{11-5} = op;
    let Inst{4-2} = 0b110;
}

// L1 with crosspath at src2
class TMS320C64xInstL1x2<bits<7> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<7> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{11-5} = op;
    let Inst{4-2} = 0b110;
}

multiclass TMS320C64xInstL1_rrr_x1<bits<7> opVal, string asmstr> {
    def _l1_rrr_x1 : TMS320C64xInstL1x1<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_rrr_x2<bits<7> opVal, string asmstr> {
    def _l1_rrr_x2 : TMS320C64xInstL1x2<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_irr<bits<7> opVal, string asmstr> {
    def _l1_irr : TMS320C64xInstL1x2<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, scst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_rrp_x1<bits<7> opVal, string asmstr> {
    def _l1_rrp_x1 : TMS320C64xInstL1x1<opVal,
        ( outs regpair5:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_rrp_x2<bits<7> opVal, string asmstr> {
    def _l1_rrp_x2 : TMS320C64xInstL1x2<opVal,
        ( outs regpair5:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_rpp<bits<7> opVal, string asmstr> {
    def _l1_rpp : TMS320C64xInstL1x1<opVal,
        ( outs regpair5:$dst ),
        ( ins regpair5:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_rpr<bits<7> opVal, string asmstr> {
    def _l1_rpr : TMS320C64xInstL1x1<opVal,
        ( outs GPRegs:$dst ),
        ( ins regpair5:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_ipr<bits<7> opVal, string asmstr> {
    def _l1_ipr : TMS320C64xInstL1x1<opVal,
        ( outs GPRegs:$dst ),
        ( ins regpair5:$src2, scst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_ipp<bits<7> opVal, string asmstr> {
    def _l1_ipp : TMS320C64xInstL1x1<opVal,
        ( outs regpair5:$dst ),
        ( ins regpair5:$src2, scst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_cmp<bits<7> opVal1, bits<7> opVal2, bits<7> opVal3, bits<7> opVal4, string asmstr> {
    def _l1_rrr_x2 : TMS320C64xInstL1x2<opVal1,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;

    def _l1_irr : TMS320C64xInstL1x2<opVal2,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, scst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;

    def _l1_rpr : TMS320C64xInstL1x1<opVal3,
        ( outs GPRegs:$dst ),
        ( ins regpair5:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;

    def _l1_ipr : TMS320C64xInstL1x1<opVal4,
        ( outs GPRegs:$dst ),
        ( ins regpair5:$src2, scst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstL1_cmpu<bits<7> opVal1, bits<7> opVal2, bits<7> opVal3, bits<7> opVal4, string asmstr> {
    def _l1_rrr_x2 : TMS320C64xInstL1x2<opVal1,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;

    def _l1_irr : TMS320C64xInstL1x2<opVal2,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, ucst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;

    def _l1_rpr : TMS320C64xInstL1x1<opVal3,
        ( outs GPRegs:$dst ),
        ( ins regpair5:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;

    def _l1_ipr : TMS320C64xInstL1x1<opVal4,
        ( outs GPRegs:$dst ),
        ( ins regpair5:$src2, ucst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

class TMS320C64xInstL2<bits<5> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> op = opVal;
    bit crosspath;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = op;
    let Inst{12} = crosspath;
    let Inst{11-2} = 0b0011010110;
}

class TMS320C64xInstL3<bits<7> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<7> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{11-5} = op;
    let Inst{4-2} = 0b110;
}

// Functional unit .M

class TMS320C64xInstM1<bits<5> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<5> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{10-6} = op;
    let Inst{11} = 0;
    let Inst{5-2} = 0b1100;
}

multiclass TMS320C64xInstM1_rrr<bits<5> opVal, string asmstr> {
    def _m1_rrr : TMS320C64xInstM1<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstM1_rrp<bits<5> opVal, string asmstr> {
    def _m1_rrp : TMS320C64xInstM1<opVal,
        ( outs regpair5:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

class TMS320C64xInstM2<bits<5> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> op = opVal;
    bit crosspath;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = op;
    let Inst{12} = crosspath;
    let Inst{11-2} = 0b0000111100;
}

multiclass TMS320C64xInstM2_rr<bits<5> opVal, string asmstr> {
    def _m2_rr : TMS320C64xInstM2<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2 ),
        !strconcat(asmstr, "\t$src2, $dst"),
        []>;
}

class TMS320C64xInstM3<bits<5> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<5> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{10-6} = op;
    let Inst{11} = 0;
    let Inst{5-2} = 0b1100;
}

class TMS320C64xInstM4<bits<5> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<5> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{11-7} = op;
    let Inst{6-2} = 0;
}

multiclass TMS320C64xInstM4_rrr<bits<5> opVal, string asmstr> {
    def _m4_rrr : TMS320C64xInstM4<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstM4_irr<bits<5> opVal, string asmstr> {
    def _m4_irr : TMS320C64xInstM4<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, scst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

// Functional unit .S

class TMS320C64xInstS1X1<bits<6> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx3:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<6> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{11-6} = op;
    let Inst{5-2} = 0b1000;
}

class TMS320C64xInstS1X2<bits<6> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<6> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{11-6} = op;
    let Inst{5-2} = 0b1000;
}

multiclass TMS320C64xInstS1_rrr<bits<6> opVal, string asmstr> {
    def _s1_rrr : TMS320C64xInstS1X2<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

multiclass TMS320C64xInstS1_irr<bits<6> opVal, string asmstr> {
    def _s1_irr : TMS320C64xInstS1X2<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, scst5:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

class TMS320C64xInstS2<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> dst;
    bits<16> const;

    let Inst{27-23} = dst;
    let Inst{22-7} = const;
    let Inst{6-2} = 0b10100;
}

class TMS320C64xInstS3<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> dst;
    bits<7> src1;
    bits<3> src2;

    let Inst{27-23} = dst;
    let Inst{22-16} = src1;
    let Inst{15-13} = src2;
    let Inst{12-2} = 0b00001011000;
}

class TMS320C64xInstS4<bits<4> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<4> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{9-6} = op;
    let Inst{11-10} = 0b11;
    let Inst{5-2} = 0b1100;
}

multiclass TMS320C64xInstS4_rrr<bits<4> opVal, string asmstr> {
    def _s4_rrr : TMS320C64xInstS4<opVal,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src1, $src2, $dst"),
        []>;
}

class TMS320C64xInstS5<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<21> const;

    let Inst{27-7} = const;
    let Inst{6-2} = 0b00100;
}

class TMS320C64xInstS6<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx1:$crosspath)), asmstr, pattern> {
    bits<5> src2;
    bit crosspath;

    let Inst{22-18} = src2;
    let Inst{12} = crosspath;
    let Inst{27-23} = 0;
    let Inst{17-13} = 0;
    let Inst{11-2} = 0b0011011000;
}

class TMS320C64xInstS7<bits<3> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<3> op = opVal;

    let Inst{20-18} = op;
    let Inst{27-21} = 0;
    let Inst{17-2} = 0b0000000000111000;
}

class TMS320C64xInstS8<bit nVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> dst;
    bits<10> src;
    bit n = nVal;

    let Inst{27-23} = dst;
    let Inst{22-13} = src;
    let Inst{12} = n;
    let Inst{11-2} = 0b0000001000;
}

class TMS320C64xInstS9<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<12> src2;
    bits<3> src1;

    let Inst{27-16} = src2;
    let Inst{15-13} = src1;
    let Inst{12-2} = 0b00001001000;
}

class TMS320C64xInstS10<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx1:$crosspath)), asmstr, pattern> {
    bits<5> src2;
    bits<3> src1;
    bit crosspath;

    let Inst{22-18} = src2;
    let Inst{15-13} = src1;
    let Inst{12} = crosspath;
    let Inst{27-23} = 0b00001;
    let Inst{17-16} = 0;
    let Inst{11-2} = 0b0011011000;
}

class TMS320C64xInstS11<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<21> const;

    let Inst{27-7} = const;
    let Inst{6-2} = 0b00100;
}

class TMS320C64xInstS12<bit hVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> dst;
    bits<16> const;
    bit h = hVal;

    let Inst{27-23} = dst;
    let Inst{22-7} = const;
    let Inst{6} = h;
    let Inst{5-2} = 0b1010;
}

class TMS320C64xInstS13<bits<4> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> src1;
    bit crosspath;
    bits<4> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = src1;
    let Inst{12} = crosspath;
    let Inst{9-6} = op;
    let Inst{11-10} = 0b11;
    let Inst{5-2} = 0b1100;
}

class TMS320C64xInstS14<bits<5> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, !con(inops, (ins crosspathopx2:$crosspath)), asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> op = opVal;
    bit crosspath;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = op;
    let Inst{12} = crosspath;
    let Inst{11-2} = 0b1111001000;
}

class TMS320C64xInstS15<bits<2> opVal, dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<5> dst;
    bits<5> src2;
    bits<5> consta;
    bits<5> constb;
    bits<2> op = opVal;

    let Inst{27-23} = dst;
    let Inst{22-18} = src2;
    let Inst{17-13} = consta;
    let Inst{12-8} = constb;
    let Inst{7-6} = op;
    let Inst{5-2} = 0b0010;
}

multiclass TMS320C64xInstS115_bf<bits<2> opVal1, bits<6> opVal2, string asmstr> {
    def _s15_riir : TMS320C64xInstS15<opVal1,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, ucst5:$consta, ucst5:$constb ),
        !strconcat(asmstr, "\t$src2, $consta, $constb, $dst"), []>;

    def _s1_rrr : TMS320C64xInstS1X2<opVal2,
        ( outs GPRegs:$dst ),
        ( ins GPRegs:$src2, GPRegs:$src1 ),
        !strconcat(asmstr, "\t$src2, $src1, $dst"), []>;
}

// No functional unit

class TMS320C64xInstNop<dag outops, dag inops, string asmstr, list<dag> pattern> : TMS320C64xInst<outops, inops, asmstr, pattern> {
    bits<4> op;

    let Inst{16-13} = op;
    let Inst{27-17} = 0;
    let Inst{12-2} = 0;
}
