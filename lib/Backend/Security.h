//-------------------------------------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt file in the project root for full license information.
//-------------------------------------------------------------------------------------------------------
#pragma once

class Security
{
private:
    Func *func;

public:
    Security(Func * func) : func(func) {}

    void            EncodeLargeConstants();
    void            InsertNOPs();
    static bool     DontEncode(IR::Opnd *opnd);
    static void     InsertRandomFunctionPad(IR::Instr * instrBeforeInstr);

	// Large constants have more than 16 significant bits.
	// Constants except these are considered large: 0x0000????, 0xffff????, 0x????0000, 0x????ffff
	static bool     IsLargeConstant(int32 value) { 
		int cbMethod = Js::Configuration::Global.cbMethod;
		if (cbMethod == 0) {
			return true;
		}
		else if (cbMethod == 4) {
			if ((value & 0xFFFFFFF0) != 0xFFFFFFF0 &&
				(value & 0x0FFFFFFF) != 0xFFFFFFF &&
				(value & 0xFFFFFFF0) != 0x0 &&
				(value & 0x0FFFFFFF) != 0x0) {
				//printf("CB4 Blinding val %d\n", value);
				return true;
			}
		}
		else if (cbMethod == 8) {
			if ((value & 0xFFFFFF00) != 0xFFFFFF00 &&
				(value & 0x00FFFFFF) != 0xFFFFFF &&
				(value & 0xFFFFFF00) != 0x0 &&
				(value & 0x00FFFFFF) != 0x0){
				//printf("CB8 Blinding val %d\n", value);
				return true;
			}
		}
		else if (cbMethod == 16) {
			if (static_cast<int16>(value) != 0 && static_cast<int16>(value) != -1 && (value >> 16) != 0 && (value >> 16) != -1){
				//printf("CB16 Blinding val %d\n", value);
				return true;
			}
		}
		return false;
	}

	/*
	static bool     IsLargeConstant(int32 value) {
	return		((value & 0xFFFFFFFC) != 0
	&& (value & 0xFFFFFFFC) != 0xFFFFFFFC
	&& (value & 0x3FFFFFFF) != 0
	&& (value & 0x3FFFFFFF) != 0x3FFFFFFF);
	}
	*/

	static IR::Instr *GenerateNOPx64(int nopSize, Func *f) {
		IR::Instr *nop = IR::Instr::New(Js::OpCode::NOP, f);

		// Let the encoder know what the size of the NOP needs to be.
		if (nopSize > 1)
		{
			// 2, 3 or 4 byte NOP.
			IR::IntConstOpnd *nopSizeOpnd = IR::IntConstOpnd::New(nopSize, TyInt8, f);
			nop->SetSrc1(nopSizeOpnd);
		}

		return nop;
	}

private:
    void            EncodeOpnd(IR::Instr *instr, IR::Opnd *opnd);
    IntConstType    EncodeValue(IR::Instr *instr, IR::Opnd *opnd, IntConstType constValue, IR::RegOpnd ** pNewOpnd);
#ifdef _M_X64
    size_t          EncodeAddress(IR::Instr *instr, IR::Opnd *opnd, size_t value, IR::RegOpnd **pNewOpnd);
#endif

    void            InsertNOPBefore(IR::Instr *instr);
    int             GetNextNOPInsertPoint();

    // Insert 1-4 bytes of NOPs
    static void     InsertSmallNOP(IR::Instr * instrBeforeInstr, DWORD nopSize);
};
