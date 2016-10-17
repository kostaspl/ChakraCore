//-------------------------------------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt file in the project root for full license information.
//-------------------------------------------------------------------------------------------------------
#include "Backend.h"

void
Security::EncodeLargeConstants()
{
#pragma prefast(suppress:6236 6285, "logical-or of constants is by design")
    if (PHASE_OFF(Js::EncodeConstantsPhase, this->func) || CONFIG_ISENABLED(Js::DebugFlag) || !MD_ENCODE_LG_CONSTS)
    {
        return;
    }

    FOREACH_REAL_INSTR_IN_FUNC_EDITING(instr, instrNext, this->func)
    {
        if (!instr->IsRealInstr())
        {
            continue;
        }
        IR::Opnd *dst = instr->GetDst();
        if (dst)
        {
            this->EncodeOpnd(instr, dst);
        }
        IR::Opnd *src1 = instr->GetSrc1();
        if (src1)
        {
            this->EncodeOpnd(instr, src1);

            IR::Opnd *src2 = instr->GetSrc2();
            if (src2)
            {
                this->EncodeOpnd(instr, src2);
            }
        }
    } NEXT_REAL_INSTR_IN_FUNC_EDITING;
}

int
Security::GetNextNOPInsertPoint()
{
    uint frequency = (1 << CONFIG_FLAG(NopFrequency)) - 1;
    return (Math::Rand() & frequency) + 1;
}

void
Security::InsertRandomFunctionPad(IR::Instr * instrBeforeInstr)
{
    if (PHASE_OFF(Js::InsertNOPsPhase, instrBeforeInstr->m_func->GetTopFunc())
        || CONFIG_ISENABLED(Js::DebugFlag) || CONFIG_ISENABLED(Js::BenchmarkFlag))
    {
        return;
    }
    DWORD randomPad = Math::Rand() & ((0 - INSTR_ALIGNMENT) & 0xF);
#ifndef _M_ARM
    if (randomPad == 1)
    {
        InsertSmallNOP(instrBeforeInstr, 1);
        return;
    }
    if (randomPad & 1)
    {
        InsertSmallNOP(instrBeforeInstr, 3);
        randomPad -= 3;
    }
#endif
    Assert((randomPad & 1) == 0);
    while (randomPad >= 4)
    {
        InsertSmallNOP(instrBeforeInstr, 4);
        randomPad -= 4;
    }
    Assert(randomPad == 2 || randomPad == 0);
    if (randomPad == 2)
    {
        InsertSmallNOP(instrBeforeInstr, 2);
    }
}


void
Security::InsertNOPs()
{
    if (PHASE_OFF(Js::InsertNOPsPhase, this->func) || CONFIG_ISENABLED(Js::DebugFlag) || CONFIG_ISENABLED(Js::BenchmarkFlag))
    {
        return;
    }

    int count = 0;
    IR::Instr *instr = this->func->m_headInstr;

    while(true)
    {
        count = this->GetNextNOPInsertPoint();
        while(instr && count--)
        {
            instr = instr->GetNextRealInstr();
        }
        if (instr == nullptr || instr->IsInjected())
        {
            break;
        }
        this->InsertNOPBefore(instr);
    };
}

void
Security::InsertNOPBefore(IR::Instr *instr)
{
    InsertSmallNOP(instr, (Math::Rand() & 0x3) + 1);
}

void
Security::InsertSmallNOP(IR::Instr * instr, DWORD nopSize)
{
#if defined(_M_IX86) || defined(_M_X64)
#ifdef _M_IX86
    if (AutoSystemInfo::Data.SSE2Available())
    {   // on x86 system that has SSE2, encode fast NOPs as x64 does
#endif
        Assert(nopSize >= 1 || nopSize <= 4);
        IR::Instr *nop = IR::Instr::New(Js::OpCode::NOP, instr->m_func);

        // Let the encoder know what the size of the NOP needs to be.
        if (nopSize > 1)
        {
            // 2, 3 or 4 byte NOP.
            IR::IntConstOpnd *nopSizeOpnd = IR::IntConstOpnd::New(nopSize, TyInt8, instr->m_func);
            nop->SetSrc1(nopSizeOpnd);
        }

        instr->InsertBefore(nop);
#ifdef _M_IX86
    }
    else
    {
        IR::Instr *nopInstr = nullptr;
        IR::RegOpnd *regOpnd;
        IR::IndirOpnd *indirOpnd;
        switch (nopSize)
        {
        case 1:
            // nop
            nopInstr = IR::Instr::New(Js::OpCode::NOP, instr->m_func);
            break;
        case 2:
            // mov edi, edi         ; 2 bytes
            regOpnd = IR::RegOpnd::New(nullptr, RegEDI, TyInt32, instr->m_func);
            nopInstr = IR::Instr::New(Js::OpCode::MOV, regOpnd, regOpnd, instr->m_func);
            break;
        case 3:
            // lea ecx, [ecx+00]    ; 3 bytes
            regOpnd = IR::RegOpnd::New(nullptr, RegECX, TyInt32, instr->m_func);
            indirOpnd = IR::IndirOpnd::New(regOpnd, (int32)0, TyInt32, instr->m_func);
            nopInstr = IR::Instr::New(Js::OpCode::LEA, regOpnd, indirOpnd, instr->m_func);
            break;
        case 4:
            // lea esp, [esp+00]    ; 4 bytes
            regOpnd = IR::RegOpnd::New(nullptr, RegESP, TyInt32, instr->m_func);
            indirOpnd = IR::IndirOpnd::New(regOpnd, (int32)0, TyInt32, instr->m_func);
            nopInstr = IR::Instr::New(Js::OpCode::LEA, regOpnd, indirOpnd, instr->m_func);
            break;
        default:
            Assert(false);
            break;
        }
        instr->InsertBefore(nopInstr);
    }
#endif
#elif defined(_M_ARM)
    // Can't insert 3 bytes, must choose between 2 and 4.

    IR::Instr *nopInstr = nullptr;

    switch(nopSize)
    {
    case 1:
    case 2:
        nopInstr = IR::Instr::New(Js::OpCode::NOP, instr->m_func);
        break;
    case 3:
    case 4:
        nopInstr = IR::Instr::New(Js::OpCode::NOP_W, instr->m_func);
        break;
    default:
        Assert(false);
        break;
    }

    instr->InsertBefore(nopInstr);
#else
    AssertMsg(false, "Unimplemented");
#endif
}

bool
Security::DontEncode(IR::Opnd *opnd)
{
	if (opnd->IsInjected()) {
		return true;
	}

    switch (opnd->GetKind())
    {
    case IR::OpndKindIntConst:
    {
		int32 val = opnd->AsIntConstOpnd()->AsInt32();

		if (val <= 3 && val >= -3)
			return true;

		return false;
    }

    case IR::OpndKindAddr:
    {
        IR::AddrOpnd *addrOpnd = opnd->AsAddrOpnd();
		if (addrOpnd->m_address == nullptr) {
			return true;
		}

		if (!Js::TaggedNumber::Is(addrOpnd->m_address) && 
			addrOpnd->GetAddrOpndKind() == IR::AddrOpndKind::AddrOpndKindDynamicVar && 
			addrOpnd->GetValueType() == ValueType::Uninitialized) {
			//printf("addr = %p\n", addrOpnd->m_address);
			return true;
		}
    }

    case IR::OpndKindHelperCall:
        return false;

	case IR::OpndKindIndir:
	{
		IR::IndirOpnd *indirOpnd = opnd->AsIndirOpnd();

		if (indirOpnd->GetOffset() == 0)
			return true;

		if (indirOpnd->GetIndexOpnd() != nullptr)
			return true;
	}
    }

    return false;
}

void
Security::EncodeOpnd(IR::Instr *instr, IR::Opnd *opnd)
{
    IR::RegOpnd *newOpnd = NULL;
    bool isSrc2 = false;

    if (Security::DontEncode(opnd))
    {
        return;
    }

    switch(opnd->GetKind())
    {
    case IR::OpndKindIntConst:
    {
        IR::IntConstOpnd *intConstOpnd = opnd->AsIntConstOpnd();

		if (instr->m_opcode == Js::OpCode::SHL ||
			instr->m_opcode == Js::OpCode::SHR ||
			instr->m_opcode == Js::OpCode::SAR ||
			instr->m_opcode == Js::OpCode::RET ||
			instr->m_opcode == Js::OpCode::NOP)
			return;

        if (opnd != instr->GetSrc1())
        {
            Assert(opnd == instr->GetSrc2());
            isSrc2 = true;
            instr->UnlinkSrc2();
        }
        else
        {
            instr->UnlinkSrc1();
        }

#if DBG_DUMP || defined(ENABLE_IR_VIEWER)
        intConstOpnd->decodedValue = intConstOpnd->GetValue();
#endif

        intConstOpnd->SetValue(EncodeValue(instr, intConstOpnd, intConstOpnd->GetValue(), &newOpnd));
    }
    break;

    case IR::OpndKindAddr:
    {
        IR::AddrOpnd *addrOpnd = opnd->AsAddrOpnd();

        if (opnd != instr->GetSrc1())
        {
            Assert(opnd == instr->GetSrc2());
            isSrc2 = true;
            instr->UnlinkSrc2();
        }
        else
        {
            instr->UnlinkSrc1();
        }

        addrOpnd->SetEncodedValue((Js::Var)this->EncodeValue(instr, addrOpnd, (IntConstType)addrOpnd->m_address, &newOpnd), addrOpnd->GetAddrOpndKind());
    }
    break;

	case IR::OpndKindHelperCall:
	{
		if (instr->m_opcode == Js::OpCode::MOV) {
			instr->UnlinkSrc1();

			IR::Instr   *instrNew = nullptr;
			//IR::RegOpnd *regOpnd = instr->GetDst()->AsRegOpnd();
			IR::RegOpnd *targetOpnd = IR::RegOpnd::New(StackSym::New(TyMachPtr, instr->m_func), TyMachPtr, instr->m_func);
			size_t cookie = (size_t)Math::Rand();

			instr->ReplaceDst(targetOpnd);

			instr->SetSrc1(IR::AddrOpnd::New((void *)((size_t)IR::GetMethodAddress(opnd->AsHelperCallOpnd()) ^ cookie), IR::AddrOpndKindConstant, instr->m_func));

			IR::AddrOpnd *cookieOpnd = IR::AddrOpnd::New((Js::Var)cookie, IR::AddrOpndKindConstant, instr->m_func);
			instrNew = IR::Instr::New(Js::OpCode::XOR, targetOpnd, targetOpnd, cookieOpnd, instr->m_func);
			instr->InsertAfter(instrNew);
			LowererMD::Legalize(instrNew);

			StackSym * stackSym = targetOpnd->m_sym;
			Assert(!stackSym->m_isSingleDef);
			Assert(stackSym->m_instrDef == nullptr);
			stackSym->m_isEncodedConstant = true;
			stackSym->constantValue = (size_t)IR::GetMethodAddress(opnd->AsHelperCallOpnd());

			instrNew->GetNextRealInstr()->ReplaceSrc1(targetOpnd);
			return;
		}
		else if (instr->m_opcode == Js::OpCode::CALL) {
			instr->UnlinkSrc1();

			IR::Instr   *instrNew = nullptr;
			IR::RegOpnd *regOpnd = IR::RegOpnd::New(TyMachReg, instr->m_func);
			regOpnd->SetReg(RegRAX);
			regOpnd->m_isCallArg = true;

			size_t cookie = (size_t)Math::Rand();

			IR::Instr   *movInstr = IR::Instr::New(Js::OpCode::MOV, regOpnd, IR::AddrOpnd::New((void *)((size_t)IR::GetMethodAddress(opnd->AsHelperCallOpnd()) ^ cookie), IR::AddrOpndKindConstant, instr->m_func), instr->m_func);
			instr->InsertBefore(movInstr);

			
			IR::AddrOpnd *cookieOpnd = IR::AddrOpnd::New((Js::Var)cookie, IR::AddrOpndKindConstant, instr->m_func);
			instrNew = IR::Instr::New(Js::OpCode::XOR, regOpnd, regOpnd, cookieOpnd, instr->m_func);
			instr->InsertBefore(instrNew);
			LowererMD::Legalize(instrNew);

			StackSym * stackSym = regOpnd->m_sym;
			Assert(!stackSym->m_isSingleDef);
			Assert(stackSym->m_instrDef == nullptr);
			stackSym->m_isEncodedConstant = true;
			stackSym->constantValue = (size_t)IR::GetMethodAddress(opnd->AsHelperCallOpnd());

			instr->SetSrc1(regOpnd);
			return;
		}
	}
	break;

    case IR::OpndKindIndir:
	{
		IR::IndirOpnd *indirOpnd = opnd->AsIndirOpnd();

		AssertMsg(indirOpnd->GetIndexOpnd() == nullptr, "Code currently doesn't support indir with offset and indexOpnd");

        IR::IntConstOpnd *indexOpnd = IR::IntConstOpnd::New(indirOpnd->GetOffset(), TyInt64, instr->m_func);
#if DBG_DUMP || defined(ENABLE_IR_VIEWER)
        indexOpnd->decodedValue = indexOpnd->GetValue();
#endif

        indexOpnd->SetValue(EncodeValue(instr, indexOpnd, indexOpnd->GetValue(), &newOpnd));
        indirOpnd->SetOffset(0);
        indirOpnd->SetIndexOpnd(newOpnd);
    }
    return;

    default:
        return;
    }

    IR::Opnd *dst = instr->GetDst();

    if (dst)
    {
#if _M_X64
        // Ensure the left and right operand has the same type (that might not be true for constants on x64)
        newOpnd = (IR::RegOpnd *)newOpnd->UseWithNewType(dst->GetType(), instr->m_func);
#endif
        if (dst->IsRegOpnd())
        {
            IR::RegOpnd *dstRegOpnd = dst->AsRegOpnd();
            StackSym *dstSym = dstRegOpnd->m_sym;

            if (dstSym)
            {
                dstSym->m_isConst = false;
                dstSym->m_isIntConst = false;
                dstSym->m_isTaggableIntConst = false;
                dstSym->m_isFltConst = false;
            }
        }
    }

     LowererMD::ImmedSrcToReg(instr, newOpnd, isSrc2 ? 2 : 1);
}

IntConstType
Security::EncodeValue(IR::Instr *instr, IR::Opnd *opnd, IntConstType constValue, IR::RegOpnd **pNewOpnd)
{
    if (opnd->GetType() == TyInt32 || opnd->GetType() == TyInt16 || opnd->GetType() == TyInt8
#if _M_IX86
        || opnd->GetType() == TyVar
#endif
        )
    {
        int32 cookie = (int32)Math::Rand();
        IR::RegOpnd *regOpnd = IR::RegOpnd::New(StackSym::New(opnd->GetType(), instr->m_func), opnd->GetType(), instr->m_func);
        IR::Instr * instrNew = LowererMD::CreateAssign(regOpnd, opnd, instr);

        IR::IntConstOpnd * cookieOpnd = IR::IntConstOpnd::New(cookie, TyInt32, instr->m_func);

#if DBG_DUMP
        cookieOpnd->name = _u("cookie");
#endif

        instrNew = IR::Instr::New(Js::OpCode::Xor_I4, regOpnd, regOpnd, cookieOpnd, instr->m_func);
        instr->InsertBefore(instrNew);

        LowererMD::EmitInt4Instr(instrNew);

        StackSym * stackSym = regOpnd->m_sym;
        Assert(!stackSym->m_isSingleDef);
        Assert(stackSym->m_instrDef == nullptr);
        stackSym->m_isEncodedConstant = true;
        stackSym->constantValue = (int32)constValue;

        *pNewOpnd = regOpnd;

        int32 value = (int32)constValue;
        value = value ^ cookie;
        return value;
    }
    else if (opnd->GetType() == TyUint32 || opnd->GetType() == TyUint16 || opnd->GetType() == TyUint8)
    {
        uint32 cookie = (uint32)Math::Rand();
        IR::RegOpnd *regOpnd = IR::RegOpnd::New(StackSym::New(opnd->GetType(), instr->m_func), opnd->GetType(), instr->m_func);
        IR::Instr * instrNew = LowererMD::CreateAssign(regOpnd, opnd, instr);

        IR::IntConstOpnd * cookieOpnd = IR::IntConstOpnd::New(cookie, TyUint32, instr->m_func);

#if DBG_DUMP
        cookieOpnd->name = _u("cookie");
#endif

        instrNew = IR::Instr::New(Js::OpCode::Xor_I4, regOpnd, regOpnd, cookieOpnd, instr->m_func);
        instr->InsertBefore(instrNew);

        LowererMD::EmitInt4Instr(instrNew);

        StackSym * stackSym = regOpnd->m_sym;
        Assert(!stackSym->m_isSingleDef);
        Assert(stackSym->m_instrDef == nullptr);
        stackSym->m_isEncodedConstant = true;
        stackSym->constantValue = (uint32)constValue;

        *pNewOpnd = regOpnd;

        uint32 value = (uint32)constValue;
        value = value ^ cookie;
        return (IntConstType)value;
    }
    else
    {
#ifdef _M_X64
        return this->EncodeAddress(instr, opnd, constValue, pNewOpnd);
#else
        Assert(false);
        return 0;
#endif
    }
}

#ifdef _M_X64
size_t
Security::EncodeAddress(IR::Instr *instr, IR::Opnd *opnd, size_t value, IR::RegOpnd **pNewOpnd)
{
    IR::Instr   *instrNew = nullptr;
    IR::RegOpnd *regOpnd  = IR::RegOpnd::New(TyMachReg, instr->m_func);

    instrNew = LowererMD::CreateAssign(regOpnd, opnd, instr);

    size_t cookie = (size_t)Math::Rand();
    IR::AddrOpnd *cookieOpnd = IR::AddrOpnd::New((Js::Var)cookie, IR::AddrOpndKindConstant, instr->m_func);
    instrNew = IR::Instr::New(Js::OpCode::XOR, regOpnd, regOpnd, cookieOpnd, instr->m_func);
    instr->InsertBefore(instrNew);
    LowererMD::Legalize(instrNew);

    StackSym * stackSym = regOpnd->m_sym;
    Assert(!stackSym->m_isSingleDef);
    Assert(stackSym->m_instrDef == nullptr);
    stackSym->m_isEncodedConstant = true;
    stackSym->constantValue = value;

    *pNewOpnd = regOpnd;
    return value ^ cookie;
}
#endif
