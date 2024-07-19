package com.lgd.test;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import com.lgd.test.beans.AddressPatch;
import com.lgd.test.beans.FlaIndex;
import com.lgd.test.beans.JmpPatch;
import com.lgd.test.beans.Regs;
import com.lgd.test.utils.FixedSizeQueue;

import java.util.*;

import static com.lgd.test.beans.Regs.getWReg;
import static unicorn.Arm64Const.*;

public class Trace_stringFromJNI extends Trace {

    FlaIndex mMainDispatchFlaIndex;
    final List<Long> mMainDispatcherIdxs = new ArrayList<>(); // 记录主选择器索引顺序
    final List<FlaIndex> mRealPatchIndices = new ArrayList<>();

    public Trace_stringFromJNI(FixedSizeQueue<Instruction> queueIns,
                               FixedSizeQueue<Long> queueAddr,
                               FixedSizeQueue<Regs> queueRegs,
                               long funcEntry, long funcLength, long mainDispatcherJmpAddr) {
        super(queueIns, queueAddr, queueRegs, funcEntry, funcLength, mainDispatcherJmpAddr);
    }

    @Override
    void onTrace(Backend backend, long address, long moduleOffAddr, int size) {
        // 避免进入子函数
        if (moduleOffAddr < mFuncEntry || moduleOffAddr > mFuncEntry + mFuncLength) return;

        int qSize = mTraceIns.size();
        Instruction ins1 = mTraceIns.get(qSize - 3);
        Instruction ins2 = mTraceIns.get(qSize - 2);
        Instruction curIns = mTraceIns.get(qSize - 1);
        // 打印当前指令
//        if (curIns != null) System.out.printf("%x %s %s\n", moduleBaseAddr, curIns.getMnemonic(), curIns.getOpStr());

        long idx = getWReg(backend.reg_read(UC_ARM64_REG_X9).longValue());
        if (moduleOffAddr == mMainDispatcherJmpAddr) {
            System.out.printf("mainDispatcher: idx=%x\n", idx);

            mMainDispatcherIdxs.add(idx);
            if (mMainDispatchFlaIndex == null) {
                mMainDispatchFlaIndex = new FlaIndex();
                mMainDispatchFlaIndex.addr = 0;
                mMainDispatchFlaIndex.idx = 0;
                mMainDispatchFlaIndex.nextIdx = idx;
                mMainDispatchFlaIndex.jmpAddr = moduleOffAddr;
                System.out.println("mainBlock: " + mMainDispatchFlaIndex);
            }
        }

        if (isMatchRbPrevPatter(ins1, ins2, curIns)) {
            long zReg = backend.reg_read(UC_ARM64_REG_NZCV).longValue() >> 30 & 1;
            if (zReg == 1) {
                String beqOpStr = curIns.getOpStr();
                long jmpOffAddr = Long.parseLong(beqOpStr.replace("#", "").replace("0x", ""), 16);
                FlaIndex blk = new FlaIndex();
                blk.addr = jmpOffAddr + moduleOffAddr;
                blk.idx = idx;
                if (!mRealPatchIndices.contains(blk)) {
                    mRealPatchIndices.add(blk);
                }
                System.out.printf("condDispatcher-true: %s\n", blk);
            }
        }

        if (isMatchRealBlockTailPattern(ins2, curIns)) {
            FlaIndex rb = new FlaIndex();
            System.out.printf("RB: %x %s %s\n", moduleOffAddr, curIns.getMnemonic(), curIns.getOpStr());
            rb.nextIdx = getWReg(mTraceRegs.get(mTraceRegs.size() - 1).getRegV(UC_ARM64_REG_X9));
            rb.jmpAddr = moduleOffAddr;

            for (int i = mTraceIns.size() - 2; i > 0; i--) {
                Instruction ins = mTraceIns.get(i);
                if (ins.getMnemonic().equals("b") || ins.getMnemonic().equals("b.eq")) {
                    rb.addr = mTraceAddr.get(i + 1);
                    rb.idx = getWReg(mTraceRegs.get(i).getRegV(UC_ARM64_REG_X9));
                    System.out.println(rb);
                    mRealPatchIndices.add(rb);
                    break;
                }
            }
        }
    }

    void distinctRB() {
        for (FlaIndex b : mRealPatchIndices) {
            for (FlaIndex bb : mRealPatchIndices) {
                if (b.idx != bb.idx) continue;
                if (b.jmpAddr == 0 && bb.jmpAddr != 0) {
                    b.jmpAddr = bb.jmpAddr;
                }
                if (b.nextIdx == 0 && bb.nextIdx != 0) {
                    b.nextIdx = bb.nextIdx;
                }
            }
        }
        Set<FlaIndex> distinct = new HashSet<>(mRealPatchIndices);
        mRealPatchIndices.clear();
        mRealPatchIndices.addAll(distinct);
    }

    @Override
    List<AddressPatch> extractJmpPatches() {
        distinctRB();

        final List<AddressPatch> jmpPatches = new ArrayList<>();
        List<FlaIndex> rbs = new ArrayList<>(mRealPatchIndices);

        FlaIndex curBlk = mMainDispatchFlaIndex;
        while (!rbs.isEmpty()) {
            JmpPatch jp = new JmpPatch(0, 0);
            jp.addr = curBlk.jmpAddr;
            boolean found = false;
            for (FlaIndex b : rbs) {
                if (curBlk.nextIdx == b.idx) {
                    found = true;
                    jp.jmpAddr = b.addr - jp.jmpAddr;
                    jmpPatches.add(jp);
                    curBlk = b;
                    rbs.remove(b);
                    break;
                }
            }

            if (!found) {
                System.out.printf("中断，无法提取所有 JmpPatch。miss: %s\n", curBlk);
                return null;
            }
        }
        return jmpPatches;
    }

    // STR  W[n], [SP,#0x60+idx]
    boolean isMatchRealBlockTailPattern(Instruction ins1, Instruction ins2) {
        if (ins1 == null || ins2 == null) return false;
        if (!ins2.getMnemonic().equals("b")) return false;
        if (!ins1.getMnemonic().equals("str")) return false;
        return ins1.getOpStr().contains(", [sp, #0x24]");
    }

    /**
     * 匹配真实块前驱，模式如下
     * SUBS            W[x], W[y], W[z]
     * STR             W[x], [stack]
     * B.EQ            loc_XXXX
     * B               loc_YYYY ; 此处可能无法走到，所以只匹配前三条即可
     */
    boolean isMatchRbPrevPatter(Instruction ins1, Instruction ins2, Instruction ins3) {
        if (ins1 == null || ins2 == null || ins3 == null) return false;
        if (!"b.eq".equals(ins3.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        if (!"str".equals(ins2.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        return "subs".equals(ins1.getMnemonic().toLowerCase(Locale.ROOT));
    }
}
