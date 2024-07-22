package com.lgd.test;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import com.lgd.test.beans.*;
import com.lgd.test.utils.FixedSizeQueue;

import java.util.*;

import static com.lgd.test.beans.Regs.getWReg;
import static unicorn.Arm64Const.*;

public class Trace_fibonacci extends Trace {

    FlaIndex mMainDispatchFlaIndex;
    final List<Long> mMainDispatcherIdxs = new ArrayList<>(); // 记录主选择器索引顺序
    final List<FlaIndex> mRealPatchIndices = new ArrayList<>();

    final long mIndirectAddr = 0x1470;
    final String sturIdxAddr = "#-0x40"; // 手工介入：用于匹配 idx sp 堆栈位置

    final List<InsBlock> mInsBlocks = new ArrayList<>(); // 手工介入：用于修复正常业务逻辑中有for循环类的平坦化

    public Trace_fibonacci(FixedSizeQueue<Instruction> queueIns, FixedSizeQueue<Long> queueAddr, FixedSizeQueue<Regs> queueRegs, long funcEntry, long funcLength, long mainDispatcherJmpAddr, Object... args) {
        super(queueIns, queueAddr, queueRegs, funcEntry, funcLength, mainDispatcherJmpAddr, args);
        mInsBlocks.add(new InsBlock(0xfd4, 0xFF8));
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
//        if (curIns != null) System.out.printf("%x %s %s\n", modelOffAddr, curIns.getMnemonic(), curIns.getOpStr());

        // 手工介入：此处有环，即此真实块有两个后继，需要根据条件修改跳转
        for (InsBlock ib : mInsBlocks) {
            ib.addIns(moduleOffAddr, curIns);
        }


        long idx = getWReg(backend.reg_read(UC_ARM64_REG_X9).longValue());
        if (moduleOffAddr == mMainDispatcherJmpAddr) {
            if (!mMainDispatcherIdxs.contains(idx)) {
                mMainDispatcherIdxs.add(idx);
            }
            if (mMainDispatchFlaIndex == null) {
                mMainDispatchFlaIndex = new FlaIndex();
                mMainDispatchFlaIndex.addr = 0;
                mMainDispatchFlaIndex.idx = 0;
                mMainDispatchFlaIndex.nextIdx = idx;
                mMainDispatchFlaIndex.jmpAddr = moduleOffAddr;
                mRealPatchIndices.add(mMainDispatchFlaIndex);
            }
        }

        if (isMatchRbPrevPatter(ins1, ins2, curIns)) {
            idx = getWReg(backend.reg_read(UC_ARM64_REG_X9).longValue());
            long zReg = backend.reg_read(UC_ARM64_REG_NZCV).longValue() >> 30 & 1;
            if (zReg == 1) {
                String beqOpStr = curIns.getOpStr();
                long jmpOffAddr = Long.parseLong(beqOpStr.replace("#", "").replace("0x", ""), 16);
                FlaIndex blk = new FlaIndex();
                blk.addr = jmpOffAddr + moduleOffAddr;
                blk.idx = idx;
                mRealPatchIndices.add(blk);
            }
        }

        if (moduleOffAddr == mIndirectAddr) {
            FlaIndex rb = new FlaIndex();

            Instruction insStur = mTraceIns.get(qSize - 3);
            if (!isMatchIdx(insStur)) {
                insStur = mTraceIns.get(qSize - 4);
            }
            if (!isMatchIdx(insStur)) {
                System.out.printf("中断：无法找到真实块：%x\n", mTraceAddr.get(qSize - 2));
                return;
            }
            String sturReg = insStur.getOpStr().split(",")[0].trim();
            rb.nextIdx = getWReg(mTraceRegs.get(qSize - 1).getRegV(UC_ARM64_REG_X0 + Integer.parseInt(sturReg.replace("w", ""))));
            rb.jmpAddr = mTraceAddr.get(qSize - 2);
            mRealPatchIndices.add(rb);

            for (int i = mTraceIns.size() - 3; i > 0; i--) {
                Instruction ins = mTraceIns.get(i);
                if (ins.getMnemonic().equals("b") || ins.getMnemonic().equals("b.eq")) {
                    rb.addr = mTraceAddr.get(i + 1);
                    rb.idx = getWReg(mTraceRegs.get(i).getRegV(UC_ARM64_REG_X9));
                    break;
                }
            }
        }
    }

    void distinctRB() {
        mRealPatchIndices.sort((o1, o2) -> (int) (o1.addr - o2.addr));
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
        for (FlaIndex b : distinct) {
            System.out.println("distinct RB: " + b);
        }
        mRealPatchIndices.clear();
        mRealPatchIndices.addAll(distinct);
    }

    @Override
    List<AddressPatch> extractJmpPatches() {
        distinctRB();

        final List<AddressPatch> patches = new ArrayList<>();
        List<FlaIndex> successors = new ArrayList<>();
        for (FlaIndex curBlk : mRealPatchIndices) {
            successors.clear();
            JmpPatch patch = new JmpPatch(curBlk.jmpAddr, 0);
            for (FlaIndex bi : mRealPatchIndices) {
                if (curBlk.nextIdx == bi.idx) {
                    successors.add(bi);
                }
            }
            if (successors.size() != 1) {
                System.out.printf("中断，后继不唯一，需要手工介入进行修复：%x\n%s\n", curBlk.nextIdx, successors);
            } else {

                patch.jmpAddr = successors.get(0).addr;
                if (patch.addr == 0 || patch.jmpAddr == 0) {
                    System.out.println("警告，无效布丁: " + patch + ", block: " + curBlk);
                } else {
                    patches.add(patch);
                }
            }
        }
        System.out.println("待手工修复指令：");
        for (InsBlock ib : mInsBlocks) {
            System.out.println(ib);
        }
        // 输出内容如下
        // ins scope: [fd4-ff8]
        // fd4 movz w8, #0xcbb1
        // fd8 movk w8, #0xc0a7, lsl #16
        // fdc movz w9, #0x9855
        // fe0 movk w9, #0x108a, lsl #16
        // fe4 ldur w10, [x29, #-0x3c]
        // fe8 ldur w11, [x29, #-0x1c]
        // fec cmp w10, w11
        // ff0 csel w8, w8, w9, lt
        // ff4 stur w8, [x29, #-0x40]
        // ff8 b #0x478
        // 此真实块存在两处后继，所以，需要增加 b.eq 指令，用于跳转到不同后继
        // 增加 b.eq 指令有如下 2 种做法
        // 1. 删除当前真实块的 1 条指令，比如 ldur w11, [x29, #-0x1c]，此指令目的是获取入参值，这个是已知值，可以不从栈中获取，
        //    删除后将其后指令向前移，然后在 b #0x478 指令前添加 b.eq 指令
        // 2. 查找修复后无法执行到的代码块，比如条件选择选择器块增加两条指令 b.eq & b 指令，然后将 ff8 处的 b 指令跳到 b.eq 位置处

        // fe8 cmp w10, #0xarg[0]
        patches.add(new FixPatch(0xfe8, String.format("cmp w10, #0x%x", (long) mArgs[0])));
        // fec csel w8, w8, w9, lt
        patches.add(new FixPatch(0xfec, "csel w8, w8, w9, lt"));
        // ff0 stur w8, [x29, #-0x40]
        patches.add(new FixPatch(0xff0, "stur w8, [x29, #-0x40]"));
        // ff4 b.eq #0x2b0
        patches.add(new FixPatch(0xff4, "b.eq #0x2b0"));
        // ff8 b #0x4
        patches.add(new FixPatch(0xff8, "b #0x4"));
        patches.add(new JmpPatch(0xfd0, 0xfd4));
        patches.add(new JmpPatch(0x12a0, 0xfd4));
        for (AddressPatch ap : patches) {
            System.out.println(ap);
        }

        return patches;
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
        if (!"b.eq".equals(ins3.getMnemonic())) return false;
        if (!"str".equals(ins2.getMnemonic()) && !"stur".equals(ins2.getMnemonic())) return false;
        return "subs".equals(ins1.getMnemonic());
    }

    boolean isMatchIdx(Instruction ins) {
        if (!"stur".equals(ins.getMnemonic())) return false;
        return ins.getOpStr().contains(sturIdxAddr);
    }
}
