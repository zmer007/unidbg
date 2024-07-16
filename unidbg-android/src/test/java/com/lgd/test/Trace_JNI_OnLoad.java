package com.lgd.test;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import com.lgd.test.beans.Block;
import com.lgd.test.beans.JmpPatch;
import com.lgd.test.beans.Regs;
import com.lgd.test.utils.FixedSizeQueue;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static com.lgd.test.beans.Regs.getWReg;
import static unicorn.Arm64Const.*;

public class Trace_JNI_OnLoad extends Trace {

    Block mMainDispatchBlock;
    final List<Long> mMainDispatcherIdxs = new ArrayList<>(); // 记录主选择器索引顺序
    final List<Block> mRealBlocks = new ArrayList<>();

    public Trace_JNI_OnLoad(FixedSizeQueue<Instruction> queueIns,
                            FixedSizeQueue<Long> queueAddr,
                            FixedSizeQueue<Regs> queueRegs,
                            long funcEntry, long funcLength, long mainDispatcherJmpAddr) {
        super(queueIns, queueAddr, queueRegs, funcEntry, funcLength, mainDispatcherJmpAddr);
    }

    @Override
    void onTrace(Backend backend, long address, long moduleBaseAddr, int size) {
        // 避免进入子函数
        if (moduleBaseAddr < mFuncEntry || moduleBaseAddr > mFuncEntry + mFuncLength) return;

        int qSize = mTraceIns.size();
        Instruction ins1 = mTraceIns.get(qSize - 3);
        Instruction ins2 = mTraceIns.get(qSize - 2);
        Instruction curIns = mTraceIns.get(qSize - 1);
        // 打印当前指令
        // if (curIns != null) System.out.printf("%x %s %s\n", moduleBaseAddr, curIns.getMnemonic(), curIns.getOpStr());


        if (moduleBaseAddr == mMainDispatcherJmpAddr) {
            long idx = getWReg(backend.reg_read(UC_ARM64_REG_X9).longValue());
            System.out.printf("mainDispatcher: idx=%x\n", idx);

            mMainDispatcherIdxs.add(idx);
            if (mMainDispatchBlock == null) {
                mMainDispatchBlock = new Block();
                mMainDispatchBlock.addr = -1;
                mMainDispatchBlock.idx = idx;
                mMainDispatchBlock.nextIdx = mMainDispatchBlock.idx;
                mMainDispatchBlock.jmpAddr = moduleBaseAddr;
            }
        }

        if (moduleBaseAddr == 0x1c7c + size * 6L) { // // 手动介入，修复 0x1c7c 真实块
            long idx = getWReg(mTraceRegs.get(mTraceRegs.size() - 6).getRegV(UC_ARM64_REG_X9));
            long nextIdx = getWReg(backend.reg_read(UC_ARM64_REG_X8).longValue());
            String beqOpStr = curIns.getOpStr();
            long jmpOffAddr = Long.parseLong(beqOpStr.replace("#", "").replace("0x", ""), 16);
            System.out.printf("manualFixRb: addr= 0x1c7c, idx= %x, nextIdx= %x, jmpAddr= %x, ins = %s\n", idx, nextIdx, jmpOffAddr + moduleBaseAddr, curIns);
            for (Block blk : mRealBlocks) {
                if (blk.addr == 0x1c7c) {
                    blk.nextIdx = nextIdx;
                    blk.jmpAddr = jmpOffAddr + moduleBaseAddr;
                }
            }
        }

        if (isMatchRbPrevPatter(ins1, ins2, curIns)) {
            long idx = getWReg(backend.reg_read(UC_ARM64_REG_X9).longValue());
            long zReg = backend.reg_read(UC_ARM64_REG_NZCV).longValue() >> 30 & 1;
            if (zReg == 1) {
                String beqOpStr = curIns.getOpStr();
                long jmpOffAddr = Long.parseLong(beqOpStr.replace("#", "").replace("0x", ""), 16);
                Block blk = new Block();
                blk.addr = jmpOffAddr + moduleBaseAddr;
                blk.idx = idx;
                if (!mRealBlocks.contains(blk)) {
                    mRealBlocks.add(blk);
                }
                System.out.printf("condDispatcher-true: %s\n", blk);
            }
        }

        if (isMatchRealBlockTailPattern(ins1, ins2, curIns)) {
            // 1. RealBlock 跳转地址，即 mMatchQueueAddr 最后一个元素（moduleBaseAddr）
            long curRbJmpAddr = mTraceAddr.get(mTraceAddr.size() - 1);

            // 2. RealBlock 下一跳索引，解析 STUR  W[n], [idx]，获取 n 寄存器值
            String[] sturOpStr = ins2.getOpStr().split(",");
            String regN = sturOpStr[0].trim();
            int reg = UC_ARM64_REG_X0 + Integer.parseInt(regN.replace("w", ""));
            long nextRbIdx = getWReg(backend.reg_read(reg).longValue());

            // 3. 回溯查找当前 RealBlock 索引值，回溯到 b.eq，获取当前块索引值以及 entry 地址
            long curRbIdx = -1;
            long curRbEntryAddr = -1;
            for (int i = mTraceIns.size() - 3; i >= 0; i--) { // 从 ins1 开始向上查找
                Instruction ins = mTraceIns.get(i);
                if (!"b.eq".equals(ins.getMnemonic().toLowerCase(Locale.ROOT))) continue;

                Regs regs = mTraceRegs.get(i);
                curRbIdx = getWReg(regs.getRegV(UC_ARM64_REG_X9)); // 索引值
                curRbEntryAddr = mTraceAddr.get(i + 1); // entry 地址
                break;
            }

            // 4. 保存真实块，如果前驱中保存过真实块，则进行更新
            Block blk = new Block();
            blk.idx = curRbIdx;
            blk.nextIdx = nextRbIdx;
            blk.addr = curRbEntryAddr;
            blk.jmpAddr = curRbJmpAddr;
            System.out.printf("realBlock：%s\n", blk);
            int index = mRealBlocks.indexOf(blk);
            if (index == -1) mRealBlocks.add(blk);
            else mRealBlocks.set(index, blk);
        }
    }

    @Override
    List<JmpPatch> extractJmpPatches() {
        final List<JmpPatch> jmpPatches = new ArrayList<>();
        List<Block> rbs = new ArrayList<>(mRealBlocks);

        Block curBlk = mMainDispatchBlock;
        while (!rbs.isEmpty()) {
            JmpPatch jp = new JmpPatch();
            jp.addr = curBlk.jmpAddr;
            boolean found = false;
            for (Block b : rbs) {
                if (curBlk.nextIdx == b.idx) {
                    found = true;
                    jp.jmpAddr = b.addr;
                    jmpPatches.add(jp);
                    curBlk = b;
                    rbs.remove(b);
                }
                rbs.remove(b);
                break;
            }

            if (!found) {
                System.out.printf("中断，无法提取所有 JmpPatch。miss: %s\n", curBlk);
                return null;
            }
        }
        return jmpPatches;
    }

    /**
     * 匹配真实块尾部，模式如下
     * CSEL    W9, regN, regN, COND
     * STUR    W9, [idx]
     * B       ind_jmp_blk ;; 即间接跳转块地址
     */
    boolean isMatchRealBlockTailPattern(Instruction ins1, Instruction ins2, Instruction ins3) {
        if (ins1 == null || ins2 == null || ins3 == null) return false;
        if (!"csel".equals(ins1.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        if (!"stur".equals(ins2.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        return "b".equals(ins3.getMnemonic().toLowerCase(Locale.ROOT));
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
