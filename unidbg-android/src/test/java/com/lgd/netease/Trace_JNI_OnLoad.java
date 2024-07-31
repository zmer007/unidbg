package com.lgd.netease;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import com.lgd.base.Trace;
import com.lgd.base.beans.AddressPatch;
import com.lgd.base.beans.Regs;
import com.lgd.base.utils.FixedSizeQueue;

import java.util.List;

public class Trace_JNI_OnLoad extends Trace {

    public Trace_JNI_OnLoad(FixedSizeQueue<Instruction> traceIns, FixedSizeQueue<Long> traceddr, FixedSizeQueue<Regs> traceRegs, long funcEntry, long funcLength, long mainDispatcherJmpAddr, Object... args) {
        super(traceIns, traceddr, traceRegs, funcEntry, funcLength, mainDispatcherJmpAddr, args);
    }

    @Override
    public void onTrace(Backend backend, long address, long moduleOffAddr, int size) {
        // 避免进入子函数
        if (moduleOffAddr < mFuncEntry || moduleOffAddr > mFuncEntry + mFuncLength) return;

        int qSize = mTraceIns.size();
        Instruction ins1 = mTraceIns.get(qSize - 3);
        Instruction ins2 = mTraceIns.get(qSize - 2);
        Instruction curIns = mTraceIns.get(qSize - 1);
        // 打印当前指令
        // if (curIns != null) System.out.printf("%x %s %s\n", moduleOffAddr, curIns.getMnemonic(), curIns.getOpStr());
    }

    @Override
    public List<AddressPatch> extractJmpPatches() {
        return null;
    }
}
