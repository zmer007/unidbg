package com.lgd.test;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import com.lgd.test.beans.JmpPatch;
import com.lgd.test.beans.Regs;
import com.lgd.test.utils.FixedSizeQueue;

import java.util.List;

public abstract class Trace {
    final FixedSizeQueue<Instruction> mTraceIns;
    final FixedSizeQueue<Long> mTraceAddr;
    final FixedSizeQueue<Regs> mTraceRegs;

    final long mFuncEntry;
    final long mFuncLength;
    final long mMainDispatcherJmpAddr;

    public Trace(FixedSizeQueue<Instruction> traceIns, FixedSizeQueue<Long> traceddr, FixedSizeQueue<Regs> traceRegs,
                 long funcEntry, long funcLength, long mainDispatcherJmpAddr) {
        mTraceIns = traceIns;
        mTraceAddr = traceddr;
        mTraceRegs = traceRegs;
        mFuncEntry = funcEntry;
        mFuncLength = funcLength;
        mMainDispatcherJmpAddr = mainDispatcherJmpAddr;
    }

    abstract void onTrace(Backend backend, long address, long moduleOffAddr, int size);


    abstract List<JmpPatch> extractJmpPatches();
}
