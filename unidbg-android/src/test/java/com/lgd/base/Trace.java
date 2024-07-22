package com.lgd.base;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import com.lgd.base.beans.AddressPatch;
import com.lgd.base.beans.Regs;
import com.lgd.base.utils.FixedSizeQueue;

import java.util.List;

public abstract class Trace {
    protected final FixedSizeQueue<Instruction> mTraceIns;
    protected final FixedSizeQueue<Long> mTraceAddr;
    protected final FixedSizeQueue<Regs> mTraceRegs;

    protected final long mFuncEntry;
    protected final long mFuncLength;
    protected final long mMainDispatcherJmpAddr;
    protected final Object[] mArgs;

    public Trace(FixedSizeQueue<Instruction> traceIns, FixedSizeQueue<Long> traceddr, FixedSizeQueue<Regs> traceRegs,
                 long funcEntry, long funcLength, long mainDispatcherJmpAddr, Object... args) {
        mTraceIns = traceIns;
        mTraceAddr = traceddr;
        mTraceRegs = traceRegs;
        mFuncEntry = funcEntry;
        mFuncLength = funcLength;
        mMainDispatcherJmpAddr = mainDispatcherJmpAddr;
        mArgs = args;
    }

    public abstract void onTrace(Backend backend, long address, long moduleOffAddr, int size);


    public abstract List<AddressPatch> extractJmpPatches();
}
