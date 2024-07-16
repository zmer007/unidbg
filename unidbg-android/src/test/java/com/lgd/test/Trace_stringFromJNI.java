package com.lgd.test;

import capstone.api.Instruction;
import com.github.unidbg.arm.backend.Backend;
import com.lgd.test.beans.JmpPatch;
import com.lgd.test.beans.Regs;
import com.lgd.test.utils.FixedSizeQueue;

import java.util.List;

public class Trace_stringFromJNI extends Trace {

    public Trace_stringFromJNI(FixedSizeQueue<Instruction> queueIns,
                               FixedSizeQueue<Long> queueAddr,
                               FixedSizeQueue<Regs> queueRegs,
                               long funcEntry, long funcLength, long mainDispatcherJmpAddr) {
        super(queueIns, queueAddr, queueRegs, funcEntry, funcLength, mainDispatcherJmpAddr);
    }

    @Override
    void onTrace(Backend backend, long address, long moduleBaseAddr, int size) {

    }

    @Override
    List<JmpPatch> extractJmpPatches() {
        return null;
    }
}
