package com.lgd.test.beans;

import capstone.api.Instruction;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class InsBlock {
    public final long startAddr;
    public final long endAddr;
    List<Long> insAryAddress;
    List<Instruction> insAry;

    public InsBlock(long start, long end) {
        startAddr = start;
        endAddr = end;
        insAry = new ArrayList<>();
        insAryAddress = new ArrayList<>();
    }

    public void addIns(long addr, Instruction ins) {
        if (addr > endAddr || addr < startAddr) return;
        if (isContain(ins)) return;

        insAry.add(ins);
        insAryAddress.add(addr);
    }

    boolean isContain(Instruction ins) {
        for (Instruction i : insAry) {
            if (Objects.equals(i.getMnemonic(), ins.getMnemonic()) && Objects.equals(i.getOpStr(), ins.getOpStr())) {
                return true;
            }
        }
        return false;
    }

    public List<Instruction> getInsAry(boolean sort) {
        if (!sort) return insAry;
        insAry.sort((o1, o2) -> (int) (o1.getAddress() - o2.getAddress()));
        return insAry;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("ins scope: [%x-%x]\n", startAddr, endAddr));
        for (int i = 0; i < insAry.size(); i++) {
            Instruction ins = insAry.get(i);
            sb.append(String.format("%x %s %s\n", insAryAddress.get(i), ins.getMnemonic(), ins.getOpStr()));
        }
        return sb.toString().trim();
    }
}
