package com.lgd.test.beans;

import java.util.Objects;

public class FlaIndex {
    public long addr;
    public long jmpAddr;

    public long idx;
    public long nextIdx;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FlaIndex flaIndex = (FlaIndex) o;
        return addr == flaIndex.addr && jmpAddr == flaIndex.jmpAddr && idx == flaIndex.idx && nextIdx == flaIndex.nextIdx;
    }

    @Override
    public int hashCode() {
        return Objects.hash(addr, jmpAddr, idx, nextIdx);
    }

    @Override
    public String toString() {
        return String.format("[addr: %x, idx: %x, nextIdx: %x, jmpAddr: %x]", addr, idx, nextIdx, jmpAddr);
    }
}
