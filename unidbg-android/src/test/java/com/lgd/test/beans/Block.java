package com.lgd.test.beans;

import java.util.Objects;

public class Block {
    public long addr;
    public long jmpAddr;

    public long idx;
    public long nextIdx;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Block block = (Block) o;
        return addr == block.addr;
    }

    @Override
    public int hashCode() {
        return Objects.hash(addr);
    }

    @Override
    public String toString() {
        return String.format("[addr: %x, idx: %x, nextIdx: %x, jmpAddr: %x]", addr, idx, nextIdx, jmpAddr);
    }
}
