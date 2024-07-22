package com.lgd.base.beans;

import java.util.Objects;

public class FixPatch extends AddressPatch {
    long addr;
    final String mAssemble;

    public FixPatch(long addr, String assemble) {
        this.addr = addr;
        mAssemble = assemble;
    }

    @Override
    public long getAddr() {
        return addr;
    }

    @Override
    public String getAssemble() {
        return mAssemble;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FixPatch)) return false;
        FixPatch that = (FixPatch) o;
        return Objects.equals(mAssemble, that.mAssemble) && Objects.equals(addr, ((FixPatch) o).addr);
    }

    @Override
    public int hashCode() {
        return Objects.hash(addr, mAssemble);
    }
}
