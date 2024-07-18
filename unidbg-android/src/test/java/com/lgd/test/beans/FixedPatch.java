package com.lgd.test.beans;

public class FixedPatch extends AddressPatch {
    final String mAssemble;

    public FixedPatch(long addr, String assemble) {
        super(addr);
        mAssemble = assemble;
    }

    @Override
    public String getAssemble() {
        return mAssemble;
    }
}
