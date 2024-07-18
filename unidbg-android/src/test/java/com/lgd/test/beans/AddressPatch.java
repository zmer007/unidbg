package com.lgd.test.beans;

public abstract class AddressPatch {
    public long addr;

    public AddressPatch(long addr) {
        this.addr = addr;
    }

    public abstract String getAssemble();

}
