package com.lgd.test.beans;

public abstract class AddressPatch {
    public abstract long getAddr();

    public abstract String getAssemble();

    @Override
    public String toString() {
        return String.format("path: %x\t%s", getAddr(), getAssemble());
    }
}
