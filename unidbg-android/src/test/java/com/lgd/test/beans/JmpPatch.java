package com.lgd.test.beans;

/**
 * 跳转布丁，将汇编
 * addr     b.eq  someAddr
 * 转换成如下
 * addr     b jmpAddr
 */
public class JmpPatch extends AddressPatch {
    public long jmpAddr; // 待跳转指令

    public JmpPatch() {
        super(0);
    }

    public JmpPatch(long addr, long jmpAddr) {
        super(addr);
        this.jmpAddr = jmpAddr;
    }

    @Override
    public String toString() {
        return String.format("[addr: %x, jmpAddr: %x]", addr, jmpAddr);
    }

    @Override
    public String getAssemble() {
        return String.format("b #0x%x", jmpAddr - addr);
    }
}
