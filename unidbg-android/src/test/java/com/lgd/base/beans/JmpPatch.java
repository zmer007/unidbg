package com.lgd.base.beans;

/**
 * 跳转布丁，将汇编
 * addr     b.eq  someAddr
 * 转换成如下
 * addr     b jmpAddr
 */
public class JmpPatch extends AddressPatch {
    public long addr;
    public long jmpAddr; // 待跳转指令

    public JmpPatch(long addr, long jmpAddr) {
        this.addr = addr;
        this.jmpAddr = jmpAddr;
    }

    @Override
    public long getAddr() {
        return addr;
    }

    @Override
    public String getAssemble() {
        return String.format("b #0x%x", jmpAddr - addr);
    }
}
