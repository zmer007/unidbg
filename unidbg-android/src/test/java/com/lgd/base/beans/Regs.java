package com.lgd.base.beans;

public class Regs {
    final int[] registers;
    final long[] registersV;

    public Regs(int[] registers) {
        this.registers = registers;
        registersV = new long[this.registers.length];
    }

    public void updateRegValue(int reg, long val) {
        for (int i = 0; i < registers.length; i++) {
            if (registers[i] == reg) {
                registersV[i] = val;
                break;
            }
        }
    }

    public long getRegV(int reg) {
        for (int i = 0; i < registers.length; i++) {
            if (registers[i] == reg) return registersV[i];
        }
        throw new IllegalStateException("非法 arm64 寄存器");
    }

    public static long getWReg(long xReg) {
        return xReg & 0xFFFFFFFFL;
    }
}
