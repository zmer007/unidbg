package com.lgd.test.beans;

/**
 * 跳转布丁，将汇编
 * addr     b.eq  someAddr
 * 转换成如下
 * addr     b jmpAddr
 */
public class JmpPatch {
    public long addr; // 将此处地址的指令替换
    public long jmpAddr; // 待跳转指令
}
