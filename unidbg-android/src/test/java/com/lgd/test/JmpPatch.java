package com.lgd.test;

/**
 * 跳转布丁，将汇编
 * addr     b.eq  someAddr
 * 转换成如下
 * addr     b jmpAddr
 */
public class JmpPatch {
    long addr; // 将此处地址的指令替换
    long jmpAddr; // 待跳转指令
}
