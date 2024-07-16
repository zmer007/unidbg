package com.lgd.test.utils;

import org.junit.Test;

import java.math.BigInteger;

public class Tools {
    @Test
    public void t() {
        System.out.println(toOC("ffffffffffffffff")); // -1
        System.out.println(toOC("fffffffffffffc0c")); // -1012
        System.out.println(toOC("0000000000000c0c")); // 3084
    }

    /**
     * 将 16 进制字符串形式的补码转换成原码
     */
    static long toOC(String comp) {
        BigInteger bi = new BigInteger(comp, 16);

        // 判断是否为负数（补码表示的负数）
        if (bi.testBit(bi.bitLength() - 1)) {
            // 计算补码
            BigInteger complement = new BigInteger("1").shiftLeft(comp.length() * 4);
            bi = bi.subtract(complement);
        }
        return bi.longValue();
    }
}
