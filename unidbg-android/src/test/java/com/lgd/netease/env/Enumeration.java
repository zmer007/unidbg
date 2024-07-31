package com.lgd.netease.env;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class Enumeration  extends DvmObject<Object> {
    public Enumeration(VM vm) {
        super(vm.resolveClass("java/util/Enumeration"), null);
    }
}