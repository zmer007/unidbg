package com.lgd.netease.env;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class Sensor extends DvmObject<Object> {
    public Sensor(VM vm) {
        super(vm.resolveClass("android/hardware/Sensor"), null);
    }
}