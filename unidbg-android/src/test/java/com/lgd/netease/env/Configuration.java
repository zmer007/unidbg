package com.lgd.netease.env;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class Configuration extends DvmObject<Object> {
    public Configuration(VM vm) {
        super(vm.resolveClass("android/content/res/Configuration"), null);
    }
}