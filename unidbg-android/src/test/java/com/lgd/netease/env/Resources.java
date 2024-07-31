package com.lgd.netease.env;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class Resources extends DvmObject<Object> {
    public Resources(VM vm) {
        super(vm.resolveClass("android/content/res/Resources"), null);
    }
}
