package com.lgd.netease.env;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class ContentResolver extends DvmObject<Object> {
    public ContentResolver(VM vm) {
        super(vm.resolveClass("android/content/ContentResolver"), null);
    }
}