package com.lgd.netease.env;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class File extends DvmObject<Object> {
    public File(VM vm) {
        super(vm.resolveClass("java/io/File"), null);
    }
}