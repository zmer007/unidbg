package com.lgd.test;

import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.AndroidElfLoader;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.lgd.test.beans.AddressPatch;
import com.lgd.test.beans.Regs;
import com.lgd.test.utils.FixedSizeQueue;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.List;

public class FlaReverseMain {

    final static int MAX_FILTER_SIZE = 80; // 此值必须大于最大真实块指令个数，否则无法匹配到真实块入口地址

    final static String SO_ROOT_DIR = "unidbg-android/src/test/resources/lgd";
    final AndroidEmulator mEmulator;
    final Module mTargetModule;
    final File mTargetLibF;
    final DalvikModule mDm;
    final VM mVm;

    final Capstone mCpst = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);

    final FixedSizeQueue<Instruction> mMatchQueueIns = new FixedSizeQueue<>(MAX_FILTER_SIZE);
    final FixedSizeQueue<Long> mMatchQueueAddr = new FixedSizeQueue<>(MAX_FILTER_SIZE);
    final FixedSizeQueue<Regs> mMatchQueueRegs = new FixedSizeQueue<>(MAX_FILTER_SIZE);
    Trace mCurTrace;

    public static void main(String[] args) {
        FlaReverseMain fk = new FlaReverseMain();
        fk.traverseWatcher();

        System.out.println("-------------------------------call_JNI_OnLoad start----------------------------------");
        fk.call_JNI_OnLoad("");
        System.out.println("-------------------------------call_JNI_OnLoad finished-------------------------------");

        System.out.println("-------------------------------call_stringFromJNI start----------------------------------");
        fk.call_stringFromJNI("");
        System.out.println("-------------------------------call_stringFromJNI finished-------------------------------");

        System.out.println("-------------------------------call_fibonacci start----------------------------------");
        fk.call_fibonacci("");
        System.out.println("-------------------------------call_fibonacci finished-------------------------------");
    }

    FlaReverseMain() {
        Logger.getLogger(LinuxModule.class).setLevel(Level.WARN);
        Logger.getLogger(AndroidElfLoader.class).setLevel(Level.WARN);
        mEmulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).setProcessName("com.lgd.helloollvm").build();
        Memory memory = mEmulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        mVm = mEmulator.createDalvikVM();
        mVm.setVerbose(true);
        mTargetLibF = new File(SO_ROOT_DIR + "/libhelloollvm.so");
        mDm = mVm.loadLibrary(mTargetLibF, false);
        mTargetModule = mDm.getModule();
    }

    // suffix 即后缀名，代表修复后是否增加后缀名，如果后缀名为空，则代表覆盖原文件
    void call_JNI_OnLoad(String suffix) {
        mCurTrace = new Trace_JNI_OnLoad(mMatchQueueIns, mMatchQueueAddr, mMatchQueueRegs,
                0x172C, 0x5E4, 0x179C); // 手动介入

        mDm.callJNI_OnLoad(mEmulator);

        // 修复 so 文件
        List<AddressPatch> jmpPatches = mCurTrace.extractJmpPatches();
        patchLibFile(mTargetLibF, jmpPatches, suffix);

        mCurTrace = null;
    }

    void call_stringFromJNI(String suffix) {
        mCurTrace = new Trace_stringFromJNI(mMatchQueueIns, mMatchQueueAddr, mMatchQueueRegs,
                0x1474, 0x2B8, 0x14C8); // 手动介入

        int arg = 10;
        DvmClass JNIHelper = mVm.resolveClass("com/lgd/helloollvm/JNIHelper");
        DvmObject<String> str = JNIHelper.newObject(null).callJniMethodObject(mEmulator, "stringFromJNI(I)Ljava/lang/String;", arg);
        System.out.printf("stringFromJNI(%d) retVal= %s\n", arg, str);

        // 修复 so 文件
        List<AddressPatch> jmpPatches = mCurTrace.extractJmpPatches();
        patchLibFile(mTargetLibF, jmpPatches, suffix);

        mCurTrace = null;
    }

    void call_fibonacci(String suffix) {
        long arg = 10;
        mCurTrace = new Trace_fibonacci(mMatchQueueIns, mMatchQueueAddr, mMatchQueueRegs,
                0x91C, 0xB58, 0x95C, arg); // 手动介入

        Number cfNum = mTargetModule.callFunction(mEmulator, 0x91C, arg);
        Pointer ptrRet = UnidbgPointer.pointer(mEmulator, cfNum);
        System.out.println(ptrRet.getString(0));

        // 修复 so 文件
        List<AddressPatch> jmpPatches = mCurTrace.extractJmpPatches();
        patchLibFile(mTargetLibF, jmpPatches, suffix);

        mCurTrace = null;
    }

    void patchLibFile(File inFile, List<AddressPatch> patches, String suffix) {
        if (inFile == null || !inFile.exists()) {
            System.out.println("patch failed: input file not exists.");
            return;
        }
        if (patches == null || patches.isEmpty()) {
            System.out.println("patch failed: patches not found.");
            return;
        }
        try {
            File outFile = suffix == null || suffix.trim().isEmpty() ?
                    inFile : new File(inFile.getAbsolutePath() + "." + suffix);
            Keystone ks = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);

            FileInputStream fis = new FileInputStream(inFile);
            byte[] data = new byte[(int) inFile.length()];
            fis.read(data);
            fis.close();
            for (AddressPatch jp : patches) {
                KeystoneEncoded ke = ks.assemble(jp.getAssemble());
                for (int i = 0; i < ke.getMachineCode().length; i++) {
                    data[(int) jp.getAddr() + i] = ke.getMachineCode()[i];
                }
            }
            FileOutputStream fos = new FileOutputStream(outFile);
            fos.write(data);
            fos.flush();
            fos.close();
            System.out.println(suffix + " 修复完成：" + outFile.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void onTrace(Backend backend, long address, int size) {
        long moduleBaseAddr = address - mTargetModule.base;

        byte[] buf = backend.mem_read(address, size);
        Instruction[] asm = mCpst.disasm(buf, 0);
        Instruction curIns = asm[0];
        mMatchQueueIns.add(curIns);
        mMatchQueueAddr.add(moduleBaseAddr);
        mMatchQueueRegs.add(restoreRegs(backend));
        if (mCurTrace != null) mCurTrace.onTrace(backend, address, moduleBaseAddr, size);
    }

    void traverseWatcher() {
        mEmulator.getBackend().hook_add_new(new CodeHook() {

            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                onTrace(backend, address, size);
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, mTargetModule.base, mTargetModule.base + mTargetModule.size, null);
    }

    Regs restoreRegs(Backend bk) {
        Regs retVal = new Regs(ARM.getAll64Registers());
        int[] regs = ARM.getAll64Registers();
        for (int reg : regs) {
            retVal.updateRegValue(reg, bk.reg_read(reg).longValue());
        }
        return retVal;
    }
}
