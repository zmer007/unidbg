package com.lgd.netease;

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
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.ApplicationInfo;
import com.github.unidbg.linux.android.dvm.api.Binder;
import com.github.unidbg.linux.android.dvm.api.SystemService;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.lgd.base.Trace;
import com.lgd.base.beans.AddressPatch;
import com.lgd.base.beans.Regs;
import com.lgd.base.utils.FixedSizeQueue;
import com.lgd.netease.env.*;
import com.lgd.netease.env.Enumeration;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

public class Main extends AbstractJni {
    final static String PKG_NAME = "com.netease.cloudmusic";
    final static int MAX_FILTER_SIZE = 80; // 此值必须大于最大真实块指令个数，否则无法匹配到真实块入口地址

    final static String SO_ROOT_DIR = "unidbg-android/src/test/resources/lgd/netease";
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
        Main fk = new Main();
        fk.traverseWatcher();

        System.out.println("-------------------------------call_JNI_OnLoad start----------------------------------");
        fk.call_JNI_OnLoad("JNI_OnLoad");
        System.out.println("-------------------------------call_JNI_OnLoad finished-------------------------------");

        System.out.println("-------------------------------call_JNIFactory_w238 start----------------------------------");
        fk.call_JNIFactory_w238("JNIFactory_w238");
        System.out.println("-------------------------------call_JNIFactory_w238 finished-------------------------------");
    }

    Main() {
        Logger.getLogger(LinuxModule.class).setLevel(Level.WARN);
        Logger.getLogger(AndroidElfLoader.class).setLevel(Level.WARN);
        mEmulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).setProcessName(PKG_NAME).build();
        Memory memory = mEmulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        mVm = mEmulator.createDalvikVM(new File("/Users/lgd/OneByOne/0718易盾逆向/wywyy.apk"));
        mVm.setDvmClassFactory(new ProxyClassFactory() {
            @Override
            public DvmClass createClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses) {
                System.out.println("ProxyCreateClass: " + className);
                if ("com/netease/mobsec/poly/a".equals(className)) {
                    return new MobsecPolyA(vm, className, superClass, interfaceClasses);
                }
                return vm.createClass(vm, className, superClass, interfaceClasses);
            }
        });
        mVm.setVerbose(true);
        mVm.setJni(this);
        mTargetLibF = new File(SO_ROOT_DIR + "/libnetmobsec-4.4.7.so");
        mDm = mVm.loadLibrary(mTargetLibF, true);
        mTargetModule = mDm.getModule();
    }

    // suffix 即后缀名，代表修复后是否增加后缀名，如果后缀名为空，则代表覆盖原文件
    void call_JNI_OnLoad(String suffix) {
        mCurTrace = new Trace_JNI_OnLoad(mMatchQueueIns, mMatchQueueAddr, mMatchQueueRegs, 0x05744C, 0x7C, 0x05744C); // 手动介入

        mDm.callJNI_OnLoad(mEmulator);

//        // 修复 so 文件
//        List<AddressPatch> jmpPatches = mCurTrace.extractJmpPatches();
//        patchLibFile(mTargetLibF, jmpPatches, suffix);

        mCurTrace = null;


    }

    void call_JNIFactory_w238(String suffix) {
        mCurTrace = new Trace_JNIFactory_w238(mMatchQueueIns, mMatchQueueAddr, mMatchQueueRegs, 0x3ef04, 0x7f8, 0x14C8); // 手动介入

        DvmClass contextClass = mVm.resolveClass("android/content/Context");
        DvmObject<?> arg1 = contextClass.newObject(null);

        // [200,A4.4.7.7,,,60d3ed071a754a8e85ee19d6a0c2a29a,1722308792,0,,,YD00000558929251,00OMqzM268SvmPEfEv4i9dzNtA2o1AAAAGRAZrL5w,ali,,false,]
        ArrayObject arg2 = ArrayObject.newStringArray(mVm, "200", "A4.4.7.7", "", "",
                "60d3ed071a754a8e85ee19d6a0c2a29a", "1722308792", "0", "", "", "YD00000558929251",
                "00OMqzM268SvmPEfEv4i9dzNtA2o1AAAAGRAZrL5w", "ali", "", "false");

        DvmClass JNIHelper = mVm.resolveClass("com/netease/mobsec/factory/JNIFactory");
        DvmObject<String> str = JNIHelper.newObject(null)
                .callJniMethodObject(mEmulator,
                        "w238jfd9349jdj394(Ljava/lang/Object;[Ljava/lang/String;)Ljava/lang/String;",
                        arg1, arg2);
        System.out.printf("JNIFactory_w238 retVal= %s\n", str);

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
            File outFile = suffix == null || suffix.trim().isEmpty() ? inFile : new File(inFile.getAbsolutePath() + "." + suffix);
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

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("com/netease/mobsec/poly/a->o:I".equals(signature)) {
            return 0;
        } else if ("com/netease/mobsec/poly/a->p:I".equals(signature)) {
            return 0;
        } else if ("android/os/BatteryManager->BATTERY_PROPERTY_CAPACITY:I".equals(signature)) {
            return 0;
        } else if ("android/accessibilityservice/AccessibilityServiceInfo->FEEDBACK_ALL_MASK:I".equals(signature)) {
            return 0xFFFFFFFF; // FEEDBACK_ALL_MASK
        } else if ("".equals(signature)) {
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/pm/PackageInfo->firstInstallTime:J".equals(signature)) {
            return 1716243923000L;
        } else if ("android/content/pm/PackageInfo->lastUpdateTime:J".equals(signature)) {
            return 1716243923000L;
        }
        return super.getLongField(vm, dvmObject, signature);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("android/view/accessibility/AccessibilityManager->isEnabled()Z".equals(signature)) {
            return false;
        } else if ("".equals(signature)) {
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("android/content/Context->getResources()Landroid/content/res/Resources;".equals(signature)) {
            return new Resources(vm);
        } else if ("android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;".equals(signature)) {
            return new ApplicationInfo(vm);
        } else if ("android/content/res/Resources->getConfiguration()Landroid/content/res/Configuration;".equals(signature)) {
            return new Configuration(vm);
        } else if ("android/content/Context->getFilesDir()Ljava/io/File;".equals(signature)) {
            return new com.lgd.netease.env.File(vm);
        } else if ("java/io/File->getPath()Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "/data/data/" + PKG_NAME + "/files");
        } else if ("android/content/Context->getContentResolver()Landroid/content/ContentResolver;".equals(signature)) {
            return new ContentResolver(vm);
        } else if ("android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;".equals(signature)) {
            StringObject serviceName = vaList.getObjectArg(0);
            assert serviceName != null;
            return new SystemService(vm, serviceName.getValue());
        } else if ("android/telephony/TelephonyManager->getSimCountryIso()Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "zh");
        } else if ("android/hardware/SensorManager->getSensorList(I)Ljava/util/List;".equals(signature)) {
            List<Sensor> ss = new ArrayList<>();
            return new ArrayListObject(vm, ss);
        } else if ("".equals(signature)) {
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("android/provider/Settings$Secure->getStringForUser(Landroid/content/ContentResolver;Ljava/lang/String;I)Ljava/lang/String;".equals(signature)) {
            return vaList.getObjectArg(1);
        } else if ("com/netease/mobsec/poly/a->b(Landroid/content/Context;)Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "1080*2160");
        } else if ("android/provider/Settings$System->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;".equals(signature)) {
            DvmObject<?> arg1 = vaList.getObjectArg(1);
            String key = (String) arg1.getValue();
            if ("screen_brightness".equals(key)) {
                return new StringObject(vm, "0.38188976");
            }
        } else if ("android/os/ServiceManager->getService(Ljava/lang/String;)Landroid/os/IBinder;".equals(signature)) {
            return new Binder(vm, signature);
        } else if ("android/os/Environment->getExternalStorageState()Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "/sdcard");
        } else if ("java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "mock");
        } else if ("java/net/NetworkInterface->getNetworkInterfaces()Ljava/util/Enumeration;".equals(signature)) {
            return new ArrayObject(new Enumeration(vm));
        } else if ("".equals(signature)) {
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/pm/ApplicationInfo->publicSourceDir:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "/data/app/" + PKG_NAME + "/base.apk");
        } else if ("android/content/pm/ApplicationInfo->processName:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, PKG_NAME);
        } else if ("".equals(signature)) {

        }
        return super.getObjectField(vm, dvmObject, signature);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("android/content/Context->BATTERY_SERVICE:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "batterymanager");
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/res/Configuration->screenLayout:I".equals(signature)) {
            return 0x02; // SCREENLAYOUT_SIZE_NORMAL
        }
        return super.getIntField(vm, dvmObject, signature);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("android/os/Process->myUid()I".equals(signature)) {
            return 11069;
        } else if ("android/provider/Settings$Secure->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I".equals(signature)) {
            return 0;
        } else if ("com/netease/mobsec/poly/a->c(Landroid/content/Context;)I".equals(signature)) {
            return 1; // NetworkInfo#getType
        } else if ("".equals(signature)) {
        }
        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("android/telephony/TelephonyManager->getSimState()I".equals(signature)) {
            return 5; // SIM_STATE_READY
        } else if ("android/content/Context->checkCallingOrSelfPermission(Ljava/lang/String;)I".equals(signature)) {
            return 0; // PERMISSION_GRANTED
        } else if ("".equals(signature)) {
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }
}

