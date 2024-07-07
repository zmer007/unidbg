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
import java.util.Locale;

import static com.lgd.test.Regs.getWReg;
import static unicorn.Arm64Const.*;

public class FlaKiller {

    final static int MAX_FILTER_SIZE = 80; // 此值必须大于最大真实块指令个数，否则无法匹配到真实块入口地址

    final static String SO_ROOT_DIR = "unidbg-android/src/test/resources/lgd";
    final AndroidEmulator mEmulator;
    final Module mTargetModule;
    final DalvikModule mDm;
    final VM mVm;

    final Capstone mCpst = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);

    long mMainDispatcherJmpAddr;
    Block mMainDispatchBlock;
    final List<Long> mMainDispatcherIdxs = new ArrayList<>(); // 记录主选择器索引顺序
    final List<Block> mRealBlocks = new ArrayList<>();

    final FixedSizeQueue<Instruction> mMatchQueueIns = new FixedSizeQueue<>(MAX_FILTER_SIZE);
    final FixedSizeQueue<Long> mMatchQueueAddr = new FixedSizeQueue<>(MAX_FILTER_SIZE);
    final FixedSizeQueue<Regs> mMatchQueueRegs = new FixedSizeQueue<>(MAX_FILTER_SIZE);

    public static void main(String[] args) {
        FlaKiller fk = new FlaKiller();
        fk.traverseWatcher();
        fk.call_JNI_OnLoad("JNI_OnLoad");
        fk.call_stringFromJNI();
    }

    public void pathLib(File soF, List<JmpPatch> patches, File patchedF) throws Exception {
        Keystone ks = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);

        FileInputStream fis = new FileInputStream(soF);
        byte[] data = new byte[(int) soF.length()];
        fis.read(data);
        fis.close();
        for (JmpPatch jp : patches) {
            String jmp = String.format("b.eq #0x%x", jp.jmpAddr - jp.addr);
            KeystoneEncoded ke = ks.assemble(jmp);
            for (int i = 0; i < ke.getMachineCode().length; i++) {
                data[(int) jp.addr + i] = ke.getMachineCode()[i];
            }
        }
        FileOutputStream fos = new FileOutputStream(patchedF);
        fos.write(data);
        fos.flush();
        fos.close();
    }

    FlaKiller() {
        Logger.getLogger(LinuxModule.class).setLevel(Level.WARN);
        Logger.getLogger(AndroidElfLoader.class).setLevel(Level.WARN);
        mEmulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).setProcessName("com.lgd.helloollvm").build();
        Memory memory = mEmulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        mVm = mEmulator.createDalvikVM();
        mVm.setVerbose(true);
        mDm = mVm.loadLibrary(new File(SO_ROOT_DIR + "/libhelloollvm.so"), false);
        mTargetModule = mDm.getModule();
    }

    // suffix 即后缀名，代表修复后是否增加后缀名，如果后缀名为空，则代表覆盖原文件
    void call_JNI_OnLoad(String suffix) {
        resetMatches(0x179C);
        mDm.callJNI_OnLoad(mEmulator);
        List<JmpPatch> jmpPatches = extractJmpPatches(mRealBlocks, mMainDispatchBlock);
        try {
            File inFile = new File(SO_ROOT_DIR + "/libhelloollvm.so");
            File outFile = suffix == null || suffix.trim().isEmpty() ?
                    inFile : new File(SO_ROOT_DIR + "/libhelloollvm.so." + suffix);
            pathLib(inFile, jmpPatches, outFile);
            System.out.println("修复完成：" + outFile.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void call_stringFromJNI() {
        resetMatches(0x179C);
        DvmClass JNIHelper = mVm.resolveClass("com/lgd/helloollvm/JNIHelper");
        DvmObject<String> str = JNIHelper.newObject(null).callJniMethodObject(mEmulator, "stringFromJNI(I)Ljava/lang/String;", 5);
        System.out.println(str);
    }

    private void resetMatches(long addr) {
        mMainDispatcherJmpAddr = addr;
        mMainDispatcherIdxs.clear();
        mRealBlocks.clear();
    }

    void onTrace(Backend backend, long address, int size) {
        long curAddr = address - mTargetModule.base;
        byte[] buf = backend.mem_read(address, size);
        Instruction[] asm = mCpst.disasm(buf, 0);
        Instruction curIns = asm[0];
        // System.out.printf("%x %s %s\n", curAddr, curIns.getMnemonic(), curIns.getOpStr());
        mMatchQueueIns.add(curIns);
        mMatchQueueAddr.add(curAddr);
        mMatchQueueRegs.add(restoreRegs(backend));

        int qSize = mMatchQueueIns.size();
        if (qSize < 3) return;
        Instruction ins1 = mMatchQueueIns.get(qSize - 3);
        Instruction ins2 = mMatchQueueIns.get(qSize - 2);
        Instruction ins3 = mMatchQueueIns.get(qSize - 1);

        if (curAddr == mMainDispatcherJmpAddr) {
            long idx = getWReg(backend.reg_read(UC_ARM64_REG_X9).longValue());
            System.out.printf("mainDispatcher: idx=%x\n", idx);

            mMainDispatcherIdxs.add(idx);
            if (mMainDispatchBlock == null) {
                mMainDispatchBlock = new Block();
                mMainDispatchBlock.addr = -1;
                mMainDispatchBlock.idx = idx;
                mMainDispatchBlock.nextIdx = mMainDispatchBlock.idx;
                mMainDispatchBlock.jmpAddr = curAddr;
            }
        }

        if (curAddr == 0x1c7c + size * 6L) { // 手动修复 0x1c7c 真实块
            long idx = getWReg(mMatchQueueRegs.get(mMatchQueueRegs.size() - 6).getRegV(UC_ARM64_REG_X9));
            long nextIdx = getWReg(backend.reg_read(UC_ARM64_REG_X8).longValue());
            String beqOpStr = curIns.getOpStr();
            long jmpOffAddr = Long.parseLong(beqOpStr.replace("#", "").replace("0x", ""), 16);
            System.out.printf("manualFixRb: addr= 0x1c7c, idx= %x, nextIdx= %x, jmpAddr= %x, ins = %s\n", idx, nextIdx, jmpOffAddr + curAddr, curIns);
            for (Block blk : mRealBlocks) {
                if (blk.addr == 0x1c7c) {
                    blk.nextIdx = nextIdx;
                    blk.jmpAddr = jmpOffAddr + curAddr;
                }
            }
        }

        if (isMatchRbPrevPatter(ins1, ins2, ins3)) {
            long idx = getWReg(backend.reg_read(UC_ARM64_REG_X9).longValue());
            long zReg = backend.reg_read(UC_ARM64_REG_NZCV).longValue() >> 30 & 1;
            if (zReg == 1) {
                String beqOpStr = curIns.getOpStr();
                long jmpOffAddr = Long.parseLong(beqOpStr.replace("#", "").replace("0x", ""), 16);
                Block blk = new Block();
                blk.addr = jmpOffAddr + curAddr;
                blk.idx = idx;
                if (!mRealBlocks.contains(blk)) {
                    mRealBlocks.add(blk);
                }
                System.out.printf("condDispatcher-true: %s\n", blk);
            }
        }

        if (isMatchRealBlockTailPattern(ins1, ins2, ins3)) {
            // 1. RealBlock 跳转地址，即 mMatchQueueAddr 最后一个元素（curAddr）
            long curRbJmpAddr = mMatchQueueAddr.get(mMatchQueueAddr.size() - 1);

            // 2. RealBlock 下一跳索引，解析 STUR  W[n], [idx]，获取 n 寄存器值
            String[] sturOpStr = ins2.getOpStr().split(",");
            String regN = sturOpStr[0].trim();
            int reg = UC_ARM64_REG_X0 + Integer.parseInt(regN.replace("w", ""));
            long nextRbIdx = getWReg(backend.reg_read(reg).longValue());

            // 3. 回溯查找当前 RealBlock 索引值，回溯到 b.eq，获取当前块索引值以及 entry 地址
            long curRbIdx = -1;
            long curRbEntryAddr = -1;
            for (int i = mMatchQueueIns.size() - 3; i >= 0; i--) { // 从 ins1 开始向上查找
                Instruction ins = mMatchQueueIns.get(i);
                if (!"b.eq".equals(ins.getMnemonic().toLowerCase(Locale.ROOT))) continue;

                Regs regs = mMatchQueueRegs.get(i);
                curRbIdx = getWReg(regs.getRegV(UC_ARM64_REG_X9)); // 索引值
                curRbEntryAddr = mMatchQueueAddr.get(i + 1); // entry 地址
                break;
            }

            // 4. 保存真实块，如果前驱中保存过真实块，则进行更新
            Block blk = new Block();
            blk.idx = curRbIdx;
            blk.nextIdx = nextRbIdx;
            blk.addr = curRbEntryAddr;
            blk.jmpAddr = curRbJmpAddr;
            System.out.printf("realBlock：%s\n", blk);
            int index = mRealBlocks.indexOf(blk);
            if (index == -1) mRealBlocks.add(blk);
            else mRealBlocks.set(index, blk);
        }
    }

    List<JmpPatch> extractJmpPatches(List<Block> realBlocks, Block firstBlock) {
        final List<JmpPatch> jmpPatches = new ArrayList<>();
        List<Block> rbs = new ArrayList<>(realBlocks);

        Block curBlk = firstBlock;
        while (!rbs.isEmpty()) {
            JmpPatch jp = new JmpPatch();
            jp.addr = curBlk.jmpAddr;
            boolean found = false;
            for (Block b : rbs) {
                if (curBlk.nextIdx == b.idx) {
                    found = true;
                    jp.jmpAddr = b.addr;
                    jmpPatches.add(jp);
                    curBlk = b;
                    rbs.remove(b);
                }
                rbs.remove(b);
                break;
            }

            if (!found) {
                System.out.println("中断，无法提取所有 JmpPatch");
                break;
            }
        }
        return jmpPatches;
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

    /**
     * 匹配真实块尾部，模式如下
     * CSEL    W9, regN, regN, COND
     * STUR    W9, [idx]
     * B       ind_jmp_blk ;; 即间接跳转块地址
     */
    boolean isMatchRealBlockTailPattern(Instruction ins1, Instruction ins2, Instruction ins3) {
        if (!"csel".equals(ins1.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        if (!"stur".equals(ins2.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        return "b".equals(ins3.getMnemonic().toLowerCase(Locale.ROOT));
    }

    /**
     * 匹配真实块前驱，模式如下
     * SUBS            W[x], W[y], W[z]
     * STR             W[x], [stack]
     * B.EQ            loc_XXXX
     * B               loc_YYYY ; 此处可能无法走到，所以只匹配前三条即可
     */
    boolean isMatchRbPrevPatter(Instruction ins1, Instruction ins2, Instruction ins3) {
        if (!"b.eq".equals(ins3.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        if (!"str".equals(ins2.getMnemonic().toLowerCase(Locale.ROOT))) return false;
        return "subs".equals(ins1.getMnemonic().toLowerCase(Locale.ROOT));
    }
}
