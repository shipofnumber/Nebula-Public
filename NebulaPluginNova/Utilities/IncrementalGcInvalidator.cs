using System;
using System.Runtime.InteropServices;

namespace Nebula.Utilities;

internal static class IncrementalGcInvalidator
{

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern nint GetModuleHandleW(string? lpModuleName);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern nint GetProcAddress(nint hModule, string procName);

    [DllImport("GameAssembly", EntryPoint = "il2cpp_gc_is_incremental", CallingConvention = CallingConvention.Cdecl)]
    static extern bool IsIncremental();

    static unsafe nint ResolveJmpThunk(nint addr, int maxHops = 5)
    {
        for (int hop = 0; hop < maxHops; hop++)
        {
            byte* p = (byte*)addr;
            if (p[0] != 0xE9) break;
            int rel = *(int*)(p + 1);
            addr = addr + 5 + rel;
        }
        return addr;
    }

    static unsafe nint FindFirstCallTarget(nint funcAddr, int scanBytes)
    {
        byte* p = (byte*)funcAddr;
        for (int i = 0; i < scanBytes - 4; i++)
        {
            if (p[i] == 0xE8)
                return funcAddr + i + 5 + *(int*)(p + i + 1);
        }
        return 0;
    }

    static unsafe nint FindMovEaxDisp32(nint funcAddr, int scanBytes)
    {
        byte* p = (byte*)funcAddr;
        for (int i = 0; i < scanBytes - 5; i++)
        {
            if (p[i] == 0xA1)
                return (nint)(*(int*)(p + i + 1));
            if (p[i] == 0x8B && p[i + 1] == 0x05)
                return (nint)(*(int*)(p + i + 2));
        }
        return 0;
    }

    // is_incrementalフラグの実アドレスを返します
    static unsafe nint DiscoverFlagAddress()
    {
        nint hGameAssembly = GetModuleHandleW("GameAssembly.dll");
        if (hGameAssembly == 0) return 0;

        nint exportAddr = GetProcAddress(hGameAssembly, "il2cpp_gc_is_incremental");
        if (exportAddr == 0) return 0;

        nint realFunc = ResolveJmpThunk(exportAddr);

        // export解決先: mov eax,[disp32]
        nint found = FindMovEaxDisp32(realFunc, 24);
        if (found != 0) return found;

        // call先を1回辿る
        nint callTarget = FindFirstCallTarget(realFunc, 24);
        if (callTarget != 0)
        {
            callTarget = ResolveJmpThunk(callTarget);
            found = FindMovEaxDisp32(callTarget, 24);
            if (found != 0) return found;
        }
        return 0;
    }

    public static unsafe bool TryDisable()
    {
        nint flagAddr = DiscoverFlagAddress();
        if (flagAddr == 0) return false;

        bool apiSaysIncremental;
        try 
        { 
            apiSaysIncremental = IsIncremental(); 
        }
        catch (Exception ex)
        {
            return false;
        }

        int* p = (int*)flagAddr;
        int before = *p;
        bool memSaysIncremental = before != 0;

        // 指し示す値に違いがある
        if (memSaysIncremental != apiSaysIncremental) return false;

        *p = 0;
        int after = *p;
        bool validated = !IsIncremental();
        return true;
    }
}
