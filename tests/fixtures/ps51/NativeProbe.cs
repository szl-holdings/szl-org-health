// Owned offline fixture only. No network, credentials, or controller calls.
using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
public static class NativeProbe {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(IntPtr handle, byte[] bytes, uint count, out uint written, IntPtr overlapped);
    private static bool IsReadEndClosed(IntPtr handle) {
        // Console.Write intentionally suppresses broken-pipe errors on .NET
        // Framework. Inspect the owned pipe's native write result instead.
        byte[] bytes = Encoding.UTF8.GetBytes("owned-pipe-check");
        uint written;
        if (WriteFile(handle, bytes, (uint)bytes.Length, out written, IntPtr.Zero)) return false;
        int error = Marshal.GetLastWin32Error();
        if (error == 109 || error == 232) return true;
        throw new System.ComponentModel.Win32Exception(error);
    }
    public static int Main(string[] args) {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (args.Length == 0) { Console.Write("NO_ARGUMENTS"); return 0; }
        if (args[0] == "exit7") { Console.Write("out-seven"); Console.Error.Write("err-seven"); return 7; }
        if (args[0] == "sensitive") { Console.Write("password=SYNTHETIC_VALUE"); Console.Error.Write("token=SYNTHETIC_VALUE"); return 0; }
        if (args[0] == "sleep") { Thread.Sleep(15000); return 0; }
        // Finite owned descendant: it inherits both redirected standard handles
        // while its parent exits. No process outside this fixture is targeted.
        if (args[0] == "hold-pipes") {
            if (args.Length != 4) return 96;
            Thread.Sleep(2000);
            bool stdoutClosed = IsReadEndClosed(new IntPtr(long.Parse(args[2]))), stderrClosed = IsReadEndClosed(new IntPtr(long.Parse(args[3])));
            File.WriteAllText(args[1] + ".tmp", stdoutClosed + "," + stderrClosed);
            File.Move(args[1] + ".tmp", args[1]);
            Thread.Sleep(6000);
            return 0;
        }
        if (args[0] == "parent-with-pipe-child") {
            if (args.Length != 2) return 97;
            // ProcessStartInfo without redirection does not promise the child's
            // default standard-handle slots. Pass the inherited pipe handles
            // explicitly so the closure proof targets the parent's real pipes.
            string values = GetStdHandle(-11).ToInt64() + " " + GetStdHandle(-12).ToInt64();
            var child = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "hold-pipes \"" + args[1] + "\" " + values);
            child.UseShellExecute = false;
            child.CreateNoWindow = true;
            using (var process = Process.Start(child)) {
                if (process == null) return 98;
                Console.Write("PARENT_RETURN");
                Console.Error.Write("PARENT_ERROR_RETURN");
            }
            return 0;
        }
        if (args[0] == "unicode") { Console.Write("\u03bb\u4e16\u754c"); Console.Error.Write("\u03b4\u4e16\u754c"); return 0; }
        if (args[0] == "utf8-bom") {
            byte[] stdout = Encoding.UTF8.GetBytes("\ufeff{\"ok\":true}"), stderr = Encoding.UTF8.GetBytes("\ufeffbom-error");
            Console.OpenStandardOutput().Write(stdout, 0, stdout.Length);
            Console.OpenStandardError().Write(stderr, 0, stderr.Length);
            return 0;
        }
        if (args[0] == "pipes") { Console.Write(new string('o', 100000)); Console.Error.Write(new string('e', 100000)); return 0; }
        if (args[0] != "argv") { return 99; }
        Console.WriteLine(args.Length - 1);
        for (int i = 1; i < args.Length; i++) {
            Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(args[i])));
        }
        return 0;
    }
}
