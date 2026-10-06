// Owned offline fixture only. No network, credentials, or controller calls.
using System;
using System.Text;
using System.Threading;
public static class NativeProbe {
    public static int Main(string[] args) {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (args.Length == 0) { Console.Write("NO_ARGUMENTS"); return 0; }
        if (args[0] == "exit7") { Console.Write("out-seven"); Console.Error.Write("err-seven"); return 7; }
        if (args[0] == "sleep") { Thread.Sleep(15000); return 0; }
        if (args[0] == "unicode") { Console.Write("\u03bb\u4e16\u754c"); Console.Error.Write("\u03b4\u4e16\u754c"); return 0; }
        if (args[0] == "pipes") { Console.Write(new string('o', 100000)); Console.Error.Write(new string('e', 100000)); return 0; }
        if (args[0] != "argv") { return 99; }
        Console.WriteLine(args.Length - 1);
        for (int i = 1; i < args.Length; i++) {
            Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(args[i])));
        }
        return 0;
    }
}
