using System.Text.Json;
using Tuf;

if (args.Length == 0)
{
    return 1;
}

switch (args[0])
{
    case "write-loop":
        {
            var cache = new FileSystemTufCache(args[1]);
            var key = args[2];
            var first = Enumerable.Repeat(Convert.ToByte(args[3], 16), int.Parse(args[5])).ToArray();
            var second = Enumerable.Repeat(Convert.ToByte(args[4], 16), int.Parse(args[5])).ToArray();
            var iterations = int.Parse(args[6]);

            for (var i = 0; i < iterations; i++)
            {
                cache.StoreTarget(key, i % 2 == 0 ? first : second);
                Thread.Sleep(1);
            }

            return 0;
        }
    case "write-metadata":
        {
            var cache = new FileSystemTufCache(args[1]);
            var role = args[2];
            var version = int.Parse(args[3]);
            var metadata = JsonSerializer.SerializeToUtf8Bytes(new
            {
                signed = new { version }
            });
            cache.StoreMetadata(role, metadata);
            return 0;
        }
    case "hold-lock":
        {
            var cachePath = args[1];
            var readyPath = args[2];
            var releasePath = args[3];
            _ = new FileSystemTufCache(cachePath);

            var lockOptions = new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None
            };
            if (!OperatingSystem.IsWindows())
            {
                lockOptions.UnixCreateMode =
                    UnixFileMode.UserRead |
                    UnixFileMode.UserWrite;
            }
            using var cacheLock = new FileStream(
                Path.Combine(cachePath, ".lock"),
                lockOptions);
            File.WriteAllText(readyPath, "ready");

            while (!File.Exists(releasePath))
            {
                Thread.Sleep(10);
            }

            return 0;
        }
    default:
        return 2;
}
