using System.Text.Json;
using System.IO;
using System.Text;
using System.Security.Cryptography;

// Parse arguments
var (command, param) = args.Length switch
{
    0 => throw new InvalidOperationException("Usage: your_program.sh <command> <param>"),
    1 => throw new InvalidOperationException("Usage: your_program.sh <command> <param>"),
    _ => (args[0], args[1])
};

// You can use print statements as follows for debugging, they'll be visible when running tests.
Console.Error.WriteLine("Logs from your program will appear here!");

// Parse command and act accordingly
if (command == "decode")
{
    int offset = 0;
    var value = Decode(param, out offset);
    Console.WriteLine(JsonSerializer.Serialize(value));
}
else if (command == "info")
{
    string text = File.ReadAllText(param, Encoding.ASCII);
    int offset = 0;
    var decoded = Decode(text, out offset) as Dictionary<object, object>;
    Console.WriteLine($"Tracker URL: {decoded!["announce"]}");

    var info = decoded["info"] as Dictionary<object, object>;

    Console.WriteLine($"Length: {info!["length"]}");
    Console.WriteLine($"Piece Length: {info!["piece length"]}");

    using (SHA1 sha1 = SHA1.Create())
    {
        byte[] data = File.ReadAllBytes(param);
        int info_idx = text.IndexOf("4:info") + "4:info".Length;
        byte[] inputBytes = data[info_idx..(text.Length - 1)];
        byte[] hashBytes = sha1.ComputeHash(inputBytes);
        string info_hash = Convert.ToHexString(hashBytes).ToLower();
        Console.WriteLine($"Info Hash: {info_hash}");

        int pieces_idx = text.IndexOf("pieces200:") + "pieces200:".Length;

        byte[] pieces_bytes = data[pieces_idx..(data.Length - 2)];
        Console.WriteLine($"Piece Hashes: {Convert.ToHexString(pieces_bytes).ToLower()}");
    }
}
else
{
    throw new InvalidOperationException($"Invalid command: {command}");
}

object Decode(string encodedValue, out int offset)
{
    if (Char.IsDigit(encodedValue[0]))
    {
        // Example: "5:hello" -> "hello"
        var colonIndex = encodedValue.IndexOf(':');
        if (colonIndex != -1)
        {
            var strLength = int.Parse(encodedValue[..colonIndex]);
            var strValue = encodedValue.Substring(colonIndex + 1, strLength);
            offset = colonIndex + strValue.Length + 1;
            return strValue;

        }
        else
        {
            throw new InvalidOperationException("Invalid encoded value: " + encodedValue);
        }
    }
    else if (encodedValue[0] == 'i')
    {
        var end_idx = encodedValue.IndexOf('e');
        var num = Int64.Parse(encodedValue[1..end_idx]);
        offset = end_idx + 1;
        return num;
    }
    else if (encodedValue[0] == 'l')
    {
        int len = encodedValue.Length - 1;
        int i = 1, e = 1;
        var items = new List<object>();

        while (i < len)
        {
            var res = Decode(encodedValue[i..], out e);
            i += e;
            items.Add(res);
            if (encodedValue[i] == 'e')
                break;
        }
        offset = i + 1;
        return items;
    }
    else if (encodedValue[0] == 'd')
    {
        int len = encodedValue.Length - 1;
        int i = 1, e = 1;
        var items = new Dictionary<object, object>();

        while (i < len)
        {
            var key = Decode(encodedValue[i..], out e);
            i += e;
            var value = Decode(encodedValue[i..], out e);
            i += e;

            items[key] = value;
            if (encodedValue[i] == 'e')
                break;
        }
        offset = i + 1;
        return items;
    }
    else
    {
        throw new InvalidOperationException("Unhandled encoded value: " + encodedValue);
    }

}