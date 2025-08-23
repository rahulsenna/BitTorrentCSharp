using System.Text.Json;

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