using System.Text.Json;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;

// Parse arguments
var (command, param, param2) = args.Length switch
{
    0 => throw new InvalidOperationException("Usage: your_program.sh <command> <param>"),
    1 => throw new InvalidOperationException("Usage: your_program.sh <command> <param>"),
    2 => (args[0], args[1], null),
    _ => (args[0], args[1], args[2])
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
    string file = param;
    string text = File.ReadAllText(file, Encoding.Latin1);
    var decoded = Decode(text, out _) as Dictionary<object, object>;
    Console.WriteLine($"Tracker URL: {decoded!["announce"]}");

    var info = decoded["info"] as Dictionary<object, object>;

    Console.WriteLine($"Length: {info!["length"]}");
    Console.WriteLine($"Piece Length: {info!["piece length"]}");

    string info_hash_hex = Convert.ToHexString(get_info_hash_bytes(text)).ToLower();
    Console.WriteLine($"Info Hash: {info_hash_hex}");

    var pieces_str = info!["pieces"] as string;
    Console.WriteLine($"Piece Hashes: {Convert.ToHexString(Encoding.Latin1.GetBytes(pieces_str!)).ToLower()}");
}
else if (command == "peers")
{
    string file = param;
    string text = File.ReadAllText(file, Encoding.Latin1);
    var decoded = Decode(text, out _) as Dictionary<object, object>;
    var tracker_url = decoded!["announce"] as string;

    string info_hash_hex = Convert.ToHexString(get_info_hash_bytes(text));
    string info_hash_url_encoded = string.Join("", info_hash_hex.Chunk(2).Select(chars => $"%{new string(chars)}"));

    var info = decoded["info"] as Dictionary<object, object>;
    Int64 length = (Int64)info!["length"];

    string url = $"{tracker_url}?port=6881&left={length}&downloaded=0&uploaded=0&compact=1&peer_id=THIS_IS_SPARTA_JKl0l&info_hash={info_hash_url_encoded}";
    using HttpClient client = new();
    HttpResponseMessage response = await client.GetAsync(url);
    byte[] response_bin = await response.Content.ReadAsByteArrayAsync();
    string response_text = Encoding.Latin1.GetString(response_bin);
    var decoded_resp = Decode(response_text, out _) as Dictionary<object, object>;
    var peers_str = decoded_resp!["peers"] as string;
    byte[] peers_bin = Encoding.Latin1.GetBytes(peers_str!);

    for (int i = 0; i < peers_bin.Length; i += 6)
    {
        string ip_port = $"{new IPAddress(peers_bin[i..(i+4)])}:{(peers_bin[i+4] << 8) | peers_bin[i+5]}";
        Console.WriteLine(ip_port);
    }
}
else if (command == "handshake")
{
    string torrent_file = param;
    string torrent_data = File.ReadAllText(torrent_file, Encoding.Latin1);
    string peer = param2!;
    
    string peer_ip = peer[0..peer.IndexOf(':')];
    int port = Convert.ToInt32(peer[(peer.IndexOf(':') + 1)..]);
    byte[] info_hash = get_info_hash_bytes(torrent_data);

    handshake(peer_ip, port, info_hash);
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

TcpClient handshake(string ip, int port, byte[] info_hash)
{
    TcpClient client = new();
    client.Connect(ip, port);
    Console.Error.WriteLine("Connetted to server");

    using NetworkStream stream = client.GetStream();
    byte[] handshake_buf = new byte[68];
    handshake_buf[0] = 19;
    Array.Copy(Encoding.Latin1.GetBytes("BitTorrent protocol"), 0, handshake_buf, 1, 19);

    Array.Copy(info_hash, 0, handshake_buf, 28, 20);
    Array.Copy(Encoding.Latin1.GetBytes("THIS_IS_SPARTA_JKl0l"), 0, handshake_buf, 48, 20);

    stream.Write(handshake_buf);
    byte[] resp_buf = new byte[68];
    int read_bytes = stream.Read(resp_buf);
    byte[] rec_info_hash = resp_buf[28..48];
    if (read_bytes == 68 && rec_info_hash.SequenceEqual(info_hash))
    {
        var peer_id = Convert.ToHexString(resp_buf[48..68]).ToLower();
        Console.WriteLine($"Peer ID: {peer_id}");
    }
    return client;
}

byte[] get_info_hash_bytes(string torrent_data)
{
    using SHA1 sha1 = SHA1.Create();
    int info_idx = torrent_data.IndexOf("4:info") + "4:info".Length; // TODO: Properly Encode info Dictionary
    string info_str = torrent_data[info_idx..(torrent_data.Length - 1)];
    byte[] info_hash_bytes = sha1.ComputeHash(Encoding.Latin1.GetBytes(info_str));
    return info_hash_bytes;
}