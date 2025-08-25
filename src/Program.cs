using System.Text.Json;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.ComponentModel.DataAnnotations;
using System.Buffers.Binary;

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

const int CHUNK_SIZE = 1024 * 16;

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

    string info_hash_hex = Convert.ToHexStringLower(get_info_hash_bytes(text));
    Console.WriteLine($"Info Hash: {info_hash_hex}");

    var pieces_str = info!["pieces"] as string;
    Console.WriteLine($"Piece Hashes: {Convert.ToHexStringLower(Encoding.Latin1.GetBytes(pieces_str!))}");
}
else if (command == "peers")
{
    string file = param;
    string text = File.ReadAllText(file, Encoding.Latin1);
    var decoded = Decode(text, out _) as Dictionary<object, object>;
    var tracker_url = (string)decoded!["announce"];
    byte[] info_hash_bytes = get_info_hash_bytes(text);

    foreach (var (ip, port) in await get_peers(tracker_url, info_hash_bytes))
    {
        Console.WriteLine($"{ip}:{port}");
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

    await handshake(peer_ip, port, info_hash);
}
else if (command == "download_piece")
{
    var (_, op, out_file, torrent_file, piece_index) = args.Length switch
    {
        _ => (args[0], args[1], args[2], args[3], Convert.ToInt32(args[4]))
    };

    string torrent_data = File.ReadAllText(torrent_file, Encoding.Latin1);
    var decoded = Decode(torrent_data, out _) as Dictionary<object, object>;
    var tracker_url = (string)decoded!["announce"];
    byte[] info_hash_bytes = get_info_hash_bytes(torrent_data);

    var info = (Dictionary<object, object>)decoded!["info"];

    int standard_piece_len = (int)(long)info["piece length"];
    int total_size = (int)(long)info["length"];
    int piece_count = total_size / standard_piece_len;
    int used_len = piece_count * standard_piece_len;
    int piece_size = (piece_index < piece_count) ? standard_piece_len : (total_size > used_len ? total_size - used_len : 0);


    var peers = await get_peers(tracker_url, info_hash_bytes, total_size);
    var (ip, port) = peers[0];
    using var stream = await handshake(ip, port, info_hash_bytes);

    byte[] piece_buffer = new byte[piece_size];
    await download_piece(piece_buffer, stream, piece_size, piece_index);
    File.WriteAllBytes(out_file, piece_buffer);
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

async Task<NetworkStream> handshake(string ip, int port, byte[] info_hash)
{
    TcpClient client = new();
    client.Connect(ip, port);
    Console.Error.WriteLine("Connetted to server");

    NetworkStream stream = client.GetStream();
    byte[] handshake_buf = new byte[68];
    handshake_buf[0] = 19;
    Array.Copy(Encoding.Latin1.GetBytes("BitTorrent protocol"), 0, handshake_buf, 1, 19);

    Array.Copy(info_hash, 0, handshake_buf, 28, 20);
    Array.Copy(Encoding.Latin1.GetBytes("THIS_IS_SPARTA_JKl0l"), 0, handshake_buf, 48, 20);

    await stream.WriteAsync(handshake_buf);
    byte[] resp_buf = new byte[68];
    int read_bytes = await stream.ReadAsync(resp_buf);
    byte[] rec_info_hash = resp_buf[28..48];
    if (read_bytes == 68 && rec_info_hash.SequenceEqual(info_hash))
    {
        var peer_id = Convert.ToHexStringLower(resp_buf[48..68]);
        Console.WriteLine($"Peer ID: {peer_id}");
    }
    return stream;
}

byte[] get_info_hash_bytes(string torrent_data)
{
    int info_idx = torrent_data.IndexOf("4:info") + "4:info".Length; // TODO: Properly Encode info Dictionary
    string info_str = torrent_data[info_idx..(torrent_data.Length - 1)];
    byte[] info_hash_bytes = SHA1.HashData(Encoding.Latin1.GetBytes(info_str));
    return info_hash_bytes;
}

async Task<List<(string, int)>> get_peers(string tracker_url, byte[] info_hash_bytes, int length = 1)
{
    string info_hash_hex = Convert.ToHexString(info_hash_bytes);
    string info_hash_url_encoded = string.Join("", info_hash_hex.Chunk(2).Select(chars => $"%{new string(chars)}"));

    string url = $"{tracker_url}?port=6881&left={length}&downloaded=0&uploaded=0&compact=1&peer_id=THIS_IS_SPARTA_JKl0l&info_hash={info_hash_url_encoded}";
    using HttpClient client = new();
    HttpResponseMessage response = await client.GetAsync(url);
    byte[] response_bin = await response.Content.ReadAsByteArrayAsync();
    string response_text = Encoding.Latin1.GetString(response_bin);
    var decoded_resp = Decode(response_text, out _) as Dictionary<object, object>;
    var peers_str = decoded_resp!["peers"] as string;

    List<(string, int)> res = [];
    byte[] peers_bin = Encoding.Latin1.GetBytes(peers_str!);
    for (int i = 0; i < peers_bin.Length; i += 6)
    {
        res.Add((new IPAddress(peers_bin[i..(i + 4)]).ToString(), (peers_bin[i + 4] << 8) | peers_bin[i + 5]));
    }
    return res;
}


    
static void hexdump(byte[] data)
{
    int size = data.Length;
    if (data == null)
        throw new ArgumentNullException(nameof(data));
    if (size < 0 || size > data.Length)
        throw new ArgumentOutOfRangeException(nameof(size));

    var buffer = new StringBuilder(4096);
    
    for (int i = 0; i < size; i += 16)
    {
        var line = new StringBuilder(80);
        
        // Address part
        line.AppendFormat("{0:x8}  ", i);
        
        // Hex part
        for (int j = 0; j < 16; j++)
        {
            if (i + j < size)
                line.AppendFormat("{0:x2} ", data[i + j]);
            else
                line.Append("   ");
                
            if (j == 7)
                line.Append(" ");
        }
        
        // ASCII part
        line.Append(" |");
        for (int j = 0; j < 16 && i + j < size; j++)
        {
            byte ch = data[i + j];
            line.Append((ch >= 32 && ch <= 126) ? (char)ch : '.');
        }
        line.Append("|\n");
        
        // Append line to buffer
        if (buffer.Length + line.Length < 4096)
        {
            buffer.Append(line);
        }
        else
        {
            // Prevent buffer overflow
            break;
        }
    }
    
    // Print the complete output
    Console.Error.Write(
        "Idx       | Hex                                             | ASCII\n" +
        "----------+-------------------------------------------------+-----------------\n" +
        buffer.ToString());
}
  
async Task download_piece(byte[] piece_buffer, NetworkStream stream, int piece_size, int piece_index) 
{
    // Phase 1: Handle bitfield messages
    byte[] len_buf = new byte[4];
    await stream.ReadExactlyAsync(len_buf.AsMemory(0, 4));
    int message_len = len_buf[0] << 24 | len_buf[1] << 16 | len_buf[2] << 8 | len_buf[3];

    byte[] resp_buf = new byte[message_len];
    await stream.ReadExactlyAsync(resp_buf, 0, message_len);

    if (resp_buf[0] == (byte)Message.Bitfield)
    {
        byte[] req = { 0, 0, 0, 1, (byte)Message.Interested };
        stream.Write(req.AsSpan(0, 5));
    }

    // Phase 2: Handle unchoke and send requests
    int chunk_count = (piece_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    await stream.ReadExactlyAsync(len_buf, 0, 4);
    message_len = len_buf[0] << 24 | len_buf[1] << 16 | len_buf[2] << 8 | len_buf[3];
    resp_buf = new byte[message_len];
    await stream.ReadExactlyAsync(resp_buf, 0, message_len);

    if (resp_buf[0] == (byte)Message.Unchoke)
    {
        byte[] msg_len_network = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(13));
        byte[] piece_index_network = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(piece_index));

        for (int chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx)
        {
            byte[] begin = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(chunk_idx * CHUNK_SIZE));
            int len_le = Math.Min(CHUNK_SIZE, piece_size - chunk_idx * CHUNK_SIZE);
            byte[] len = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(len_le));

            await stream.WriteAsync(msg_len_network.AsMemory(0, 4));
            await stream.WriteAsync([(byte)Message.Request], 0, 1);
            await stream.WriteAsync(piece_index_network.AsMemory(0, 4));
            await stream.WriteAsync(begin.AsMemory(0, 4));
            await stream.WriteAsync(len.AsMemory(0, 4));
        }
    }
    // Phase 3: Download chunks
    for (int chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx)
    {
        await stream.ReadExactlyAsync(len_buf, 0, 4);
        message_len = len_buf[0] << 24 | len_buf[1] << 16 | len_buf[2] << 8 | len_buf[3];
        byte[] info_buf = new byte[9];
        await stream.ReadExactlyAsync(info_buf, 0, 9);

        int byte_offset = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(info_buf[5..9]));
        int block_len = message_len - 9;
        await stream.ReadExactlyAsync(piece_buffer, byte_offset, block_len);
    }
}

enum Message : byte
{
    Choke = 0x0,
    Unchoke,
    Interested,
    NotInterested,
    Have,
    Bitfield,
    Request,
    Piece,
    Cancel,
};