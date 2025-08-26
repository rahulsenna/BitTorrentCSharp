using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Text.Encodings.Web;

// Parse arguments
var (command, param) = args.Length switch
{
    < 2 => throw new InvalidOperationException("Usage: your_program.sh <command> <param>"),
    _ => (args[0], args[1])
};

const int HANDSHAKE_RESPONSE_SIZE = 68;
const int INFO_HASH_OFFSET = 28;
const int INFO_HASH_LENGTH = 20;
const int PEER_ID_OFFSET = 48;
const int PEER_ID_LENGTH = 20;
const int EXTENSION_SUPPORT_FLAG_OFFSET = 25;
const byte EXTENSION_SUPPORT_FLAG = 0x10;
const byte MESSAGE_ID = 20;
const byte EXTENSION_MESSAGE_ID = 0;

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
    var (_, torrent_file, peer) = args.Length switch
    {
        < 3 => throw new InvalidOperationException($"Usage: your_program.sh {command} <torrent_file> <peer>"),
        _ => (args[0], args[1], args[2])
    };

    string torrent_data = File.ReadAllText(torrent_file, Encoding.Latin1);

    string peer_ip = peer[0..peer.IndexOf(':')];
    int port = Convert.ToInt32(peer[(peer.IndexOf(':') + 1)..]);
    byte[] info_hash = get_info_hash_bytes(torrent_data);

    await handshake(peer_ip, port, info_hash);
}
else if (command == "download_piece")
{
    var (_, op, out_file, torrent_file, piece_index) = args.Length switch
    {
        < 5 => throw new InvalidOperationException($"Usage: your_program.sh {command} -o <out_file> <torrent_file> <piece_index>"),
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

    byte[] piece_buffer = new byte[piece_size];
    await download_piece(piece_buffer, ip, port, info_hash_bytes, piece_size, piece_index);
    File.WriteAllBytes(out_file, piece_buffer);
}
else if (command == "download")
{
    var (_, op, out_file, torrent_file) = args.Length switch
    {
        < 4 => throw new InvalidOperationException($"Usage: your_program.sh {command} -o <out_file> <torrent_file>"),
        _ => (args[0], args[1], args[2], args[3])
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

    Console.WriteLine($"piece_count: {piece_count}");
    byte[] file_buffer = new byte[total_size];

    for (int piece_index = 0; piece_index <= piece_count;)
    {
        var peers = await get_peers(tracker_url, info_hash_bytes, total_size);
        List<Task> download_tasks = [];
        foreach (var (ip, port) in peers)
        {
            Console.WriteLine($"piece_index: {piece_index}");

            int offset = piece_index * standard_piece_len;
            int piece_size = (piece_index < piece_count) ? standard_piece_len : (total_size > used_len ? total_size - used_len : 0);
            download_tasks.Add(download_piece(file_buffer, ip, port, info_hash_bytes, piece_size, piece_index, offset));
            piece_index++;
            if (piece_index > piece_count)
                break;
        }
        await Task.WhenAll(download_tasks);
    }

    File.WriteAllBytes(out_file, file_buffer);
}
else if (command == "magnet_parse")
{
    string magnet_link = param;

    int pos = magnet_link.IndexOf("xt=urn:btih:") + "xt=urn:btih:".Length;
    string info_hash = magnet_link[pos..(pos + 40)];

    pos = magnet_link.IndexOf("tr=") + "tr=".Length;
    string url = magnet_link[pos..];

    Console.WriteLine($"Info Hash: {info_hash}");
    Console.WriteLine($"Tracker URL: {Uri.UnescapeDataString(url)}");
}
else if (command == "magnet_handshake")
{
    string magnet_link = param;

    int pos = magnet_link.IndexOf("xt=urn:btih:") + "xt=urn:btih:".Length;
    byte[] info_hash_bytes = Convert.FromHexString(magnet_link[pos..(pos + 40)]);

    pos = magnet_link.IndexOf("tr=") + "tr=".Length;
    string tracker_url = magnet_link[pos..];

    var peers = await get_peers(Uri.UnescapeDataString(tracker_url), info_hash_bytes);
    var (ip, port) = peers[0];
    await handshake(ip, port, info_hash_bytes, true);
}
else if (command == "magnet_info")
{
    string magnet_link = param;

    int pos = magnet_link.IndexOf("xt=urn:btih:") + "xt=urn:btih:".Length;
    string info_hash = magnet_link[pos..(pos + 40)];
    byte[] info_hash_bytes = Convert.FromHexString(info_hash);

    pos = magnet_link.IndexOf("tr=") + "tr=".Length;
    string tracker_url = magnet_link[pos..];

    Console.WriteLine($"Info Hash: {info_hash}");
    Console.WriteLine($"Tracker URL: {Uri.UnescapeDataString(tracker_url)}");

    var peers = await get_peers(Uri.UnescapeDataString(tracker_url), info_hash_bytes);
    var (ip, port) = peers[0];
    PeerInfo peer = await handshake(ip, port, info_hash_bytes, true);

    var metadata = await get_magnet_metadata(peer) as Dictionary<object, object>;

    int length = (int)(long)metadata!["length"];
    int piece_length = (int)(long)metadata!["piece length"];
    Console.WriteLine($"Length: {length}");
    Console.WriteLine($"Piece Length: {piece_length}");

    string pieces_hashes = Convert.ToHexStringLower(Encoding.Latin1.GetBytes((string)metadata!["pieces"]));
    Console.WriteLine(string.Join('\n', Enumerable.Range(0, pieces_hashes.Length / 40).Select(i => pieces_hashes.Substring(i * 40, 40))));
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


async Task<PeerInfo> handshake(string ip, int port, byte[] info_hash, bool extension = false)
{
    TcpClient client = new();
    client.Connect(ip, port);

    NetworkStream stream = client.GetStream();
    PeerInfo peer = new(stream);

    byte[] handshake_buf = new byte[HANDSHAKE_RESPONSE_SIZE];
    handshake_buf[0] = 19;
    Array.Copy(Encoding.Latin1.GetBytes("BitTorrent protocol"), 0, handshake_buf, 1, 19);

    Array.Copy(info_hash, 0, handshake_buf, INFO_HASH_OFFSET, INFO_HASH_LENGTH);
    Array.Copy(Encoding.Latin1.GetBytes("THIS_IS_SPARTA_JKl0l"), 0, handshake_buf, PEER_ID_OFFSET, PEER_ID_LENGTH);

    if (extension)
        handshake_buf[EXTENSION_SUPPORT_FLAG_OFFSET] = EXTENSION_SUPPORT_FLAG;

    await stream.WriteAsync(handshake_buf);
    byte[] resp_buf = new byte[HANDSHAKE_RESPONSE_SIZE];
    await stream.ReadExactlyAsync(resp_buf, 0, HANDSHAKE_RESPONSE_SIZE);
    byte[] rec_info_hash = resp_buf[INFO_HASH_OFFSET..PEER_ID_OFFSET];
    if (rec_info_hash.SequenceEqual(info_hash))
    {
        var peer_id = Convert.ToHexStringLower(resp_buf[PEER_ID_OFFSET..HANDSHAKE_RESPONSE_SIZE]);
        Console.WriteLine($"Peer ID: {peer_id}");
        if (resp_buf[EXTENSION_SUPPORT_FLAG_OFFSET] == EXTENSION_SUPPORT_FLAG)
        {
            Console.Error.WriteLine("---------[ Extension Supported ]---------");
            byte[] meta_data_req = Encoding.Latin1.GetBytes("d1:md11:ut_metadatai1e6:ut_pexi2ee1:pi6881ee");
            int len = meta_data_req.Length + /* message id */ 1 + /* ext message id */ 1;
            byte[] len_data = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(len));

            await stream.WriteAsync(len_data);
            byte[] msg_id = { MESSAGE_ID, EXTENSION_MESSAGE_ID };
            await stream.WriteAsync(msg_id);
            await stream.WriteAsync(meta_data_req);

            //--[ BitField]--------------------
            byte[] len_buf = new byte[4];
            await stream.ReadExactlyAsync(len_buf, 0, 4);
            int message_len = len_buf[0] << 24 | len_buf[1] << 16 | len_buf[2] << 8 | len_buf[3];


            byte[] bitfield_buf = new byte[message_len];
            await stream.ReadExactlyAsync(bitfield_buf, 0, message_len);

            //--[ Receive Extension Handshake ]--------------------
            await stream.ReadExactlyAsync(len_buf, 0, 4);
            message_len = len_buf[0] << 24 | len_buf[1] << 16 | len_buf[2] << 8 | len_buf[3];

            await stream.ReadExactlyAsync(resp_buf, 0, 2); // Message ID and Ext Message ID
            message_len -= 2;

            byte[] meta_data_buf = new byte[message_len];
            await stream.ReadExactlyAsync(meta_data_buf, 0, message_len);

            string meta_data_str = Encoding.Latin1.GetString(meta_data_buf);
            var meta_data_obj = Decode(meta_data_str, out _) as Dictionary<object, object>;

            var m = meta_data_obj!["m"] as Dictionary<object, object>;
            int ut_metadata = (int)(long)m!["ut_metadata"];
            Console.WriteLine($"Peer Metadata Extension ID: {ut_metadata}");
            peer.ut_metadata = ut_metadata;
            peer.extension = true;
        }
    }
    return peer;
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
  
async Task download_piece(byte[] piece_buffer, string ip, int port, byte[] info_hash_bytes, int piece_size, int piece_index, int buffer_offset = 0)
{
    PeerInfo peer = await handshake(ip, port, info_hash_bytes);
    using var stream = peer.stream;
    // Phase 1: Handle bitfield messages
    byte[] len_buf = new byte[4];
    await stream.ReadExactlyAsync(len_buf.AsMemory(0, 4));
    int message_len = len_buf[0] << 24 | len_buf[1] << 16 | len_buf[2] << 8 | len_buf[3];

    byte[] resp_buf = new byte[message_len];
    await stream.ReadExactlyAsync(resp_buf, 0, message_len);

    if (resp_buf[0] == (byte)Message.Bitfield)
    {
        byte[] req = { 0, 0, 0, 1, (byte)Message.Interested };
        await stream.WriteAsync(req.AsMemory(0, 5));
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
        await stream.ReadExactlyAsync(piece_buffer, buffer_offset + byte_offset, block_len);
    }
}

async Task<object> get_magnet_metadata(PeerInfo peer)
{
    byte[] payload = Encoding.Latin1.GetBytes("d8:msg_typei0e5:piecei0ee");
    byte[] len_data = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(payload.Length + 2));
    await peer.stream.WriteAsync(len_data);
    byte[] msg_data = { (byte)MESSAGE_ID, (byte)peer.ut_metadata };
    await peer.stream.WriteAsync(msg_data);
    await peer.stream.WriteAsync(payload);

    await peer.stream.ReadExactlyAsync(len_data, 0, 4);
    int message_len = len_data[0] << 24 | len_data[1] << 16 | len_data[2] << 8 | len_data[3];

    byte[] resp_buf = new byte[message_len];
    await peer.stream.ReadExactlyAsync(msg_data, 0, 2); // Message ID and Ext Message ID
    await peer.stream.ReadExactlyAsync(resp_buf, 0, message_len-2);

    string metadata_str = Encoding.Latin1.GetString(resp_buf);
    Decode(metadata_str, out int offset);
    return Decode(metadata_str[offset..], out _);
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

struct PeerInfo(NetworkStream stream, byte ut_metadata = 0, bool extension = false)
{
    public NetworkStream stream = stream;
    public int ut_metadata = ut_metadata;
    public bool extension = extension;
};