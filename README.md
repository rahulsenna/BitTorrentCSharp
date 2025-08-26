# BitTorrent Client in C#

A fully-featured BitTorrent client implementation in C# that supports both traditional .torrent files and magnet links.

## Features

- **Bencode Decoding**: Parse and decode bencoded data from torrent files
- **Torrent File Analysis**: Extract metadata including tracker URLs, piece hashes, and file information
- **Peer Discovery**: Connect to BitTorrent trackers to discover peers
- **BitTorrent Protocol**: Full implementation of the BitTorrent peer protocol with handshaking
- **Piece-based Downloads**: Download files in pieces with integrity verification
- **Parallel Downloads**: Concurrent downloading from multiple peers for improved performance
- **Magnet Link Support**: Parse and download from magnet links using metadata extension
- **Extension Protocol**: Support for BitTorrent Extension Protocol (BEP 10) for magnet links

## Usage

### Decode Bencoded Data
```bash
./your_program.sh decode "5:hello"
```

### Get Torrent Information
```bash
./your_program.sh info sample.torrent
```

### List Peers
```bash
./your_program.sh peers sample.torrent
```

### Perform Handshake with Peer
```bash
./your_program.sh handshake sample.torrent 127.0.0.1:6881
```

### Download Single Piece
```bash
./your_program.sh download_piece -o piece_output sample.torrent 0
```

### Download Complete File
```bash
./your_program.sh download -o complete_file sample.torrent
```

### Magnet Link Operations
```bash
# Parse magnet link
./your_program.sh magnet_parse "magnet:?xt=urn:btih:..."

# Handshake via magnet link
./your_program.sh magnet_handshake "magnet:?xt=urn:btih:..."

# Get metadata from magnet link
./your_program.sh magnet_info "magnet:?xt=urn:btih:..."

# Download piece via magnet link
./your_program.sh magnet_download_piece -o piece_output "magnet:?xt=urn:btih:..." 0

# Download complete file via magnet link
./your_program.sh magnet_download -o complete_file "magnet:?xt=urn:btih:..."
```

## Project Structure

```
├── CodeCrafters.Bittorrent.csproj    # Project file
├── CodeCrafters.Bittorrent.sln       # Solution file
├── codecrafters.yml                   # CodeCrafters configuration
├── Properties/
│   └── launchSettings.json          # Launch settings
├── README.md                         # This file
├── sample.torrent                    # Sample torrent file for testing
├── src/
│   └── Program.cs                    # Main implementation
└── your_program.sh                   # Entry point script
```

## Implementation Details

### Core Components

- **Bencode Parser**: Custom implementation for parsing BitTorrent's bencoded format
- **SHA-1 Hashing**: Info hash calculation for torrent identification
- **TCP Networking**: Direct peer-to-peer communication using TCP sockets
- **HTTP Tracker Communication**: RESTful communication with BitTorrent trackers
- **Piece Management**: Chunked downloading with configurable piece sizes (16KB chunks)

### Protocol Support

- **BitTorrent Protocol v1.0**: Complete handshake and message protocol implementation
- **Extension Protocol (BEP 10)**: Support for protocol extensions including metadata exchange
- **Magnet Links**: Full magnet URI parsing and metadata resolution via `ut_metadata` extension

### Performance Features

- **Concurrent Downloads**: Multi-peer downloading for improved throughput
- **Pipelining**: Request pipelining for efficient piece downloading
- **Memory Efficient**: Streaming downloads with controlled buffer sizes

## Requirements

- .NET 9.0 or later
- Network connectivity for tracker and peer communication

## Building and Running

1. Ensure you have .NET 9.0 installed
2. Run the application using the provided shell script:
   ```bash
   ./your_program.sh <command> <parameters>
   ```

## Development

This project was developed as part of the CodeCrafters "Build Your Own BitTorrent" challenge, implementing the complete BitTorrent protocol from scratch in C#.

### Key Technical Achievements

- **Zero External Dependencies**: Pure C# implementation using only standard libraries
- **Protocol Compliance**: Full adherence to BitTorrent Protocol specifications
- **Extension Support**: Modern BitTorrent features like magnet links and metadata exchange
- **Error Handling**: Robust error handling for network failures and protocol violations
- **Performance**: Optimized for both speed and memory efficiency

## License

This project is part of the CodeCrafters challenge and is intended for educational purposes.

Sources
[1] GitHub - rahulsenna/BitTorrentCSharp https://github.com/rahulsenna/BitTorrentCSharp
