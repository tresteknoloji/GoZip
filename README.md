# GoZip

GoZip is a command-line utility written in Go for compressing and decompressing files using Zstandard (zstd) compression and AES encryption.

## Features
- Compression: Compresses files and directories using zstd compression algorithm.
- Encryption: Encrypts compressed data using AES encryption.
- Concurrency: Utilizes multiple goroutines for concurrent file processing.

## Installation
Clone the repository and build the executable using the following commands:

```bash
git clone https://github.com/tresteknoloji/GoZip.git
cd GoZip
go build
```

## Usage

To compress files and directories into a GoZip archive:

```bash
./GoZip compress <gozipfile> <path1> <path2> ...
```


To decompress a GoZip archive:

```bash
./GoZip decompress <gozipfile> [<output_directory>]
```
