package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	numWorkers        = 4
	encryptionKeySize = 32
)

var encryptionKey = [encryptionKeySize]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: GoZip <compress|decompress> <gozipfile> <path1> <path2> ...")
		return
	}

	command := os.Args[1]
	gozipFileName := os.Args[2]
	paths := os.Args[3:]

	switch command {
	case "compress":
		err := createGoZip(gozipFileName, paths)
		if err != nil {
			fmt.Println("Error creating gozip file:", err)
		} else {
			fmt.Println("Successfully created", gozipFileName)
		}
	case "decompress":
		outputDir := "."
		if len(paths) > 0 {
			outputDir = paths[0]
		}
		err := extractGoZip(gozipFileName, outputDir)
		if err != nil {
			fmt.Println("Error extracting gozip file:", err)
		} else {
			fmt.Println("Successfully extracted", gozipFileName)
		}
	default:
		fmt.Println("Unknown command. Use 'compress' or 'decompress'")
	}
}

func createGoZip(gozipFileName string, paths []string) error {
	gozipFile, err := os.Create(gozipFileName)
	if err != nil {
		return err
	}
	defer gozipFile.Close()

	zstdWriter, err := zstd.NewWriter(gozipFile)
	if err != nil {
		return err
	}
	defer zstdWriter.Close()

	fileChannel := make(chan string, len(paths))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChannel {
				err := addPathToGoZip(zstdWriter, path)
				if err != nil {
					fmt.Println("Error adding path:", err)
				}
			}
		}()
	}

	for _, path := range paths {
		fileChannel <- path
	}
	close(fileChannel)
	wg.Wait()
	return nil
}

func addPathToGoZip(zstdWriter io.Writer, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return addDirectoryToGoZip(zstdWriter, path)
	}

	return addFileToGoZip(zstdWriter, path)
}

func addDirectoryToGoZip(zstdWriter io.Writer, dirPath string) error {
	return filepath.WalkDir(dirPath, func(filePath string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		return addFileToGoZip(zstdWriter, filePath)
	})
}

func addFileToGoZip(zstdWriter io.Writer, filePath string) error {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var compressedData bytes.Buffer
	zstdCompressor, err := zstd.NewWriter(&compressedData, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return err
	}
	_, err = zstdCompressor.Write(fileData)
	if err != nil {
		return err
	}
	zstdCompressor.Close()

	encryptedData, err := encrypt(compressedData.Bytes())
	if err != nil {
		return err
	}

	_, err = zstdWriter.Write([]byte(fmt.Sprintf("%s\n", filepath.Base(filePath))))
	if err != nil {
		return err
	}

	_, err = zstdWriter.Write([]byte(fmt.Sprintf("%d\n", len(encryptedData))))
	if err != nil {
		return err
	}

	_, err = zstdWriter.Write(encryptedData)
	return err
}

func extractGoZip(gozipFileName string, outputDir string) error {
	gozipFile, err := os.Open(gozipFileName)
	if err != nil {
		return err
	}
	defer gozipFile.Close()

	zstdReader, err := zstd.NewReader(gozipFile)
	if err != nil {
		return err
	}
	defer zstdReader.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex

	for {
		fileName, err := readLine(zstdReader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("Error reading file name: %v", err)
		}

		contentSizeStr, err := readLine(zstdReader)
		if err == io.EOF {
			return fmt.Errorf("Unexpected EOF while reading file size for file %s", fileName)
		}
		if err != nil {
			return fmt.Errorf("Error reading file size for file %s: %v", fileName, err)
		}

		contentSize, err := strconv.Atoi(contentSizeStr)
		if err != nil {
			return fmt.Errorf("Error converting file size for file %s: %v", fileName, err)
		}

		encryptedData := make([]byte, contentSize)
		_, err = io.ReadFull(zstdReader, encryptedData)
		if err == io.EOF {
			return fmt.Errorf("Unexpected EOF while reading encrypted data for file %s", fileName)
		}
		if err != nil {
			return fmt.Errorf("Error reading encrypted data: %v", err)
		}

		decryptedData, err := decrypt(encryptedData)
		if err != nil {
			return fmt.Errorf("Error decrypting file %s: %v", fileName, err)
		}

		var decompressedData bytes.Buffer
		zstdDecompressor, err := zstd.NewReader(bytes.NewReader(decryptedData))
		if err != nil {
			return fmt.Errorf("Error decompressing file %s: %v", fileName, err)
		}
		_, err = io.Copy(&decompressedData, zstdDecompressor)
		zstdDecompressor.Close()
		if err != nil {
			return fmt.Errorf("Error decompressing data: %v", err)
		}

		wg.Add(1)
		go func(fileName string, data []byte) {
			defer wg.Done()
			mu.Lock()
			defer mu.Unlock()

			fileNamePath := filepath.Join(outputDir, fileName)

			if err := os.WriteFile(fileNamePath, data, 0644); err != nil {
				fmt.Println("Error creating file:", err)
			}
		}(fileName, decompressedData.Bytes())
	}

	wg.Wait()
	return nil
}

func readLine(r io.Reader) (string, error) {
	buffer := make([]byte, 0, 256)
	tmp := make([]byte, 1)
	for {
		n, err := r.Read(tmp)
		if err != nil {
			if err == io.EOF && len(buffer) > 0 {
				return string(buffer), nil
			}
			return "", err
		}
		if n > 0 {
			if tmp[0] == '\n' {
				break
			}
			buffer = append(buffer, tmp[0])
		}
	}
	return string(buffer), nil
}

func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey[:])
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey[:])
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}
