package socket

import (
	"encoding/binary"
	"hash/fnv"
	"math/rand"
	"sync"
)

const NonceSize = 2 // 2 bytes for uint16 nonce

// Buffer pool for reducing allocations
var bufferPool = sync.Pool{
	New: func() interface{} {
		// Allocate 2KB buffers (enough for MTU + overhead)
		buf := make([]byte, 2048)
		return &buf
	},
}

// Obfuscator handles dynamic packet obfuscation using FNV-1a key derivation
type Obfuscator struct {
	masterKey []byte
	enabled   bool
}

// NewObfuscator creates a new obfuscator with the given master key
func NewObfuscator(key string) *Obfuscator {
	if key == "" {
		return &Obfuscator{enabled: false}
	}
	return &Obfuscator{
		masterKey: []byte(key),
		enabled:   true,
	}
}

// generateNonce generates a random 2-byte nonce
func (o *Obfuscator) generateNonce() uint16 {
	return uint16(rand.Uint32())
}

// derivePacketKey derives a unique packet key from master key and nonce using FNV-1a
func (o *Obfuscator) derivePacketKey(nonce uint16) []byte {
	h := fnv.New64a()
	
	// Write master key
	h.Write(o.masterKey)
	
	// Write nonce (BigEndian)
	nonceBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(nonceBuf, nonce)
	h.Write(nonceBuf)
	
	// Get 64-bit hash
	hashValue := h.Sum64()
	
	// Convert hash to byte array for XOR operations
	keyStream := make([]byte, 8)
	binary.BigEndian.PutUint64(keyStream, hashValue)
	
	return keyStream
}

// xorData applies XOR operation with the packet key
func (o *Obfuscator) xorData(data []byte, packetKey []byte) {
	keyLen := len(packetKey)
	for i := 0; i < len(data); i++ {
		data[i] ^= packetKey[i%keyLen]
	}
}

// Obfuscate takes raw KCP packet and returns obfuscated packet with nonce and random padding
// Format: [Nonce (2 bytes)] + [Data Length (2 bytes)] + [Obfuscated Data] + [Random Padding]
func (o *Obfuscator) Obfuscate(rawData []byte) []byte {
	if !o.enabled || len(rawData) == 0 {
		return rawData
	}

	// Generate random nonce
	nonce := o.generateNonce()

	// Derive packet-specific key
	packetKey := o.derivePacketKey(nonce)

	// Calculate random padding (0-31 bytes)
	paddingSize := rand.Intn(32)
	dataLen := uint16(len(rawData))
	totalSize := NonceSize + 2 + int(dataLen) + paddingSize

	// Try to get buffer from pool, or allocate if too large
	var output []byte
	var pooledBuf *[]byte
	if totalSize <= 2048 {
		pooledBuf = bufferPool.Get().(*[]byte)
		output = (*pooledBuf)[:totalSize]
	} else {
		// For large packets, allocate directly
		output = make([]byte, totalSize)
	}

	// Write Nonce (2 bytes)
	binary.BigEndian.PutUint16(output[0:2], nonce)

	// Write Data Length (2 bytes) - Encrypted later
	binary.BigEndian.PutUint16(output[2:4], dataLen)

	// Copy Raw Data
	copy(output[4:], rawData)

	// Generate Random Padding
	if paddingSize > 0 {
		rand.Read(output[4+int(dataLen):])
	}

	// XOR encrypt everything after nonce (Length + Data + Padding)
	o.xorData(output[2:], packetKey)

	// For pooled buffers, make a copy to return (pool buffer will be reused)
	if pooledBuf != nil {
		result := make([]byte, totalSize)
		copy(result, output)
		bufferPool.Put(pooledBuf)
		return result
	}

	return output
}

// Deobfuscate takes obfuscated packet and returns original KCP packet
// Input format: [Nonce (2 bytes)] + [Encrypted Length (2 bytes)] + [Encrypted Data] + [Encrypted Padding]
func (o *Obfuscator) Deobfuscate(obfuscatedData []byte) ([]byte, bool) {
	if !o.enabled {
		return obfuscatedData, true
	}

	// Validate minimum size (Nonce + Length)
	if len(obfuscatedData) < NonceSize+2 {
		return nil, false
	}

	// Extract Nonce
	nonce := binary.BigEndian.Uint16(obfuscatedData[0:2])

	// Derive packet key
	packetKey := o.derivePacketKey(nonce)

	// Try to get buffer from pool for decryption
	decryptedSize := len(obfuscatedData) - NonceSize
	var decrypted []byte
	var pooledBuf *[]byte
	if decryptedSize <= 2048 {
		pooledBuf = bufferPool.Get().(*[]byte)
		decrypted = (*pooledBuf)[:decryptedSize]
	} else {
		decrypted = make([]byte, decryptedSize)
	}

	// Decrypt everything after nonce
	copy(decrypted, obfuscatedData[NonceSize:])
	o.xorData(decrypted, packetKey)

	// Extract Real Data Length
	dataLen := binary.BigEndian.Uint16(decrypted[0:2])

	// Validate length sanity
	if int(dataLen) > len(decrypted)-2 {
		if pooledBuf != nil {
			bufferPool.Put(pooledBuf)
		}
		return nil, false // Corrupted or spoofed packet
	}

	// Copy actual data to return
	result := make([]byte, dataLen)
	copy(result, decrypted[2:2+dataLen])

	// Return buffer to pool
	if pooledBuf != nil {
		bufferPool.Put(pooledBuf)
	}

	return result, true
}

// GetOverhead returns the average size overhead added by obfuscation
func (o *Obfuscator) GetOverhead() int {
	if !o.enabled {
		return 0
	}
	return NonceSize + 2 + 16 // Nonce + Len + Avg Padding
}

// IsEnabled returns whether obfuscation is enabled
func (o *Obfuscator) IsEnabled() bool {
	return o.enabled
}
