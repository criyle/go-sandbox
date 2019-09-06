package daemon

import (
	"sync"
)

// 16k buffsize
const bufferSize = 16384

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, bufferSize)
	},
}

// GetBuffer get buffer from pool
func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

// PutBuffer return buffer to the pool
func PutBuffer(x []byte) {
	bufferPool.Put(x)
}
