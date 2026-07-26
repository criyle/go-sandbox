package container

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// 32k buffer size
const bufferSize = 32 << 10

// Chunk framing for messages larger than bufferSize. A gob stream never starts
// with a zero byte (its leading length prefix is always >= 1), so a leading
// chunkByte unambiguously marks a chunk and small messages need no header at
// all. Each chunk datagram is [chunkByte][flag][payload] and stays within
// bufferSize, so it always fits the default kernel socket buffer regardless of
// the total message size.
const (
	chunkByte        = 0 // sentinel first byte marking a chunk datagram
	chunkHeaderSize  = 2 // [chunkByte][flag]
	chunkPayloadSize = bufferSize - chunkHeaderSize
)

const (
	chunkPartial  byte = 0 // more chunks follow
	chunkComplete byte = 1 // final chunk of the message
)

type socket struct {
	*unixsocket.Socket

	buff []byte

	decoder  *gob.Decoder
	recvBuff bufferRotator

	encoder  *gob.Encoder
	sendBuff bytes.Buffer

	chunkBuff []byte       // reusable framing buffer for sending chunks
	recvChunk bytes.Buffer // reusable assembly buffer for receiving chunks
}

// bufferRotator replace the underlying Buffers to avoid allocation
type bufferRotator struct {
	*bytes.Buffer
}

func (b *bufferRotator) Rotate(buffer *bytes.Buffer) {
	b.Buffer = buffer
}

func newSocket(s *unixsocket.Socket) *socket {
	soc := socket{
		Socket: s,
	}
	soc.buff = make([]byte, bufferSize)
	soc.decoder = gob.NewDecoder(&soc.recvBuff)
	soc.encoder = gob.NewEncoder(&soc.sendBuff)

	return &soc
}

func (s *socket) RecvMsg(e any) (msg unixsocket.Msg, err error) {
	n, msg, err := s.Socket.RecvMsg(s.buff)
	if err != nil {
		return msg, fmt.Errorf("recv msg: %w", err)
	}
	// A leading chunkByte marks a chunk of a larger message; gob output never
	// starts with a zero byte, so small messages are received as-is with no
	// extra copy. Chunks are reassembled until the complete flag is seen, and
	// the returned msg carries the FDs from the first chunk.
	if n >= chunkHeaderSize && s.buff[0] == chunkByte {
		s.recvChunk.Reset()
		flag := s.buff[1]
		s.recvChunk.Write(s.buff[chunkHeaderSize:n])
		for flag != chunkComplete {
			cn, cmsg, cerr := s.Socket.RecvMsg(s.buff)
			if cerr != nil {
				return cmsg, fmt.Errorf("recv msg: chunk: %w", cerr)
			}
			if cn < chunkHeaderSize || s.buff[0] != chunkByte {
				return cmsg, fmt.Errorf("recv msg: expected chunk, got %d bytes", cn)
			}
			if len(cmsg.Fds) > 0 {
				// FDs only travel with the first chunk; close unexpected ones.
				closeFds(cmsg.Fds)
				return cmsg, fmt.Errorf("recv msg: unexpected FDs in chunk")
			}
			flag = s.buff[1]
			s.recvChunk.Write(s.buff[chunkHeaderSize:cn])
		}
		s.recvBuff.Rotate(bytes.NewBuffer(s.recvChunk.Bytes()))
		if err := s.decoder.Decode(e); err != nil {
			return msg, fmt.Errorf("recv msg: decode: %w", err)
		}
		return msg, nil
	}
	s.recvBuff.Rotate(bytes.NewBuffer(s.buff[:n]))

	if err := s.decoder.Decode(e); err != nil {
		return msg, fmt.Errorf("recv msg: decode: %w", err)
	}
	return msg, nil
}

func (s *socket) SendMsg(e any, msg unixsocket.Msg) error {
	s.sendBuff.Reset()
	if err := s.encoder.Encode(e); err != nil {
		return fmt.Errorf("send msg: encode: %w", err)
	}
	data := s.sendBuff.Bytes()
	// Small messages fit in a single datagram and are sent as-is (zero copy);
	// larger ones are split into [chunkByte][flag][payload] chunks, each within
	// bufferSize so it always fits the receiver's buffer.
	if len(data) <= bufferSize {
		if err := s.Socket.SendMsg(data, msg); err != nil {
			return fmt.Errorf("send msg: %w", err)
		}
		return nil
	}
	if s.chunkBuff == nil {
		s.chunkBuff = make([]byte, bufferSize)
	}
	for offset := 0; offset < len(data); offset += chunkPayloadSize {
		end := offset + chunkPayloadSize
		if end > len(data) {
			end = len(data)
		}
		s.chunkBuff[0] = chunkByte
		if end == len(data) {
			s.chunkBuff[1] = chunkComplete
		} else {
			s.chunkBuff[1] = chunkPartial
		}
		nc := copy(s.chunkBuff[chunkHeaderSize:], data[offset:end])
		// FDs / credentials travel with the first chunk only.
		chunkMsg := unixsocket.Msg{}
		if offset == 0 {
			chunkMsg = msg
		}
		if err := s.Socket.SendMsg(s.chunkBuff[:chunkHeaderSize+nc], chunkMsg); err != nil {
			return fmt.Errorf("send msg: chunk: %w", err)
		}
	}
	return nil
}
