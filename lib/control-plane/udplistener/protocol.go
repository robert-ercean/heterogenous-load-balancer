package udplistener

import (
	"encoding/binary"
	"fmt"
)

// Protocol message layout (all messages are 8 bytes):
//
// REGISTER (backend → control plane):
//   offset 0..3 : magic (0xDEADBEEF, big-endian)
//   offset 4    : msg type (0x01)
//   offset 5..6 : service port (big-endian)
//   offset 7    : reserved, must be zero
//
// ACK (control plane → backend):
//   offset 0..3 : magic
//   offset 4    : msg type (0x02)
//   offset 5..7 : reserved, must be zero
//
// HEARTBEAT (backend → control plane):
//   offset 0..3 : magic
//   offset 4    : msg type (0x03)
//   offset 5    : load score (0-255)
//   offset 6..7 : reserved, must be zero

const (
	Magic uint32 = 0xDEADBEEF

	MsgRegister  uint8 = 0x01
	MsgAck       uint8 = 0x02
	MsgHeartbeat uint8 = 0x03

	PacketSize = 8
)

type RegisterMsg struct {
	Port uint16
}

type HeartbeatMsg struct {
	Load uint8
}

// Decode parses an 8-byte binary message.
func Decode(b []byte) (msgType uint8, payload any, err error) {
	if len(b) != PacketSize {
		return 0, nil, fmt.Errorf("expected %d bytes, got %d", PacketSize, len(b))
	}

	magic := binary.BigEndian.Uint32(b[0:4])
	if magic != Magic {
		return 0, nil, fmt.Errorf("bad magic: 0x%08X", magic)
	}

	msgType = b[4]

	switch msgType {
	case MsgRegister:
		if b[7] != 0 {
			return msgType, nil, fmt.Errorf("non-zero reserved byte in REGISTER")
		}
		return msgType, RegisterMsg{
			Port: binary.BigEndian.Uint16(b[5:7]),
		}, nil

	case MsgHeartbeat:
		if b[6] != 0 || b[7] != 0 {
			return msgType, nil, fmt.Errorf("non-zero reserved bytes in HEARTBEAT")
		}
		return msgType, HeartbeatMsg{
			Load: b[5],
		}, nil

	default:
		return msgType, nil, fmt.Errorf("unknown msg type: 0x%02X", msgType)
	}
}

func EncodeAck() []byte {
	b := make([]byte, PacketSize)
	binary.BigEndian.PutUint32(b[0:4], Magic)
	b[4] = MsgAck
	// b[5..7] remains zero
	return b
}
