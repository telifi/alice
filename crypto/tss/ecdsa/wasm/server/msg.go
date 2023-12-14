package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"

	"github.com/pkg/errors"
)

type WrapMsg struct {
	Type     byte
	SenderID []byte
	Data     []byte
}

// SerializeWMsg converts a wmsg to a byte slice.
func SerializeWMsg(w *WrapMsg) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := buf.WriteByte(w.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(len(w.SenderID))); err != nil {
		return nil, err
	}

	buf.Write(w.SenderID)
	// Serialize Field2 (string).
	if err := binary.Write(buf, binary.BigEndian, int32(len(w.Data))); err != nil {
		return nil, err
	}
	buf.Write(w.Data)

	// Prepend length of the buffer to the buffer itself.
	finalBytes := append(intToBytes(buf.Len()), buf.Bytes()...)

	return finalBytes, nil
}

// DeserializeWMsg converts a byte slice to a wmsg.
func DeserializeWMsg(data []byte) (WrapMsg, error) {
	var (
		w   WrapMsg
		err error
	)
	if len(data) <= 3 {
		err = errors.Errorf("Invalid msg %v", data)
		return w, err
	}
	buf := bytes.NewReader(data[4:]) // Skip the length prefix.

	// Deserialize Field1 (int).
	var msgType byte
	msgType, err = buf.ReadByte()
	if err != nil {
		return w, err
	}
	// Deserialize Field2 (string).
	var lSenderID int32
	if err := binary.Read(buf, binary.BigEndian, &lSenderID); err != nil {
		return w, err
	}
	senderID := make([]byte, lSenderID)
	if _, err := buf.Read(senderID); err != nil {
		return w, err
	}
	var lData int32
	if err := binary.Read(buf, binary.BigEndian, &lData); err != nil {
		return w, err
	}
	msgData := make([]byte, lData)
	if _, err := buf.Read(msgData); err != nil {
		return w, err
	}
	w = WrapMsg{
		Type:     msgType,
		SenderID: senderID,
		Data:     msgData,
	}
	return w, nil
}

// intToBytes converts an integer to a byte slice.
func intToBytes(i int) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(i))
	return length[:]
}

func (m *WrapMsg) ToWSMsg(rID string) interface{} {

	wMsgByte, err := SerializeWMsg(m)
	if err != nil {
		loginfo("Cannot serialize message, err %v", err)
		return nil
	}

	wsMsg := map[string]string{}
	wsMsg["data"] = base64.StdEncoding.EncodeToString(wMsgByte)
	wsMsg["receiverid"] = rID
	return wsMsg
}

const (
	REGISTER = byte(iota)
	KEYGEN
	STARTKEYGEN
	STARTREFRESH
	STARTSIGN
	KEYGENOUTPUT
	REF
	SIGN
)
