package main

import (
	"encoding/base64"
	"fmt"

	"google.golang.org/protobuf/proto"
)

type peerManager struct {
	msgType byte
	group   *groupData
	id      string
	ids     []string
}

func NewPeerManager(selfID string, ids []string, g *groupData) *peerManager {
	return &peerManager{
		group: g,
		id:    selfID,
		ids:   ids,
	}
}

func (p *peerManager) NumPeers() uint32 {
	return uint32(len(p.ids))
}

func (p *peerManager) SelfID() string {
	return p.id
}

func (p *peerManager) PeerIDs() []string {
	return p.ids
}

func (p *peerManager) MustSend(peerId string, message interface{}) {
	msg, ok := message.(proto.Message)
	if !ok {
		loginfo("invalid proto message")
		return
	}

	bs, err := proto.Marshal(msg)
	if err != nil {
		loginfo("Cannot marshal message, err %v", err)
		return
	}
	wMsg := WrapMsg{
		Type:     p.msgType,
		SenderID: []byte(p.SelfID()),
		Data:     bs,
	}
	wMsgByte, err := SerializeWMsg(&wMsg)
	if err != nil {
		loginfo("Cannot serialize message, err %v", err)
		return
	}
	gLocker.Lock()
	if p.group.wsconn != nil {
		msg := map[string]string{}
		msg["data"] = base64.StdEncoding.EncodeToString(wMsgByte)
		msg["receiverid"] = peerId
		err := p.group.wsconn.WriteJSON(msg)
		loginfo("Error send: %v", err)
		fmt.Printf("Trying to send %v %v\n", msg, err)
	}
	gLocker.Unlock()
}

// EnsureAllConnected connects the host to specified peer and sends the message to it.
func (p *peerManager) EnsureAllConnected() {
}

// AddPeer adds a peer to the peer list.
func (p *peerManager) AddPeer(peerId string, peerAddr string) {
	// p.peers[peerId] = peerAddr
}
