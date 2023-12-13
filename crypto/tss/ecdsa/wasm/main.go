//go:build js && wasm
// +build js,wasm

package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"syscall/js"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/sign"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

func JSKeyGen(this js.Value, p []js.Value) interface{} {
	teleID := p[0].String()
	sID := p[1].String()

	_, _, _, pk, err := StartKeyGen(teleID, sID)
	if err != nil {
		// Handle error if needed
		loginfo("Error in JSReceive:", err)
	}
	return crypto.PubkeyToAddress(*pk)
}

func JSReceiveWrapper(this js.Value, p []js.Value) interface{} {
	receiverID := p[0].String()
	data := p[1]
	dataBytes := jsValueToBytes(data)

	err := JSReceive(receiverID, dataBytes)

	if err != nil {
		// Handle error if needed
		loginfo("Error in JSReceive:", err)
	}

	return nil
}

func jsValueToBytes(val js.Value) []byte {
	// Check if the js.Value is an instance of Uint8Array
	if val.InstanceOf(js.Global().Get("Uint8Array")) {
		// Prepare a byte slice of the same length
		byteSlice := make([]byte, val.Length())

		// Copy the data from the js.Value to the Go byte slice
		n := js.CopyBytesToGo(byteSlice, val)
		if n != val.Length() {
			panic(fmt.Errorf("failed to copy the entire buffer"))
			return nil //, fmt.Errorf("failed to copy the entire buffer")
		}

		return byteSlice
	}
	panic(fmt.Errorf("value is not a Uint8Array"))
	return nil //, fmt.Errorf("value is not a Uint8Array")
}

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

var (
	GlobalMsg = make(chan []byte, 10)
	PKs       = map[string]*ecpointgrouplaw.ECPoint{}
	ready     = make(chan bool, 2)
	pPK       = make(chan []byte, 2)
	dkg1      *dkg.DKG
	dkg3      *dkg.DKG
	dkgR1     *dkg.Result
	dkgR3     *dkg.Result
	ld1       = &listener{
		errCh: make(chan error, 10),
	}
	ld3 = &listener{
		errCh: make(chan error, 10),
	}
	ref1  *refresh.Refresh
	ref3  *refresh.Refresh
	refR1 *refresh.Result
	refR3 *refresh.Result
	lr1   = &listener{
		errCh: make(chan error, 10),
	}
	lr3 = &listener{
		errCh: make(chan error, 10),
	}
	sign1  *sign.Sign
	sign3  *sign.Sign
	signR1 *sign.Result
	signR3 *sign.Result
	ls1    = &listener{
		errCh: make(chan error, 10),
	}
	ls3 = &listener{
		errCh: make(chan error, 10),
	}
)

func JSSend(msg WrapMsg) error {
	msgBytes, err := SerializeWMsg(&msg)
	if err != nil {
		return err
	}
	uint8Array := js.Global().Get("Uint8Array").New(len(msgBytes))
	js.CopyBytesToJS(uint8Array, msgBytes)
	js.Global().Call("onWasmEvent", uint8Array)
	return nil
}

func JSCheckConnect(serverID string) bool {
	connected := js.Global().Get(serverID + "connected")
	if connected.IsNull() {
		return false
	}
	return true
}

//export JSReceive
func JSReceive(receiverID string, data []byte) error {
	loginfo("%v got data %v", receiverID, []byte(data))
	wMsg, err := DeserializeWMsg(data)
	if err != nil {
		return err
	}
	loginfo("receive msg %v=>%v type:%v", string(wMsg.SenderID), receiverID, wMsg.Type)
	switch wMsg.Type {
	case STARTKEYGEN:
		dkg1.BroadcastFisrtMsg()
		dkg3.BroadcastFisrtMsg()
	case KEYGEN:
		return handleKeyGen(wMsg, receiverID)
	case KEYGENOUTPUT:
		GlobalMsg <- wMsg.Data
	case STARTREFRESH:
		ref1.BroadcastFisrtMsg()
		ref3.BroadcastFisrtMsg()
	case REF:
		return handleRef(wMsg, receiverID)
	case STARTSIGN:
		sign1.BroadcastFisrtMsg()
		// sign3.BroadcastFisrtMsg()

	case SIGN:
		return handleSign(wMsg, receiverID)
	default:
		fmt.Printf("Unknown message command: %v", wMsg.Type)
	}
	return nil

}

func loginfo(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	js.Global().Get("console").Call("log", s)
}
func base64ToBytes(base64Str string) []byte {
	// Decode the Base64 string
	decodedBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		// Handle error, e.g., log it or return an error
		js.Global().Call("console", "log", "Error decoding Base64:", err.Error())
		return nil
	}

	return decodedBytes
}

func main() {
	js.Global().Set("JSReceive", js.FuncOf(JSReceiveWrapper))
	userId := js.Global().Get("userId").String()
	tssServiceName := js.Global().Get("tssServiceName").String()
	// privateShare := js.Global().Get("privateShare").String()
	// message := js.Global().Get("message").String()

	if tssServiceName == "KeyGen" {
		sid := InitKeyGen()
		loginfo("DKG start")
		d1, d3, pks, _, err := StartKeyGen(userId, sid)
		if err != nil {
			panic(err)
		}
		loginfo("DKG start", d1, d3, pks)

		// sid = InitRef(d1, d3, pks)
		// loginfo("REF start")
		// _, _, err = StartRef(userId, sid)
		// if err != nil {
		// 	panic(err)
		// }
	} else if tssServiceName == "Precomputed" {
		loginfo("Precomputed----------------")

		d1 := js.Global().Get("d1").String()
		loginfo("dk1----------------")

		d3 := js.Global().Get("d3").String()
		loginfo("dk2----------------", d3)

		pks := js.Global().Get("pks").String()
		loginfo("dk3----------------")

		dR1, dR3, sid := InitRef(base64ToBytes(d1), base64ToBytes(d3), base64ToBytes(pks))
		loginfo("dR1----------------", dR1)

		loginfo("REF start")
		_, _, err := StartRef(userId, sid, dR1, dR3)
		if err != nil {
			panic(err)
		}
	}
	// else {

	// 	sid := InitSig(d1, r1, pks)
	// 	loginfo("SIGN start")
	// 	StartSign(userId, sid, message)
	// }

	select {}
}

func handleKeyGen(wMsg WrapMsg, receiverID string) error {
	msg := &dkg.Message{}
	loginfo("Received msg tss, sender %v receiver:%v data:%v", string(wMsg.SenderID), receiverID, wMsg.Data)
	err := proto.Unmarshal(wMsg.Data, msg)
	if err != nil {
		loginfo("Error proto.Unmarshal: %v", err)
		return err
	}
	if receiverID == "client1" {
		return dkg1.AddMessage(string(wMsg.SenderID), msg)
	}
	if receiverID == "client3" {
		return dkg3.AddMessage(string(wMsg.SenderID), msg)
	}
	return nil
}

func InitKeyGen() string {
	sID := "helloworld"
	var err1 error
	var err3 error

	pm1 := NewPeerManager("client1", []string{"client2", "client3"}, KEYGEN)
	dkg1, err1 = dkg.NewDKG(elliptic.Secp256k1(), pm1, []byte(sID), 2, 0, ld1)
	loginfo("DKG return err %v", err1)
	pm3 := NewPeerManager("client3", []string{"client1", "client2"}, KEYGEN)
	dkg3, err3 = dkg.NewDKG(elliptic.Secp256k1(), pm3, []byte(sID), 2, 0, ld3)
	pm1.AddMsgMains(dkg1.MessageMain, dkg3.MessageMain)
	pm3.AddMsgMains(dkg1.MessageMain, dkg3.MessageMain)
	loginfo("DKG return err %v", err3)
	return sID
}
func StartKeyGen(telegramID, sID string) ([]byte, []byte, []byte, *ecdsa.PublicKey, error) {
	msgReg := WrapMsg{
		Type:     REGISTER,
		SenderID: []byte(telegramID),
		Data:     []byte(telegramID),
	}
	JSSend(msgReg)
	st := time.Now()
	if dkg1 == nil || dkg3 == nil {
		loginfo("DKG is not init yet")
		return nil, nil, nil, nil, errors.Errorf("DKG is not init yet")
	}
	go dkg1.Start()
	go dkg3.Start()

	defer dkg1.Stop()
	defer dkg3.Stop()
	msgStart := WrapMsg{
		Type:     STARTKEYGEN,
		SenderID: []byte(telegramID),
		Data:     []byte(sID),
	}
	JSSend(msgStart)
	if err := <-ld1.Done(); err != nil {
		return nil, nil, nil, nil, err
	} else {
		loginfo("DKG 1 done!\n")
	}
	if err := <-ld3.Done(); err != nil {
		return nil, nil, nil, nil, err
	} else {
		loginfo("DKG 3 done\n")
	}
	result1, _ := dkg1.GetResult()
	result3, _ := dkg3.GetResult()
	myPartialPublicKey1 := ecpointgrouplaw.ScalarBaseMult(elliptic.Secp256k1(), result1.Share)
	pkPointMsg, err := myPartialPublicKey1.ToEcPointMessage()
	pkBytes, err := proto.Marshal(pkPointMsg)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	msgOutput := WrapMsg{
		Type:     KEYGENOUTPUT,
		SenderID: []byte("client1"),
		Data:     pkBytes,
	}
	JSSend(msgOutput)
	myPartialPublicKey3 := ecpointgrouplaw.ScalarBaseMult(elliptic.Secp256k1(), result3.Share)
	pkPointMsg, err = myPartialPublicKey3.ToEcPointMessage()
	pkBytes, err = proto.Marshal(pkPointMsg)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	msgOutput = WrapMsg{
		Type:     KEYGENOUTPUT,
		SenderID: []byte("client3"),
		Data:     pkBytes,
	}
	JSSend(msgOutput)
	serverPK := <-GlobalMsg
	var msg ecpointgrouplaw.EcPointMessage
	err = proto.Unmarshal(serverPK, &msg)
	if err != nil {
		loginfo("Cannot unmarshal proto message", "err", err)
		return nil, nil, nil, nil, err
	}
	p, err := msg.ToPoint()
	if err != nil {
		loginfo("Cannot convert to EcPoint", "err", err)
		return nil, nil, nil, nil, err
	}
	PKs["client2"] = p
	PKs["client1"] = myPartialPublicKey1
	PKs["client3"] = myPartialPublicKey3
	dkgR1 = result1
	sk1, err := dkresult2bytes(dkgR1, PKs)
	if err != nil {
		loginfo("Cannot marshal dkgR1 err %v", err)
		return nil, nil, nil, nil, err
	}
	dkgR3 = result3
	sk3, err := dkresult2bytes(dkgR3, PKs)
	if err != nil {
		loginfo("Cannot marshal dkgR1 err %v", err)
		return nil, nil, nil, nil, err
	}
	loginfo("Keygen done, server pk %v, got %v cost %v", p.String(), crypto.PubkeyToAddress(*result1.PublicKey.ToPubKey()), time.Since(st))
	for c, pk := range PKs {
		loginfo("peer:%v  ==>  %v", c, pk.String())
	}
	PKString, err := json.Marshal(PKs)
	if err != nil {
		loginfo("Cannot marshal dkgR1 err %v", err)
		return nil, nil, nil, nil, err
	}
	js.Global().Call("getKeyGen", js.Global().Get("JSON").Call("stringify", js.ValueOf(map[string]interface{}{
		// "address": crypto.PubkeyToAddress(*result1.PublicKey.ToPubKey()).String(),
		// "privateKey1": crypto.PubkeyToAddress(*result1.PublicKey),
		// "privateKey2": crypto.PubkeyToAddress(*result.PublicKey.ToPubKey()).String(),
		"privateKey1": string(sk1),
		"privateKey3": string(sk3),
		// "smallPKs":    string(PKString),
		"address": crypto.PubkeyToAddress(*result1.PublicKey.ToPubKey()).String(),
		// "party3": result3,
	})))

	return sk1, sk3, PKString, result1.PublicKey.ToPubKey(), nil
}

func InitRef(dkgR1Bytes, dkgR3Bytes, PKs []byte) (*DKGResult, *DKGResult, string) {
	sID := "helloworld"
	var err error

	dkgR1NewStruct := &DKGResult{}
	err = json.Unmarshal(dkgR1Bytes, dkgR1NewStruct)
	loginfo("0 %v cost", err)

	dkgR1New, pPKs, err := ConvertDKGResult(dkgR1NewStruct.Pubkey, dkgR1NewStruct.Share, dkgR1NewStruct.BKs, dkgR1NewStruct.Rid, dkgR1NewStruct.PartialPublicKeys)
	loginfo("1 %v cost", err)

	dkgR3NewStruct := &DKGResult{}
	err = json.Unmarshal(dkgR3Bytes, dkgR3NewStruct)
	loginfo("2 %v cost", err)

	dkgR3New, pPKs, err := ConvertDKGResult(dkgR3NewStruct.Pubkey, dkgR3NewStruct.Share, dkgR3NewStruct.BKs, dkgR3NewStruct.Rid, dkgR3NewStruct.PartialPublicKeys)
	loginfo("3 %v cost", err)

	// pks := make(map[string]*ecpointgrouplaw.ECPoint)
	// err = json.Unmarshal(PKs, pks)
	// loginfo("4 %v cost", err)

	pm1 := NewPeerManager("client1", []string{"client2", "client3"}, REF)

	ref1, err = initRefCore(sID, "client1", dkgR1New, pm1, lr1, pPKs)
	loginfo("5 %v cost", err)

	if err != nil {
		panic(err)
	}

	pm3 := NewPeerManager("client3", []string{"client1", "client2"}, REF)
	ref3, err = initRefCore(sID, "client3", dkgR3New, pm3, lr3, pPKs)
	if err != nil {
		panic(err)
	}
	pm1.AddMsgMains(ref1.MessageMain, ref3.MessageMain)
	pm3.AddMsgMains(ref1.MessageMain, ref3.MessageMain)
	return dkgR1NewStruct, dkgR3NewStruct, sID
}

func initRefCore(sID string, selfID string, dkgR *dkg.Result, pm *peerManager, l *listener, pks map[string]*ecpointgrouplaw.ECPoint) (*refresh.Refresh, error) {
	st := time.Now()
	ssid := cggmp.ComputeSSID([]byte(sID), []byte(dkgR.Bks[selfID].String()), dkgR.Rid)
	loginfo("Computed ssid %v cost %v", selfID, time.Since(st))

	ref, err := refresh.NewRefresh(dkgR.Share, dkgR.PublicKey, pm, 2, pks, dkgR.Bks, 2048, ssid, l)

	if err != nil {
		loginfo("Cannot create a new reshare core %v err", selfID, err)
		return nil, err
	}
	loginfo("Init ref cost %v", time.Since(st))
	return ref, nil
}

func StartRef(telegramID, sID string, dkgR1, dkgR3 *DKGResult) ([]byte, []byte, error) {
	msgReg := WrapMsg{
		Type:     REGISTER,
		SenderID: []byte(telegramID),
		Data:     []byte(telegramID),
	}
	JSSend(msgReg)
	st := time.Now()
	if ref1 == nil {
		loginfo("REF is not init yet")
		return nil, nil, errors.Errorf("REF is not init yet")
	}
	go ref1.Start()
	go ref3.Start()

	defer ref1.Stop()
	defer ref3.Stop()
	msgStart := WrapMsg{
		Type:     STARTREFRESH,
		SenderID: []byte(telegramID),
		Data:     []byte(sID),
	}
	JSSend(msgStart)
	if err := <-lr1.Done(); err != nil {
		return nil, nil, err
	} else {
		loginfo("REF 1 done!\n")
	}
	if err := <-lr3.Done(); err != nil {
		return nil, nil, err
	} else {
		loginfo("REF 3 done\n")
	}
	refR1, _ = ref1.GetResult()
	r1, err := refresult2bytes(refR1, dkgR1)
	if err != nil {
		loginfo("Cannot marshal dkgR1 err %v", err)
		return nil, nil, err
	}
	refR3, _ = ref3.GetResult()
	r3, err := refresult2bytes(refR3, dkgR3)
	if err != nil {
		loginfo("Cannot marshal dkgR1 err %v", err)
		return nil, nil, err
	}
	loginfo("Ref done,  cost %v", time.Since(st))
	js.Global().Call("getPreCompute", js.Global().Get("JSON").Call("stringify", js.ValueOf(map[string]interface{}{
		// "address": crypto.PubkeyToAddress(*result1.PublicKey.ToPubKey()).String(),
		// "privateKey1": crypto.PubkeyToAddress(*result1.PublicKey),
		// "privateKey2": crypto.PubkeyToAddress(*result.PublicKey.ToPubKey()).String(),
		"preCompute1": string(r1),
		"preCompute3": string(r3),
		// "smallPKs":    string(PKString),
		// "address":     crypto.PubkeyToAddress(*result1.PublicKey.ToPubKey()).String(),
		// "party3": result3,
	})))
	return r1, r3, nil
}

func handleRef(wMsg WrapMsg, receiverID string) error {
	msg := &refresh.Message{}
	loginfo("Received msg ref, sender %v receiver:%v data:%v", string(wMsg.SenderID), receiverID, wMsg.Data)
	err := proto.Unmarshal(wMsg.Data, msg)
	if err != nil {
		loginfo("Error proto.Unmarshal: %v", err)
		return err
	}
	if receiverID == "client1" {
		return ref1.AddMessage(string(wMsg.SenderID), msg)
	}
	if receiverID == "client3" {
		return ref3.AddMessage(string(wMsg.SenderID), msg)
	}
	return nil
}

type peerManager struct {
	msgMain1 types.MessageMain
	msgMain3 types.MessageMain
	msgType  byte
	id       string
	ids      []string
}

func NewPeerManager(selfID string, ids []string, msgType byte) *peerManager {
	return &peerManager{
		msgType: msgType,
		id:      selfID,
		ids:     ids,
	}
}

func (p *peerManager) NumPeers() uint32 {
	return uint32(len(p.ids))
}

func (p *peerManager) AddMsgMains(msgMain1, msgMain3 types.MessageMain) {
	p.msgMain1 = msgMain1
	p.msgMain3 = msgMain3
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
	loginfo("Trying to send %v %v %v %v", peerId, message.(types.Message).GetMessageType(), bs, len(bs))
	if peerId == "client1" {
		err = p.msgMain1.AddMessage(p.SelfID(), message.(types.Message))
		loginfo("Trying to send %v %v to dkg1", p.SelfID(), peerId)
		return
	}
	if peerId == "client2" {
		msgOutput := WrapMsg{
			Type:     p.msgType,
			SenderID: []byte(p.SelfID()),
			Data:     bs,
		}
		err = JSSend(msgOutput)
		loginfo("JSSend err %v", err)
		return
	}
	if peerId == "client3" {
		err = p.msgMain3.AddMessage(p.SelfID(), message.(types.Message))
		fmt.Printf("Trying to send %v %v to dkg3", p.SelfID(), peerId)
		return
	}
}

// EnsureAllConnected connects the host to specified peer and sends the message to it.
func (p *peerManager) EnsureAllConnected() {
	// JSCheckConnect(p.serverID)
}

// AddPeer adds a peer to the peer list.
func (p *peerManager) AddPeer(peerId string, peerAddr string) {
}

type listener struct {
	errCh chan error
}

func (l *listener) OnStateChanged(oldState types.MainState, newState types.MainState) {
	loginfo("State changed; old", oldState.String(), "new", newState.String())
	if newState == types.StateFailed {
		l.errCh <- fmt.Errorf("State %s -> %s", oldState.String(), newState.String())
		return
	} else if newState == types.StateDone {
		l.errCh <- nil
		return
	}
}

func (l *listener) Done() <-chan error {
	return l.errCh
}

func InitSig(dkgR1Bytes, refR1Bytes, PKs []byte) string {
	sID := "helloworld"
	var err error

	dkgR1NewStruct := &DKGResult{}
	json.Unmarshal(dkgR1Bytes, dkgR1NewStruct)
	dkgR1New, _, err := ConvertDKGResult(dkgR1NewStruct.Pubkey, dkgR1NewStruct.Share, dkgR1NewStruct.BKs, dkgR1NewStruct.Rid, dkgR1NewStruct.PartialPublicKeys)

	refR1NewStruct := &ReshareResult{}
	json.Unmarshal(refR1Bytes, refR1NewStruct)
	refR1New, err := ConvertReshareResult(refR1NewStruct.Share, refR1NewStruct.PaillierKey, refR1NewStruct.YSecret, refR1NewStruct.PartialPublicKeys, refR1NewStruct.Y, refR1NewStruct.PedParameters)

	pks := make(map[string]*ecpointgrouplaw.ECPoint)
	json.Unmarshal(PKs, pks)

	pm1 := NewPeerManager("client1", []string{"client2"}, SIGN)
	sign1, err = initSignCore(sID, "client1", "helloworld", dkgR1New, refR1New, pm1, ls1)
	if err != nil {
		panic(err)
	}

	// pm3 := NewPeerManager("client3", []string{"client1", "client2"}, SIGN)
	// sign3, err = initSignCore(sID, "client3", "helloworld", dkgR3, refR3, pm3, ls3)
	// if err != nil {
	// 	panic(err)
	// }
	pm1.AddMsgMains(sign1.MessageMain, nil)
	// pm3.AddMsgMains(sign1.MessageMain, sign3.MessageMain)
	return sID
}

func initSignCore(sID, selfID, msg string, dkgR *dkg.Result, refR *refresh.Result, pm *peerManager, l *listener) (*sign.Sign, error) {
	st := time.Now()
	ssid := cggmp.ComputeSSID([]byte(sID), []byte(dkgR.Bks[selfID].String()), dkgR.Rid)
	loginfo("Computed ssid %v cost %v", selfID, time.Since(st))
	delete(dkgR.Bks, "client3")
	delete(refR.PedParameter, "client3")
	delete(refR.PartialPubKey, "client3")

	sign, err := sign.NewSign(
		2,
		ssid,
		refR.Share,
		dkgR.PublicKey,
		refR.PartialPubKey,
		refR.PaillierKey,
		refR.PedParameter,
		dkgR.Bks,
		[]byte(msg),
		pm,
		l,
	)

	if err != nil {
		loginfo("Cannot create a new reshare core %v err", selfID, err)
		return nil, err
	}
	loginfo("Init sign cost %v", time.Since(st))
	return sign, nil
}

func StartSign(telegramID, sID, msg string) error {
	// msgReg := WrapMsg{
	// 	Type:     REGISTER,
	// 	SenderID: []byte(telegramID),
	// 	Data:     []byte(telegramID),
	// }
	// JSSend(msgReg)
	st := time.Now()
	if sign1 == nil {
		loginfo("SIGN is not init yet")
		return errors.Errorf("SIGN is not init yet")
	}
	go sign1.Start()
	// go sign3.Start()

	defer sign1.Stop()
	// defer sign3.Stop()
	msgStart := WrapMsg{
		Type:     STARTSIGN,
		SenderID: []byte(telegramID),
		Data:     []byte(sID),
	}
	JSSend(msgStart)
	if err := <-ls1.Done(); err != nil {
		return err
	} else {
		loginfo("SIG 1 done!\n")
	}
	// if err := <-ls3.Done(); err != nil {
	// 	return err
	// } else {
	// 	loginfo("SIG 3 done\n")
	// }
	// signR3, _ = sign3.GetResult()
	signR1, _ = sign1.GetResult()

	loginfo("sign done,  cost %v", time.Since(st))
	// for c, pk := range PKs {
	// 	loginfo("peer:%v  ==>  %v", c, pk.String())
	// }
	return nil
}

func handleSign(wMsg WrapMsg, receiverID string) error {
	msg := &sign.Message{}
	loginfo("Received msg ref, sender %v receiver:%v data:%v", string(wMsg.SenderID), receiverID, wMsg.Data)
	err := proto.Unmarshal(wMsg.Data, msg)
	if err != nil {
		loginfo("Error proto.Unmarshal: %v", err)
		return err
	}
	if receiverID == "client1" {
		return sign1.AddMessage(string(wMsg.SenderID), msg)
	}
	if receiverID == "client3" {
		return sign3.AddMessage(string(wMsg.SenderID), msg)
	}
	return nil
}

type ECPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type PaillierKey struct {
	P string `json:"p"`
	Q string `json:"q"`
}

type PederssenOpenParameter struct {
	N string `json:"n"`
	S string `json:"s"`
	T string `json:"t"`
}

type Pubkey struct {
	X string `json:"x"`
	Y string `json:"y"`
}
type BK struct {
	X    string `json:"x"`
	Rank uint32 `json:"rank"`
}

type DKGResult struct {
	Share             string            `json:"share"`
	Pubkey            Pubkey            `json:"pubkey"`
	BKs               map[string]BK     `json:"bks"`
	Rid               string            `json:"rid"`
	PartialPublicKeys map[string]Pubkey `json:"partialPublicKeys"`
}

func dkresult2bytes(dkgR *dkg.Result, pks map[string]*ecpointgrouplaw.ECPoint) ([]byte, error) {
	dkgResult := &DKGResult{
		Share: dkgR.Share.String(),
		Pubkey: Pubkey{
			X: dkgR.PublicKey.GetX().String(),
			Y: dkgR.PublicKey.GetY().String(),
		},
		BKs:               make(map[string]BK),
		Rid:               hex.EncodeToString(dkgR.Rid),
		PartialPublicKeys: make(map[string]Pubkey),
	}
	for peerId, bk := range dkgR.Bks {
		dkgResult.BKs[peerId] = BK{
			X:    bk.GetX().String(),
			Rank: bk.GetRank(),
		}
	}

	for peerId, partialPublicKey := range pks {
		dkgResult.PartialPublicKeys[peerId] = Pubkey{
			X: partialPublicKey.GetX().String(),
			Y: partialPublicKey.GetY().String(),
		}
	}
	return json.Marshal(dkgResult)
}

type ReshareResult struct {
	DKGResult         `json:",omitempty,inline"`
	PartialPublicKeys map[string]Pubkey                 `json:"partialPublicKeys"`
	YSecret           string                            `json:"ySecret"`
	PaillierKey       PaillierKey                       `json:"paillierKey"`
	Y                 map[string]ECPoint                `json:"y"`
	PedParameters     map[string]PederssenOpenParameter `json:"pedParameters"`
}

func refresult2bytes(refR *refresh.Result, dkgR *DKGResult) ([]byte, error) {
	p, q := refR.PaillierKey.GetPQ()
	reshareResult := &ReshareResult{
		DKGResult: DKGResult{
			Share:             refR.Share.String(),
			PartialPublicKeys: make(map[string]Pubkey),
			BKs:               dkgR.BKs,
			Pubkey:            dkgR.Pubkey,
			Rid:               dkgR.Rid,
		},
		YSecret:       refR.YSecret.String(),
		PedParameters: make(map[string]PederssenOpenParameter),
		Y:             make(map[string]ECPoint),
		PaillierKey: PaillierKey{
			P: p.String(),
			Q: q.String(),
		},
	}

	for peerId, d := range refR.PartialPubKey {
		reshareResult.PartialPublicKeys[peerId] = Pubkey{
			X: d.GetX().String(),
			Y: d.GetY().String(),
		}
	}

	for peerId, d := range refR.PedParameter {
		reshareResult.PedParameters[peerId] = PederssenOpenParameter{
			N: d.GetN().String(),
			S: d.GetS().String(),
			T: d.GetT().String(),
		}
	}

	for peerId, d := range refR.Y {
		reshareResult.Y[peerId] = ECPoint{
			X: d.GetX().String(),
			Y: d.GetY().String(),
		}
	}
	return json.Marshal(reshareResult)
}

// ConvertDKGResult converts DKG result from config.
func ConvertDKGResult(cfgPubkey Pubkey, cfgShare string, cfgBKs map[string]BK, rid string, ppks map[string]Pubkey) (*dkg.Result, map[string]*ecpointgrouplaw.ECPoint, error) {
	// Build public key.
	r := map[string]*ecpointgrouplaw.ECPoint{}
	for peerId, pub := range ppks {
		p, err := convertECPoint(pub.X, pub.Y)
		if err != nil {
			loginfo("Cannot convert EC point", "err", err)
			return nil, nil, err
		}

		r[peerId] = p
	}
	x, ok := new(big.Int).SetString(cfgPubkey.X, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "x", cfgPubkey.X)
		return nil, nil, ErrConversion
	}
	y, ok := new(big.Int).SetString(cfgPubkey.Y, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "y", cfgPubkey.Y)
		return nil, nil, ErrConversion
	}
	pubkey, err := ecpointgrouplaw.NewECPoint(elliptic.Secp256k1(), x, y)
	if err != nil {
		loginfo("Cannot get public key", "err", err)
		return nil, nil, err
	}

	// Build share.
	share, ok := new(big.Int).SetString(cfgShare, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "share", share)
		return nil, nil, ErrConversion
	}

	rawRid, err := hex.DecodeString(rid)
	if err != nil {
		loginfo("Cannot get rid", "err", err)
		return nil, nil, err
	}

	dkgResult := &dkg.Result{
		PublicKey: pubkey,
		Share:     share,
		Bks:       make(map[string]*birkhoffinterpolation.BkParameter),
		Rid:       rawRid,
	}

	// Build bks.
	for peerID, bk := range cfgBKs {
		x, ok := new(big.Int).SetString(bk.X, 10)
		if !ok {
			loginfo("Cannot convert string to big int", "x", bk.X)
			return nil, nil, ErrConversion
		}
		dkgResult.Bks[peerID] = birkhoffinterpolation.NewBkParameter(x, bk.Rank)
	}

	return dkgResult, r, nil
}

// ConvertReshareResult converts the reshare result from config.
func ConvertReshareResult(cfgShare string, paillierKey PaillierKey, ySecret string, partialPubKeys map[string]Pubkey, y map[string]ECPoint, pedParams map[string]PederssenOpenParameter) (*refresh.Result, error) {
	r := &refresh.Result{
		PartialPubKey: make(map[string]*ecpointgrouplaw.ECPoint),
		Y:             make(map[string]*ecpointgrouplaw.ECPoint),
		PedParameter:  make(map[string]*paillierzkproof.PederssenOpenParameter),
	}

	// Build share.
	share, ok := new(big.Int).SetString(cfgShare, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "share", share)
		return nil, ErrConversion
	}

	r.Share = share

	ys, ok := new(big.Int).SetString(ySecret, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "share", share)
		return nil, ErrConversion
	}

	r.YSecret = ys

	p, ok := new(big.Int).SetString(paillierKey.P, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "p", paillierKey.P)
		return nil, ErrConversion
	}
	q, ok := new(big.Int).SetString(paillierKey.Q, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "q", paillierKey.Q)
		return nil, ErrConversion
	}

	var err error

	r.PaillierKey, err = paillier.NewPaillierWithGivenPrimes(p, q)
	if err != nil {
		loginfo("Cannot NewPaillierWithGivenPrimes from P and Q", "err", err)
		return nil, err
	}

	for peerId, pub := range partialPubKeys {
		p, err := convertECPoint(pub.X, pub.Y)
		if err != nil {
			loginfo("Cannot convert EC point", "err", err)
			return nil, err
		}

		r.PartialPubKey[peerId] = p
	}

	for peerId, yy := range y {
		p, err := convertECPoint(yy.X, yy.Y)
		if err != nil {
			loginfo("Cannot convert EC point", "err", err)
			return nil, err
		}

		r.Y[peerId] = p
	}

	for peerId, pp := range pedParams {
		n, ok := new(big.Int).SetString(pp.N, 10)
		if !ok {
			loginfo("Cannot convert string to big int", "n", pp.N)
			return nil, ErrConversion
		}
		s, ok := new(big.Int).SetString(pp.S, 10)
		if !ok {
			loginfo("Cannot convert string to big int", "s", pp.S)
			return nil, ErrConversion
		}
		t, ok := new(big.Int).SetString(pp.T, 10)
		if !ok {
			loginfo("Cannot convert string to big int", "t", pp.T)
			return nil, ErrConversion
		}

		r.PedParameter[peerId] = paillierzkproof.NewPedersenOpenParameter(n, s, t)
	}

	return r, nil
}

func convertECPoint(xx, yy string) (*ecpointgrouplaw.ECPoint, error) {
	// Build public key.
	x, ok := new(big.Int).SetString(xx, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "x", xx)
		return nil, ErrConversion
	}
	y, ok := new(big.Int).SetString(yy, 10)
	if !ok {
		loginfo("Cannot convert string to big int", "y", yy)
		return nil, ErrConversion
	}
	return ecpointgrouplaw.NewECPoint(elliptic.Secp256k1(), x, y)
}

var (
	// ErrConversion for big int conversion error
	ErrConversion = errors.New("conversion error")
)

// reshareResult := &ReshareResult{
// 	DKGResult: dkgexample.DKGResult{
// 		Share:             result.Share.String(),
// 		PartialPublicKeys: make(map[string]config.Pubkey),
// 		BKs:               cfg.BKs,
// 		Pubkey:            cfg.Pubkey,
// 		Rid:               cfg.Rid,
// 	},
// 	YSecret:       result.YSecret.String(),
// 	PedParameters: make(map[string]config.PederssenOpenParameter),
// 	Y:             make(map[string]config.ECPoint),
// 	PaillierKey: config.PaillierKey{
// 		P: p.String(),
// 		Q: q.String(),
// 	},
// }

// for peerId, d := range result.PartialPubKey {
// 	reshareResult.PartialPublicKeys[peerId] = config.Pubkey{
// 		X: d.GetX().String(),
// 		Y: d.GetY().String(),
// 	}
// }

// for peerId, d := range result.PedParameter {
// 	reshareResult.PedParameters[peerId] = config.PederssenOpenParameter{
// 		N: d.GetN().String(),
// 		S: d.GetS().String(),
// 		T: d.GetT().String(),
// 	}
// }

// for peerId, d := range result.Y {
// 	reshareResult.Y[peerId] = config.ECPoint{
// 		X: d.GetX().String(),
// 		Y: d.GetY().String(),
// 	}
// }
