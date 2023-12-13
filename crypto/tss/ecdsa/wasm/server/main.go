package main

import (
	"fmt"

	"github.com/getamis/alice/types"
)

// var gLocker = &sync.RWMutex{}
// var allGroup = map[string]*groupData{}

func loginfo(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	fmt.Println(s)
}

// type groupData struct {
// 	dkg         *dkg.DKG
// 	dkgResult   *dkg.Result
// 	refre       *refresh.Refresh
// 	refreResult *refresh.Result
// 	signer      *sign.Sign
// 	wsconn      *websocket.Conn
// 	locker      *sync.RWMutex
// 	pPKs        map[string]ecpointgrouplaw.ECPoint
// 	l           *listener
// }

type listener struct {
	errCh chan error
}

func (l *listener) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		l.errCh <- fmt.Errorf("State %s -> %s", oldState.String(), newState.String())
		return
	} else if newState == types.StateDone {
		l.errCh <- nil
		return
	}
	loginfo("State changed, old: %v; new: %v", oldState.String(), newState.String())
}

func (l *listener) Done() <-chan error {
	return l.errCh
}

// var upgrader = websocket.Upgrader{
// 	CheckOrigin: func(r *http.Request) bool {
// 		return true // Accepting all requests
// 	},
// }

// func startServer() {
// 	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
// 		conn, err := upgrader.Upgrade(w, r, nil)
// 		if err != nil {
// 			loginfo("Error connecting to WebSocket server:%v", err)
// 			return
// 		}
// 		defer conn.Close()

// 		websocketID := conn.RemoteAddr().String()
// 		loginfo("Start listening client %v\n", websocketID)
// 		teleID := ""
// 		for {
// 			if err := handleMessage(conn, &teleID, websocketID); err != nil {
// 				panic(err)
// 				fmt.Printf("Websocket ID %v return err %v", websocketID, err)
// 				return
// 			}
// 		}
// 	})

// 	loginfo("Start Server %v", http.ListenAndServe(":8080", nil))
// }

// func handleMessage(conn *websocket.Conn, teleID *string, websocketID string) error {

// 	_, rawMsg, err := conn.ReadMessage()
// 	if err != nil {
// 		return err
// 	}
// 	loginfo("Got msg %v %v from %v", rawMsg, len(rawMsg), websocketID)

// 	wMsg, err := DeserializeWMsg(rawMsg)
// 	if err != nil {
// 		return err
// 	}
// 	switch wMsg.Type {
// 	case STARTKEYGEN:
// 		return handleStartKeyGen(conn, wMsg.Data, teleID, websocketID)
// 	case KEYGEN:
// 		return handleKeyGen(wMsg, teleID)
// 	case KEYGENOUTPUT:
// 		return handleKeyGenOut(wMsg, teleID)
// 	case STARTREFRESH:
// 		// return handleStartRefresh(msgBody, senderID, *gData)
// 	case STARTSIGN:
// 		// return handleStartSign(msgBody, senderID)
// 	case SIGN:
// 		// return handleStartSign(msgBody, senderID)
// 	case REF:
// 	default:
// 		fmt.Printf("Unknown message command: %v", wMsg.Type)
// 	}
// 	return nil
// }

// func processMessage(msg []byte) (senderID byte, msgCmd byte, msgBody []byte) {
// 	senderID = msg[0]
// 	msgCmd = msg[1]
// 	msgBody = msg[2:]
// 	return
// }

// func handleStartKeyGen(conn *websocket.Conn, msgBody []byte, teleID *string, websocketID string) error {
// 	*teleID = string(msgBody)
// 	fmt.Printf("Receive request start keygen for teleID %v from ws %v \n", *teleID, websocketID)
// 	err := NewDKGPerTelegramID(*teleID, "", conn)
// 	if err != nil {
// 		fmt.Printf("Cannot create new dkg err %v\n", err)
// 		return err
// 	}
// 	respMsg := WrapMsg{
// 		Type:     STARTKEYGEN,
// 		Data:     []byte("0"),
// 		SenderID: []byte("client2"),
// 	}
// 	respBytes, err := SerializeWMsg(&respMsg)
// 	if err != nil {
// 		fmt.Printf("Cannot create new dkg err %v\n", err)
// 		return err
// 	}
// 	wMsg := map[string]string{}
// 	wMsg["data"] = base64.StdEncoding.EncodeToString(respBytes)
// 	wMsg["receiverid"] = "client1"
// 	go StartDKGPerTelegramID(*teleID)
// 	gLocker.Lock()
// 	err = conn.WriteJSON(wMsg)
// 	gLocker.Unlock()
// 	if err != nil {
// 		fmt.Printf("Cannot write json %v\n", err)
// 		// wsconn = nil
// 		return err
// 	}
// 	panic("dd")
// 	return nil
// }

// func handleKeyGen(wMsg WrapMsg, teleID *string) error {

// 	fmt.Printf("data get from client %v %v \n", string(wMsg.SenderID), wMsg.Data)
// 	data := &dkg.Message{}
// 	err := proto.Unmarshal(wMsg.Data, data)
// 	if err != nil {
// 		fmt.Printf("Cannot proto unmarshal data err %v\n", err)
// 		// wsconn = nil
// 		return err
// 	}
// 	gLocker.RLock()
// 	gData, ok := allGroup[*teleID]
// 	gLocker.RUnlock()
// 	_ = ok
// 	loginfo("----------- sender %v %v -----------", string(wMsg.SenderID), gData.dkg.AddMessage(string(data.GetId()), data))
// 	return nil
// }

// func handleKeyGenOut(wMsg WrapMsg, teleID *string) error {
// 	gLocker.RLock()
// 	gData, ok := allGroup[*teleID]
// 	gLocker.RUnlock()
// 	_ = ok
// 	var msg ecpointgrouplaw.EcPointMessage
// 	err := proto.Unmarshal(wMsg.Data, &msg)
// 	if err != nil {
// 		loginfo("Cannot unmarshal proto message", "err", err)
// 		return err
// 	}

// 	p, err := msg.ToPoint()
// 	if err != nil {
// 		loginfo("Cannot convert to EcPoint", "err", err)
// 		return err
// 	}
// 	gData.pPKs[string(wMsg.SenderID)] = *p

// 	return nil
// }

// func handleStartSign(msgBody []byte, senderID byte) error {
// 	return nil
// }

// func handleStartRefresh(msgBody []byte, senderID byte, gData *groupData) error {

// 	return nil
// }

// func NewDKGPerTelegramID(teleID string, sID string, wsconn *websocket.Conn) error {
// 	gLocker.RLock()
// 	gData, ok := allGroup[teleID]
// 	if !ok {
// 		gData = &groupData{
// 			locker: &sync.RWMutex{},
// 			l: &listener{
// 				errCh: make(chan error, 10),
// 			},
// 			pPKs: make(map[string]ecpointgrouplaw.ECPoint),
// 		}
// 	}
// 	gLocker.RUnlock()

// 	dkgP, err := dkg.NewDKG(elliptic.Secp256k1(), NewPeerManager("client2", []string{"client1", "client3"}, gData), []byte(sID), 2, 0, gData.l)
// 	if err != nil {
// 		return err
// 	}
// 	gData.dkg = dkgP
// 	gData.wsconn = wsconn
// 	gLocker.Lock()
// 	allGroup[teleID] = gData
// 	gLocker.Unlock()

// 	return nil
// }

// func StartDKGPerTelegramID(teleID string) error {
// 	gLocker.RLock()
// 	gData, ok := allGroup[teleID]
// 	gLocker.RUnlock()
// 	if !ok {
// 		return errors.Errorf("DKG for tele %v is not init yet", teleID)
// 	}
// 	gData.dkg.Start()
// 	defer gData.dkg.Stop()
// 	time.Sleep(500 * time.Millisecond)
// 	gData.dkg.BroadcastFisrtMsg()
// 	//gData.dkg.BroadcastFisrtMsg()
// 	if err := <-gData.l.Done(); err != nil {
// 		panic(err)
// 	} else {
// 		loginfo("DKG done!\n")
// 		gData.dkgResult, err = gData.dkg.GetResult()
// 		if err != nil {
// 			return err
// 		}
// 		p := *ecpointgrouplaw.ScalarBaseMult(elliptic.Secp256k1(), gData.dkgResult.Share)
// 		gData.pPKs["client2"] = p

// 		pkPointMsg, err := p.ToEcPointMessage()
// 		pkBytes, err := proto.Marshal(pkPointMsg)
// 		if err != nil {
// 			return err
// 		}
// 		msgOutput := WrapMsg{
// 			Type:     KEYGENOUTPUT,
// 			SenderID: []byte("client2"),
// 			Data:     pkBytes,
// 		}
// 		msgBytes, err := SerializeWMsg(&msgOutput)
// 		if err != nil {
// 			return err
// 		}

// 		if gData.wsconn != nil {
// 			wMsg := map[string]string{}
// 			wMsg["data"] = base64.StdEncoding.EncodeToString(msgBytes)
// 			wMsg["receiverid"] = "client1"
// 			gLocker.Lock()
// 			err := gData.wsconn.WriteJSON(wMsg)
// 			gLocker.Unlock()
// 			loginfo("Error send: %v", err)
// 			fmt.Printf("Trying to send %v %v\n", wMsg, err)
// 		}
// 	}
// 	gLocker.Lock()
// 	allGroup[teleID] = gData
// 	gLocker.Unlock()
// 	return nil
// }

func main() {
	// var err error
	sm := NewServiceManager()

	wsServer := NewWebSocketServer(":8080")
	wsServer.AddListener(sm.NewClient)
	go wsServer.Start()
	go sm.WatchRegister()

	select {}
}
