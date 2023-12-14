package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/sign"
	"github.com/getamis/alice/types"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

type ConnectionData struct {
	TeleID   string
	WSClient *Client
}

type Service struct {
	DKGResult     *dkg.Result
	PPKs          map[string]*ecpointgrouplaw.ECPoint
	ReShareResult *refresh.Result
	ConnData      *ConnectionData
}

func NewService() *Service {
	return &Service{
		DKGResult:     nil,
		PPKs:          make(map[string]*ecpointgrouplaw.ECPoint),
		ReShareResult: nil,
	}
}

func (s *Service) SetConnData(cData *ConnectionData) {
	s.ConnData = cData
}

type ServiceManager struct {
	ServiceByTeleID  map[string]*Service
	ServiceByTeleIDL *sync.RWMutex
	NewClient        chan *Client
}

func NewServiceManager() *ServiceManager {
	return &ServiceManager{
		ServiceByTeleID:  map[string]*Service{},
		ServiceByTeleIDL: &sync.RWMutex{},
		NewClient:        make(chan *Client, 128),
	}
}

func (s *ServiceManager) WatchRegister() {
	for c := range s.NewClient {
		loginfo("Got new connection, start handle it.")
		go s.handleConn(c)
	}
}

func (s *ServiceManager) handleConn(c *Client) {
	var (
		wMsg WrapMsg
	)
	for {
		_, rawMsg, err := c.conn.ReadMessage()
		if err != nil {
			loginfo("Can not get msg from server %v\n", err)
			if _, _, err := c.conn.NextReader(); err != nil {
				c.conn.Close()
				break
			}
			continue
		}
		wMsg, err = DeserializeWMsg(rawMsg)
		if err != nil {
			loginfo("Can not DeserializeWMsg %v %v\n", rawMsg, err)
			continue
		}
		loginfo("Got msg %v ", wMsg)
		if wMsg.Type != REGISTER {
			loginfo("Wrong msg type, wanted %v, got %v", REGISTER, wMsg.Type)
			continue
		}
		break
	}
	teleID := string(wMsg.SenderID)
	cData := &ConnectionData{
		TeleID:   teleID,
		WSClient: c,
	}
	service, ok := s.ServiceByTeleID[teleID]
	if !ok {
		service = NewService()
	}
	service.ConnData = cData
	s.ServiceByTeleID[teleID] = service
	loginfo("Start service for tele %v, conn %v.", teleID, c.conn.RemoteAddr().String())
	go service.Start()
}

func (s *Service) Start() {
	loginfo("Start service for %v", s.ConnData.TeleID)
	defer s.ConnData.WSClient.close()
	incoming := make(chan []byte, 32)
	go s.ConnData.WSClient.readPump(incoming)
	go s.ConnData.WSClient.writePump()
	defer s.ConnData.WSClient.close()
	loginfo("wait for new msg")
	for msg := range incoming {
		wMsg, err := DeserializeWMsg(msg)
		if err != nil {
			loginfo("Can not DeserializeWMsg %v\n", msg)
			return
		}
		loginfo("Got new msg in start %v", wMsg.Type)
		switch wMsg.Type {
		case STARTKEYGEN:
			sID := string(wMsg.Data)
			st := time.Now()
			err := s.StartKeyGen(sID, incoming)
			if err != nil {
				loginfo("Can not start keygen for %v - %v, err %v", sID, s.ConnData.TeleID, err)
				return
			}
			loginfo("Keygen done. cost %v", time.Since(st))
			// return
		case STARTREFRESH:
			sID := string(wMsg.Data)
			st := time.Now()
			err := s.StartRef(sID, incoming)
			if err != nil {
				loginfo("Can not start ref for %v - %v, err %v", sID, s.ConnData.TeleID, err)
				return
			}
			loginfo("ref done. cost %v", time.Since(st))
			// return
		case STARTSIGN:
			sID := string(wMsg.Data)
			st := time.Now()
			err := s.StartSign(sID, incoming)
			if err != nil {
				loginfo("Can not start sign for %v - %v, err %v", sID, s.ConnData.TeleID, err)
				return
			}
			loginfo("sign done. cost %v", time.Since(st))
		default:
			fmt.Printf("Unknown message command: %v", wMsg.Type)
		}
	}

}
func (s *Service) StartKeyGen(sID string, incoming chan []byte) error {
	loginfo("Start KeyGen for %v %v", s.ConnData.TeleID, sID)
	l := &listener{
		errCh: make(chan error, 10),
	}
	dkgP, err := dkg.NewDKG(elliptic.Secp256k1(), NewPeerManager("client2", []string{"client1", "client3"}, s.ConnData.WSClient, KEYGEN), []byte(sID), 2, 0, l)
	if err != nil {
		loginfo("Can not create new DKG for %v, error %v", s.ConnData.TeleID, err)
		return err
	}
	loginfo("Got new dkg")
	go dkgP.Start()
	defer dkgP.Stop()
	respMsg := WrapMsg{
		Type:     STARTKEYGEN,
		Data:     []byte("0"),
		SenderID: []byte("client2"),
	}
	s.ConnData.WSClient.sendMessage(respMsg.ToWSMsg("client1"))
	dkgP.BroadcastFisrtMsg()
	isDone := false
	for !isDone {
		select {
		case msg := <-incoming:
			wMsg, err := DeserializeWMsg(msg)
			loginfo("Got new msg in start %v", wMsg.Type)
			if err != nil {
				loginfo("Can not DeserializeWMsg %v\n", msg)
				return err
			}
			if wMsg.Type != KEYGEN {
				continue
			}
			data := &dkg.Message{}
			err = proto.Unmarshal(wMsg.Data, data)
			if err != nil {
				loginfo("Cannot proto unmarshal data err %v\n", err)
				return err
			}
			err = dkgP.AddMessage(string(wMsg.SenderID), data)
			if err != nil {
				loginfo("Cannot proto unmarshal data err %v\n", err)
				return err
			}
		case err := <-l.Done():
			if err != nil {
				return err
			}
			loginfo("DKG done!")
			isDone = true
		default:
		}
	}
	res, err := dkgP.GetResult()
	if err != nil {
		return errors.Errorf("Can not get result after genkey done for %v sID %v, err %v", s.ConnData.TeleID, sID, err)
	}
	return s.GetKeygenOutput(res, incoming)

}

func (s *Service) StartRef(sID string, incoming chan []byte) error {
	loginfo("Start Ref for %v %v", s.ConnData.TeleID, sID)
	l := &listener{
		errCh: make(chan error, 10),
	}
	st := time.Now()
	ssid := cggmp.ComputeSSID([]byte(sID), []byte(s.DKGResult.Bks["client2"].String()), s.DKGResult.Rid)
	loginfo("Computed ssid %v cost %v", "client2", time.Since(st))
	l = &listener{
		errCh: make(chan error, 10),
	}

	refP, err := refresh.NewRefresh(s.DKGResult.Share, s.DKGResult.PublicKey, NewPeerManager("client2", []string{"client1", "client3"}, s.ConnData.WSClient, REF), 2, s.PPKs, s.DKGResult.Bks, 2048, ssid, l)
	if err != nil {
		loginfo("Cannot create a new reshare core client2 err", err)
		return err
	}
	loginfo("Init ref cost %v", time.Since(st))

	loginfo("Got new Ref core")
	go refP.Start()
	defer refP.Stop()
	respMsg := WrapMsg{
		Type:     STARTREFRESH,
		Data:     []byte("0"),
		SenderID: []byte("client2"),
	}
	s.ConnData.WSClient.sendMessage(respMsg.ToWSMsg("client1"))
	refP.BroadcastFisrtMsg()
	isDone := false
	for !isDone {
		select {
		case msg := <-incoming:
			wMsg, err := DeserializeWMsg(msg)
			loginfo("Got new msg in start %v", wMsg.Type)
			if err != nil {
				loginfo("Can not DeserializeWMsg %v\n", msg)
				return err
			}
			if wMsg.Type != REF {
				loginfo("Got wrong msg type %v in start", wMsg.Type)
				continue
			}
			data := &refresh.Message{}
			err = proto.Unmarshal(wMsg.Data, data)
			if err != nil {
				loginfo("Cannot proto unmarshal data err %v\n", err)
				return err
			}
			err = refP.AddMessage(string(wMsg.SenderID), data)
			if err != nil {
				loginfo("Cannot proto unmarshal data err %v\n", err)
				return err
			}
		case err := <-l.Done():
			if err != nil {
				return err
			}
			loginfo("Ref done!")
			isDone = true
		default:
		}
	}
	s.ReShareResult, err = refP.GetResult()
	if err != nil {
		return errors.Errorf("Can not get result after ref done for %v sID %v, err %v", s.ConnData.TeleID, sID, err)
	}
	return nil

}

func (s *Service) StartSign(sID string, incoming chan []byte) error {
	msg := "helloworld"
	loginfo("Start Sign for %v %v", s.ConnData.TeleID, sID)
	l := &listener{
		errCh: make(chan error, 10),
	}

	st := time.Now()
	ssid := cggmp.ComputeSSID([]byte(sID), []byte(s.DKGResult.Bks["client2"].String()), s.DKGResult.Rid)
	loginfo("Computed ssid %v cost %v", "client2", time.Since(st))
	l = &listener{
		errCh: make(chan error, 10),
	}
	refR := s.ReShareResult
	dkgR := s.DKGResult
	delete(dkgR.Bks, "client3")
	delete(refR.PedParameter, "client3")
	delete(refR.PartialPubKey, "client3")
	signP, err := sign.NewSign(
		2,
		ssid,
		refR.Share,
		dkgR.PublicKey,
		refR.PartialPubKey,
		refR.PaillierKey,
		refR.PedParameter,
		dkgR.Bks,
		[]byte(msg),
		NewPeerManager("client2", []string{"client1"}, s.ConnData.WSClient, SIGN),
		l,
	)

	if err != nil {
		loginfo("Cannot create a new reshare core client2 err", err)
		return err
	}
	loginfo("Init ref cost %v", time.Since(st))

	loginfo("Got new Ref core")
	go signP.Start()
	defer signP.Stop()
	respMsg := WrapMsg{
		Type:     STARTSIGN,
		Data:     []byte("0"),
		SenderID: []byte("client2"),
	}
	s.ConnData.WSClient.sendMessage(respMsg.ToWSMsg("client1"))
	signP.BroadcastFisrtMsg()
	isDone := false
	for !isDone {
		select {
		case msg := <-incoming:
			wMsg, err := DeserializeWMsg(msg)
			loginfo("Got new msg in start %v", wMsg.Type)
			if err != nil {
				loginfo("Can not DeserializeWMsg %v\n", msg)
				return err
			}
			if wMsg.Type != SIGN {
				loginfo("Got wrong msg type %v in start", wMsg.Type)
				continue
			}
			data := &sign.Message{}
			err = proto.Unmarshal(wMsg.Data, data)
			if err != nil {
				loginfo("Cannot proto unmarshal data err %v\n", err)
				return err
			}
			err = signP.AddMessage(string(wMsg.SenderID), data)
			if err != nil {
				loginfo("Cannot proto unmarshal data err %v\n", err)
				return err
			}
		case err := <-l.Done():
			if err != nil {
				return err
			}
			loginfo("Sign done!")
			isDone = true
		default:
		}
	}
	sig, err := signP.GetResult()
	if err != nil {
		return errors.Errorf("Can not get result after ref done for %v sID %v, err %v", s.ConnData.TeleID, sID, err)
	}
	loginfo("Got %v %v ", sig.R.Bytes(), sig.S.Bytes())
	return nil

}

func (s *Service) GetKeygenOutput(res *dkg.Result, incoming chan []byte) error {
	pPKs := map[string]*ecpointgrouplaw.ECPoint{}

	pPK := *ecpointgrouplaw.ScalarBaseMult(elliptic.Secp256k1(), res.Share)
	pPKs["client2"] = &pPK
	pkPointMsg, err := pPK.ToEcPointMessage()
	if err != nil {
		loginfo("Can not protoMarshal ECPoint, err %v", err)
		return errors.Errorf("Can not protoMarshal ECPoint, err %v", err)
	}
	pkBytes, err := proto.Marshal(pkPointMsg)
	if err != nil {
		loginfo("Can not protoMarshal ECPoint, err %v", err)
		return errors.Errorf("Can not protoMarshal ECPoint, err %v", err)
	}
	msgOutput := WrapMsg{
		Type:     KEYGENOUTPUT,
		SenderID: []byte("client2"),
		Data:     pkBytes,
	}
	s.ConnData.WSClient.sendMessage(msgOutput.ToWSMsg("client1"))
	oCounter := 0
	timeout := time.NewTimer(600 * time.Second)
	for {
		select {
		case msg := <-incoming:
			wMsg, err := DeserializeWMsg(msg)
			if err != nil {
				loginfo("Can not DeserializeWMsg %v\n", msg)
				return err
			}
			if wMsg.Type != KEYGENOUTPUT {
				continue
			}
			var msgOut ecpointgrouplaw.EcPointMessage
			err = proto.Unmarshal(wMsg.Data, &msgOut)
			if err != nil {
				loginfo("Cannot unmarshal proto message err %v", err)
				return err
			}
			op, err := msgOut.ToPoint()
			if err != nil {
				loginfo("Cannot convert to EcPoint, err %v", err)
				return err
			}
			pPKs[string(wMsg.SenderID)] = op
			oCounter++

		case <-timeout.C:
			return errors.Errorf("Time out")
		default:
		}
		if oCounter == 2 {
			s.DKGResult = res
			s.PPKs = pPKs
			break
		}
	}
	return nil
}

type listener struct {
	errCh chan error
}

func (l *listener) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		l.errCh <- errors.Errorf("State %s -> %s", oldState.String(), newState.String())
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
