package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

type peerManager struct {
	msgType byte
	c       *Client
	id      string
	ids     []string
}

func NewPeerManager(selfID string, ids []string, c *Client, msgType byte) *peerManager {
	return &peerManager{
		msgType: msgType,
		c:       c,
		id:      selfID,
		ids:     ids,
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
	loginfo("Got request sending to %v msg Type %v", peerId, p.msgType)
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

	p.c.sendMessage(wMsg.ToWSMsg(peerId))
}

// EnsureAllConnected connects the host to specified peer and sends the message to it.
func (p *peerManager) EnsureAllConnected() {
}

// AddPeer adds a peer to the peer list.
func (p *peerManager) AddPeer(peerId string, peerAddr string) {
	// p.peers[peerId] = peerAddr
}

// Client represents a connected WebSocket client
type Client struct {
	sid        string
	conn       *websocket.Conn
	sendChan   chan interface{}
	closed     chan struct{}
	closeMutex *sync.Mutex
	isClosed   bool
}

// NewClient creates a new Client instance
func NewClient(conn *websocket.Conn) *Client {
	return &Client{
		sid:        uuid.NewString(),
		conn:       conn,
		sendChan:   make(chan interface{}),
		closed:     make(chan struct{}),
		isClosed:   false,
		closeMutex: &sync.Mutex{},
	}
}

// close safely closes the WebSocket connection
func (c *Client) close() {
	c.closeMutex.Lock()
	defer c.closeMutex.Unlock()
	if c.isClosed {
		return
	}
	c.isClosed = true
	c.closed <- struct{}{}
	c.conn.Close()
	close(c.closed)
}

// readPump reads messages from the WebSocket connection
func (c *Client) readPump(out chan []byte) {
	loginfo("%v Start readPump ", c.sid)
	defer c.close()

	for {
		select {
		case <-c.closed:
			// Exit if the connection is closed
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				loginfo("%v Error reading message: %v", c.sid, err)
				return
			}
			// log.Printf("Received: %s", ?)
			out <- message
		}
	}
}

// writePump sends messages to the WebSocket connection
func (c *Client) writePump() {
	loginfo("%v Start WritePump", c.sid)
	defer c.close()
	for {
		loginfo("%v Wait for new outgoing msg", c.sid)
		select {
		case message, ok := <-c.sendChan:
			loginfo("%v Got new request send to %v", c.sid, c.conn.RemoteAddr().String())
			if !ok {
				loginfo("%v channel is already closed", c.sid)
				// The channel is closed

				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteJSON(message); err != nil {
				loginfo("%v Can not write, err %v", c.sid, err)
				return
			}
		case <-c.closed:
			loginfo("%v connection is closed", c.sid)
			return
		}
	}
}

// sendMessage safely sends a message to the client
func (c *Client) sendMessage(message interface{}) {
	if c.isClosed {
		return
	}
	c.sendChan <- message
}

// WebSocketServer represents the WebSocket server
type WebSocketServer struct {
	addr         string
	upgrader     websocket.Upgrader
	connListener []chan *Client
}

// NewWebSocketServer creates a new WebSocketServer
func NewWebSocketServer(addr string) *WebSocketServer {
	return &WebSocketServer{
		addr: addr,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Accepting all requests
			},
		},
		connListener: []chan *Client{},
	}
}

// handleConnection handles incoming WebSocket connections
func (ws *WebSocketServer) handleConnection(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {
		conn, err := ws.upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Error upgrading to WebSocket:", err)
			return
		}
		client := NewClient(conn)
		loginfo("Got new connection %v from %v, finding listener and send to them.", client.sid, r.RemoteAddr)
		if len(ws.connListener) == 0 {
			loginfo("Dont have any listener")
		}
		for i, l := range ws.connListener {
			loginfo("Sent %v to listener %v", i, client.sid)
			l <- client
		}

		// // Example usage: send a welcome message
		// for !client.isClosed {
		// }
	} else {
		w.Write([]byte("Hello from non-WebSocket request!"))
	}
}

func (ws *WebSocketServer) AddListener(l chan *Client) {
	ws.connListener = append(ws.connListener, l)
}

// Start starts the WebSocket server
func (ws *WebSocketServer) Start() {
	http.HandleFunc("/", ws.handleConnection)
	log.Fatal(http.ListenAndServe(ws.addr, nil))
}
