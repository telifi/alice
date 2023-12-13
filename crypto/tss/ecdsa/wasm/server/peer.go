package main

import (
	"log"
	"net/http"
	"sync"

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
	conn       *websocket.Conn
	sendChan   chan interface{}
	closed     chan struct{}
	closeMutex *sync.Mutex
	isClosed   bool
}

// NewClient creates a new Client instance
func NewClient(conn *websocket.Conn) *Client {
	return &Client{
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
	close(c.closed)
	c.conn.Close()
}

// readPump reads messages from the WebSocket connection
func (c *Client) readPump(out chan []byte) {
	log.Println("Start readPump")
	defer c.close()

	for {
		select {
		case <-c.closed:
			// Exit if the connection is closed
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				log.Println("Error reading message:", err)
				return
			}
			// log.Printf("Received: %s", ?)
			out <- message
		}
	}
}

// writePump sends messages to the WebSocket connection
func (c *Client) writePump() {
	loginfo("Start WritePump")
	defer c.close()
	for {
		loginfo("Wait for new outgoing msg")
		select {
		case message, ok := <-c.sendChan:
			loginfo("Got new request send to %v", c.conn.RemoteAddr().String())
			if !ok {
				loginfo("channel is already closed")
				// The channel is closed
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteJSON(message); err != nil {
				loginfo("Can not write %v", err)
				return
			}
		case <-c.closed:
			loginfo("connection is closed")
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
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading to WebSocket:", err)
		return
	}

	client := NewClient(conn)
	if len(ws.connListener) == 0 {
		loginfo("Dont have any listener")
	}
	for _, l := range ws.connListener {
		l <- client
	}

	// Example usage: send a welcome message
	for !client.isClosed {
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
