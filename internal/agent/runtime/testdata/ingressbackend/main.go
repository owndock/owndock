package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const websocketMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func main() {
	body := os.Getenv("OWNDOCK_TEST_BACKEND_BODY")
	if body == "" {
		log.Fatal("OWNDOCK_TEST_BACKEND_BODY is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(response, body)
	})
	mux.HandleFunc("/stream", func(response http.ResponseWriter, request *http.Request) {
		flusher, ok := response.(http.Flusher)
		if !ok {
			http.Error(response, "stream unavailable", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(response, "stream-start:%s\n", body)
		flusher.Flush()
		for range 40 {
			select {
			case <-request.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
				_, _ = fmt.Fprintf(response, "stream-tick:%s:%d\n", body, time.Now().UnixNano())
				flusher.Flush()
			}
		}
		_, _ = fmt.Fprintf(response, "stream-end:%s\n", body)
	})
	mux.HandleFunc("/ws", func(response http.ResponseWriter, request *http.Request) {
		serveWebSocket(response, request, body)
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("ready")
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}

func serveWebSocket(response http.ResponseWriter, request *http.Request, body string) {
	key := request.Header.Get("Sec-WebSocket-Key")
	if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" || key == "" {
		http.Error(response, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		http.Error(response, "upgrade unavailable", http.StatusInternalServerError)
		return
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	acceptDigest := sha1.Sum([]byte(key + websocketMagic))
	if _, err := fmt.Fprintf(buffer,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(acceptDigest[:])); err != nil || buffer.Flush() != nil {
		return
	}
	for {
		payload, opcode, err := readWebSocketFrame(buffer)
		if err != nil || opcode == 0x8 {
			return
		}
		if opcode != 0x1 {
			return
		}
		message := append([]byte(body+":"), payload...)
		if len(message) > 125 || writeWebSocketFrame(connection, 0x1, message) != nil {
			return
		}
	}
}

func readWebSocketFrame(reader *bufio.ReadWriter) ([]byte, byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, 0, err
	}
	if header[0]&0x80 == 0 || header[1]&0x80 == 0 || header[1]&0x7f > 125 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(reader, mask); err != nil {
		return nil, 0, err
	}
	payload := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, 0, err
	}
	for index := range payload {
		payload[index] ^= mask[index%len(mask)]
	}
	return payload, header[0] & 0x0f, nil
}

func writeWebSocketFrame(connection net.Conn, opcode byte, payload []byte) error {
	frame := append([]byte{0x80 | opcode, byte(len(payload))}, payload...)
	_, err := connection.Write(frame)
	return err
}
