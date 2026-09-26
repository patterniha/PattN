package protocol

import "encoding/json"

const Version = 1

type Request struct {
	Version int             `json:"v"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Version int    `json:"v"`
	ID      string `json:"id,omitempty"`
	Event   string `json:"event,omitempty"`
	Data    any    `json:"data,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Capabilities struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Methods         []string `json:"methods"`
	NativeScanner   bool     `json:"nativeScanner"`
}
