package protocol

import (
	"fmt"
)

const requestedTransportSize = 4

const (
	TCP byte = 6
	UDP byte = 17
)

type RequestedTransport struct {
	Transport byte
}

func (r *RequestedTransport) Get(m *Message) error {
	v, ok := m.GetAttribute(AttributeTypeRequestedTransport)
	if !ok {
		return fmt.Errorf("no requested transport attribute")
	}

	if len(v) != requestedTransportSize {
		return fmt.Errorf("invalid requested transport attribute length")
	}

	r.Transport = v[0]
	return nil
}
