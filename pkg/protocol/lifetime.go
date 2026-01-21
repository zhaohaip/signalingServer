package protocol

import (
	"encoding/binary"
	"fmt"
	"time"
	"webRTCInfra/pkg/common"
)

const lifeTimeSize = 4

type LifeTime struct {
	LifeTime time.Duration
}

// Get 获取属性值
func (l *LifeTime) Get(m *Message) error {
	v, ok := m.GetAttribute(AttributeTypeLifetime)
	if !ok {
		return fmt.Errorf("no lifetime attribute")
	}

	if len(v) != lifeTimeSize {
		return fmt.Errorf("invalid lifetime attribute length")
	}

	_ = v[lifeTimeSize-1] // 触发长度边界检查
	seconds := binary.BigEndian.Uint32(v)
	l.LifeTime = time.Duration(seconds) * time.Second
	return nil
}

// GetLifeTime 获取有效期
func (l *LifeTime) GetLifeTime(m *Message) time.Duration {
	if err := l.Get(m); err == nil {
		if l.LifeTime < common.MaxLimitLifeTime {
			return l.LifeTime
		}
	}

	// 若客户端未设置有效期，或者有效期设置有误，则使用默认有效期
	l.LifeTime = common.DefaultLifeTime
	return l.LifeTime
}

func (l *LifeTime) AddTo(m *Message) {
	v := make([]byte, lifeTimeSize)
	binary.BigEndian.PutUint32(v, uint32(l.LifeTime.Seconds()))
	m.BuildAttribute(AttributeTypeLifetime, v)
}
