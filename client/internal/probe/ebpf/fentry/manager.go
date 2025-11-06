package fentry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

/**
代码构建思路，参考官方用例
	1. 设置资源限制
	2. 加载eBPF程序
	3. 挂载eBPF程序
	4. 创建ringbuf读取器
	5. 启动一个goroutine来读取事件，并且将事件发送到通道
	6. 提供一个goroutine方法来关闭所有资源

	需要定义一个事件结构体并且与eBPF程序中的事件结构体对应，请参考由bpf2go生成的代码中的结构体
*/

// TCPConnectEvent TCP连接事件
type TCPConnectEvent struct {
	Comm      string    `json:"comm"`      // 进程名
	SrcAddr   string    `json:"src_addr"`  // 源IP地址
	SrcPort   uint16    `json:"src_port"`  // 源端口
	DestAddr  string    `json:"dest_addr"` // 目标IP地址
	DestPort  uint16    `json:"dest_port"` // 目标端口
	Timestamp time.Time `json:"timestamp"` // 事件事件
}

// FentryManager 向外部提供接口
type FentryManager struct {
	objs      *bpfObjects
	link      link.Link
	reader    *ringbuf.Reader
	eventChan chan *TCPConnectEvent
	running   bool
}

// NewFentryManager 创建新的 fentry 管理器
func NewFentryManager() (*FentryManager, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing resources: %w", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	lnk, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TcpConnect,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("link tracing options: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		lnk.Close()
		objs.Close()
		return nil, fmt.Errorf("opening ringbuf reader: %s", err)
	}

	manager := &FentryManager{
		objs:      &objs,
		link:      lnk,
		reader:    rd,
		eventChan: make(chan *TCPConnectEvent, 100),
		running:   false,
	}

	return manager, nil
}

// Start 开始监控TCP连接事件
func (m *FentryManager) Start() error {
	if m.running {
		return fmt.Errorf("already running")
	}
	m.running = true

	// 启动事件循环处理
	go m.eventLoop()

	log.Println("The Fentry TCP Connection Monitoring Manager has been started.")
	return nil
}

// Stop 停止监控
func (m *FentryManager) Stop() {
	if !m.running {
		return
	}

	m.running = false
	log.Println("The Fentry TCP Connection Monitoring Manager has been stopped.")
}

// Close
func (m *FentryManager) Close() error {
	m.Stop()

	if m.reader != nil {
		m.reader.Close()
	}
	if m.link != nil {
		m.link.Close()
	}
	if m.objs != nil {
		m.objs.Close()
	}

	return nil
}

// eventLoop
func (m *FentryManager) eventLoop() {
	defer close(m.eventChan)

	for {
		if !m.running {
			return
		}

		//读取ringbuf事件
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Println("read ringbuf error:", err)
			continue
		}

		event, err := m.parseEvent(record.RawSample)
		if err != nil {
			log.Printf("parase error: %v", err)
			continue
		}

		// 发送事件到通道
		select {
		case m.eventChan <- event:
			//成功发送
		default:
			log.Println("event channel is full, dropping event: %v", event)
		}
	}
}

func (m *FentryManager) parseEvent(data []byte) (*TCPConnectEvent, error) {
	var rawEvent bpfEvent
	if err := binary.Read(bytes.NewBuffer(data), binary.BigEndian, &rawEvent); err != nil {
		return nil, fmt.Errorf("binary read: %w", err)
	}

	event := &TCPConnectEvent{
		Comm:      string(rawEvent.Comm[:]), // 转换字节数组为字符串
		SrcAddr:   intToIP(rawEvent.Saddr).String(),
		SrcPort:   rawEvent.Sport,
		DestAddr:  intToIP(rawEvent.Daddr).String(),
		DestPort:  rawEvent.Dport,
		Timestamp: time.Now(),
	}

	// 清理进程名中的空字符
	event.Comm = cleanComm(event.Comm)

	return event, nil
}

func cleanComm(comm string) string {
	for i, c := range comm {
		if c == 0 {
			return comm[:i]
		}
	}
	return comm
}

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

// FormatEvent
func FormatEvent(event *TCPConnectEvent) string {
	return fmt.Sprintf("%s %-15s:%-6d -> %-15s:%-6d [%s]",
		event.Comm,
		event.SrcAddr, event.SrcPort,
		event.DestAddr, event.DestPort,
		event.Timestamp.Format("15:04:05"))
}

// Events 将事件暴露出去，详见测试代码ebpf_fentry_test
func (m *FentryManager) Events() <-chan *TCPConnectEvent {
	return m.eventChan
}
