//go:build linux

package goexporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	rawPlaneLLite   uint8 = 1
	rawPlanePtlRPC  uint8 = 2
	rawOpLookup     uint8 = 1
	rawOpOpen       uint8 = 2
	rawOpRead       uint8 = 3
	rawOpWrite      uint8 = 4
	rawOpFsync      uint8 = 5
	rawOpQueueWait  uint8 = 6
	rawOpSendNewReq uint8 = 7
	rawOpFreeReq    uint8 = 8
)

type rawEvent struct {
	Plane      uint8
	Op         uint8
	_          [6]byte
	UID        uint32
	PID        uint32
	_          uint32
	DurationUS uint64
	SizeBytes  uint64
	RequestPtr uint64
	Comm       [16]byte
}

type bpfConfig struct {
	TargetMajor uint32
	TargetMinor uint32
}

type linuxEventSource struct {
	events     chan Event
	reader     *perf.Reader
	collection *ebpf.Collection
	links      []link.Link
	once       sync.Once
	done       chan struct{}
	started    bool
}

func newEventSource(ctx context.Context, cfg Config, mountInfo MountInfo) (EventSource, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	if cfg.BPFObjectPath == "" {
		return nil, fmt.Errorf("--bpf-object is required")
	}
	if _, err := os.Stat(cfg.BPFObjectPath); err != nil {
		return nil, err
	}

	required := []probeSpec{
		{"ll_lookup_nd", "ll_lookup_nd_enter", false, false},
		{"ll_file_open", "ll_file_open_enter", false, false},
		{"ll_file_read_iter", "ll_file_read_iter_enter", false, false},
		{"ll_file_write_iter", "ll_file_write_iter_enter", false, false},
		{"ll_fsync", "ll_fsync_enter", false, false},
	}
	optional := []probeSpec{
		{"ptlrpc_queue_wait", "ptlrpc_queue_wait_enter", false, true},
		{"ptlrpc_queue_wait", "ptlrpc_queue_wait_exit", true, true},
		{"ptlrpc_send_new_req", "ptlrpc_send_new_req_enter", false, true},
		{"__ptlrpc_free_req", "ptlrpc_free_req_enter", false, true},
	}

	spec, err := ebpf.LoadCollectionSpec(cfg.BPFObjectPath)
	if err != nil {
		return nil, err
	}
	collection, skippedPrograms, err := loadCollectionWithOptionalPrograms(spec, optional)
	if err != nil {
		return nil, err
	}
	if len(skippedPrograms) > 0 {
		log.Printf("warning: disabled optional BPF programs after load failure: %s", strings.Join(skippedPrograms, ", "))
	}

	configMap := collection.Maps["config_map"]
	if configMap == nil {
		collection.Close()
		return nil, fmt.Errorf("config_map not found in %s", cfg.BPFObjectPath)
	}
	key := uint32(0)
	value := bpfConfig{TargetMajor: mountInfo.Major, TargetMinor: mountInfo.Minor}
	if err := configMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
		collection.Close()
		return nil, err
	}

	reader, err := perf.NewReader(collection.Maps["events"], os.Getpagesize()*8)
	if err != nil {
		collection.Close()
		return nil, err
	}

	source := &linuxEventSource{
		events:     make(chan Event, 1024),
		reader:     reader,
		collection: collection,
		done:       make(chan struct{}),
	}

	if err := source.attachAll(required, false); err != nil {
		source.Close()
		return nil, err
	}
	if err := source.attachAll(optional, false); err != nil {
		source.Close()
		return nil, err
	}

	source.started = true
	go source.readLoop(ctx)
	return source, nil
}

type probeSpec struct {
	symbol   string
	program  string
	ret      bool
	optional bool
}

func (s *linuxEventSource) attachAll(specs []probeSpec, allowMissing bool) error {
	for _, spec := range specs {
		prog := s.collection.Programs[spec.program]
		if prog == nil {
			if spec.optional || allowMissing {
				log.Printf("warning: BPF program %s not found", spec.program)
				continue
			}
			return fmt.Errorf("required BPF program missing: %s", spec.program)
		}
		var (
			lnk link.Link
			err error
		)
		if spec.ret {
			lnk, err = link.Kretprobe(spec.symbol, prog, nil)
		} else {
			lnk, err = link.Kprobe(spec.symbol, prog, nil)
		}
		if err != nil {
			if spec.optional || allowMissing || isMissingSymbolError(err) {
				log.Printf("warning: skipping probe %s/%s: %v", spec.symbol, spec.program, err)
				continue
			}
			return err
		}
		s.links = append(s.links, lnk)
	}
	return nil
}

func (s *linuxEventSource) readLoop(ctx context.Context) {
	defer close(s.events)
	defer close(s.done)
	for {
		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("warning: perf event read failed: %v", err)
				continue
			}
		}
		if record.LostSamples > 0 {
			log.Printf("warning: lost %d perf samples", record.LostSamples)
			continue
		}
		event, err := decodeRawEvent(record.RawSample)
		if err != nil {
			log.Printf("warning: decode raw event: %v", err)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case s.events <- event:
		}
	}
}

func (s *linuxEventSource) Events() <-chan Event {
	return s.events
}

func (s *linuxEventSource) Close() error {
	var closeErr error
	s.once.Do(func() {
		if s.reader != nil {
			closeErr = errors.Join(closeErr, s.reader.Close())
		}
		for _, lnk := range s.links {
			closeErr = errors.Join(closeErr, lnk.Close())
		}
		if s.collection != nil {
			s.collection.Close()
		}
		if s.started {
			<-s.done
		}
	})
	return closeErr
}

func decodeRawEvent(sample []byte) (Event, error) {
	var raw rawEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return Event{}, err
	}
	plane, err := planeName(raw.Plane)
	if err != nil {
		return Event{}, err
	}
	op, err := opName(raw.Op)
	if err != nil {
		return Event{}, err
	}
	return Event{
		Plane:      plane,
		Op:         op,
		UID:        raw.UID,
		PID:        raw.PID,
		Comm:       strings.TrimRight(string(raw.Comm[:]), "\x00"),
		DurationUS: raw.DurationUS,
		SizeBytes:  raw.SizeBytes,
		RequestPtr: raw.RequestPtr,
	}, nil
}

func planeName(raw uint8) (string, error) {
	switch raw {
	case rawPlaneLLite:
		return PlaneLLite, nil
	case rawPlanePtlRPC:
		return PlanePtlRPC, nil
	default:
		return "", fmt.Errorf("unknown plane code: %d", raw)
	}
}

func opName(raw uint8) (string, error) {
	switch raw {
	case rawOpLookup:
		return OpLookup, nil
	case rawOpOpen:
		return OpOpen, nil
	case rawOpRead:
		return OpRead, nil
	case rawOpWrite:
		return OpWrite, nil
	case rawOpFsync:
		return OpFsync, nil
	case rawOpQueueWait:
		return OpQueueWait, nil
	case rawOpSendNewReq:
		return OpSendNewReq, nil
	case rawOpFreeReq:
		return OpFreeReq, nil
	default:
		return "", fmt.Errorf("unknown op code: %d", raw)
	}
}

func isMissingSymbolError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no such file") || strings.Contains(msg, "symbol") || strings.Contains(msg, "not found")
}

func loadCollectionWithOptionalPrograms(spec *ebpf.CollectionSpec, optional []probeSpec) (*ebpf.Collection, []string, error) {
	collection, err := ebpf.NewCollection(spec)
	if err == nil {
		return collection, nil, nil
	}

	specCopy := spec.Copy()
	var skipped []string
	for _, probe := range optional {
		if _, ok := specCopy.Programs[probe.program]; ok {
			delete(specCopy.Programs, probe.program)
			skipped = append(skipped, probe.program)
		}
	}
	if len(skipped) == 0 {
		return nil, nil, err
	}

	collection, retryErr := ebpf.NewCollection(specCopy)
	if retryErr != nil {
		return nil, nil, err
	}
	return collection, skipped, nil
}
