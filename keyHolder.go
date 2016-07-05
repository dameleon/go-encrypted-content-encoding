package main

import (
	"errors"
)

type keyHolder struct {
	keys map[string][]byte
	labels map[string][]byte
}

type KeyHolder interface {
	Store([]byte, []byte, []byte)
	Get([]byte) ([]byte, []byte, error)
	Has([]byte) bool
}

func NewKeyHolder() KeyHolder {
	return &keyHolder{
		make(map[string][]byte),
		make(map[string][]byte),
	}
}

func(h *keyHolder) Store(id, label, key []byte) {
	sId := string(id)
	h.keys[sId] = key
	h.labels[sId] = append(label[:], []byte{0}...)
}

func(h *keyHolder) Get(id []byte) ([]byte, []byte, error) {
	var k []byte
	var l []byte

	if !h.Has(id) {
		return k, l, errors.New("undefined id")
	}
	sId := string(id)
	k, _ = h.keys[sId]
	l, _ = h.labels[sId]
	return k, l, nil
}

func(h *keyHolder) Has(id []byte) bool {
	sId := string(id)
	if _, ok := h.keys[sId]; !ok {
		return false
	}
	if _, ok := h.labels[sId]; !ok {
		return false
	}
	return true
}
