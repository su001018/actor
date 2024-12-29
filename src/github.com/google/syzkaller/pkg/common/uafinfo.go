package common

import (
	"encoding/json"
	"log"
)

type UafInfo struct {
	FreeIndex int
	UseIndex  int
	FreeAddr  uint64
	UseAddr   uint64
	Sched     int
}

func (uafInfo *UafInfo) Serialize() []byte {
	data, err := json.Marshal(uafInfo)
	if err != nil {
		log.Fatalf("Error serializing uafInfo: %s", err)
		return nil
	}
	return data
}

func Deserialize(data []byte) *UafInfo {
	var info UafInfo
	err := json.Unmarshal(data, &info)
	if err != nil {
		log.Fatalf("Error deserializing uafProg: %s", err)
		return nil
	}
	return &info
}
