package uaf

import (
	"encoding/json"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

type Address struct {
	ptr       uint64
	size      uint64
	callIndex int
}

type UafProg struct {
	Prog      []byte
	FreeIndex int
	UseIndex  int
}

func Deserialize(data []byte) *UafProg {
	var p UafProg
	err := json.Unmarshal(data, &p)
	if err != nil {
		log.Fatalf("Error deserializing uafProg: %s", err)
		return nil
	}
	return &p
}

func (p *UafProg) Serialize() []byte {
	data, err := json.Marshal(p)
	if err != nil {
		log.Fatalf("Error serializing uafProg: %s", err)
		return nil
	}
	return data
}

func (p *UafProg) ToRpcType() rpctype.UafInput {
	return rpctype.UafInput{
		Prog:      p.Prog,
		FreeIndex: p.FreeIndex,
		UseIndex:  p.UseIndex,
	}
}

func FromRpcType(inp rpctype.UafInput) *UafProg {
	return &UafProg{
		Prog:      inp.Prog,
		FreeIndex: inp.FreeIndex,
		UseIndex:  inp.UseIndex,
	}
}

//func SaveUAFProg(p *prog.Prog, callPairMap map[int]map[int]int) {
//	if len(callPairMap) <= 0 || p == nil {
//		return
//	}
//	log.Logf(0, "SaveUAFProg: Prog: %v, callMap: %v", p, callPairMap)
//	saveFile, err := os.OpenFile("pairs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
//	if err != nil {
//		log.Fatalf("Error opening file: %s", err)
//		return
//	}
//	defer saveFile.Close()
//
//	for freeIndex, callMap := range callPairMap {
//		for callIndex, _ := range callMap {
//			uafProg := UafProg{
//				Prog:      p.Serialize(),
//				FreeIndex: freeIndex,
//				UseIndex:  callIndex,
//			}
//			log.Logf(0, "SaveUAFProg: uafProg:%v", uafProg)
//
//			// 获取当前时间
//			currentTime := time.Now().Format(time.RFC3339)
//			// 将结构体转换为 JSON 格式
//			jsonData, err := json.Marshal(uafProg)
//
//			log.Logf(0, "SaveUAFProg: jsonData: %s", string(jsonData))
//			if err != nil {
//				log.Fatalf("Error marshalling JSON: %s", err)
//				return
//			}
//
//			// 写入当前时间和 JSON 数据到文件
//			_, err = fmt.Fprintf(saveFile, "[%s] %s\n", currentTime, string(jsonData))
//			if err != nil {
//				fmt.Println("Error writing to file:", err)
//				return
//			}
//		}
//	}
//}

func BuildFreeMap(info *ipc.ProgInfo) map[uint64]Address {

	// alloc内存操作对应的地址、大小
	allocMap := make(map[uint64]Address)

	// free内存操作对应的地址、大小、调用函数索引
	freeMap := make(map[uint64]Address)

	// 遍历函数调用信息数据
	for _, call := range info.Calls {
		// 遍历每个函数对应的事件记录数组
		for _, ev := range call.EvList {
			// 如果是alloc操作
			if ev.EventType == prog.EVTRACK_EVENT_HEAP_ALLOCATION {
				// 记录alloc内存操作对应的地址、大小
				allocMap[ev.Ptr] = Address{
					ptr:  ev.Ptr,
					size: uint64(ev.Size),
				}
			}
		}
	}

	// 遍历函数调用信息数据
	for callIndex, call := range info.Calls {
		// 遍历每个函数对应的事件记录数组
		for _, ev := range call.EvList {
			// 如果是free操作
			if ev.EventType == prog.EVTRACK_EVENT_HEAP_DEALLOCATION {
				// 检查是否是已分配的地址
				if add, ok := allocMap[ev.Ptr]; ok {
					freeMap[ev.Ptr] = Address{
						ptr:       ev.Ptr,
						size:      add.size,
						callIndex: callIndex,
					}
				}
			}
		}
	}
	return freeMap
}

func BuildCallPairMap(info *ipc.ProgInfo) map[int]map[int]int {

	// free内存操作对应的地址、大小、调用函数索引
	freeMap := BuildFreeMap(info)

	// free操作和访问操作内存地址有重叠的函数调用对
	callPairMap := make(map[int]map[int]int)

	// 遍历函数调用信息数据
	for callIndex, callInfo := range info.Calls {
		// 遍历每个函数对应的事件记录数组
		for _, ev := range callInfo.EvList {
			// 如果是内存访问操作
			if ev.EventType == prog.EVTRACK_EVENT_HEAP_READ || ev.EventType == prog.EVTRACK_EVENT_HEAP_WRITE ||
				ev.EventType == prog.EVTRACK_EVENT_HEAP_POINTER_READ || ev.EventType == prog.EVTRACK_EVENT_HEAP_POINTER_WRITE ||
				ev.EventType == prog.EVTRACK_EVENT_HEAP_INDEX_READ || ev.EventType == prog.EVTRACK_EVENT_HEAP_INDEX_WRITE {
				// 遍历所有free操作记录
				for _, freeAdress := range freeMap {
					// 检查是否是同一函数调用
					if freeAdress.callIndex == callIndex {
						continue
					}
					//检查内存地址是否重叠
					if freeAdress.ptr <= ev.Ptr && freeAdress.ptr+freeAdress.size >= ev.Ptr {
						if _, ok := callPairMap[freeAdress.callIndex]; !ok {
							callPairMap[freeAdress.callIndex] = make(map[int]int)
						}
						callPairMap[freeAdress.callIndex][callIndex] = 1
					}
				}
			}
		}
	}
	return callPairMap
}

func BuildUafProgList(p *prog.Prog, info *ipc.ProgInfo) []UafProg {
	if p == nil {
		return nil
	}
	callPairMap := BuildCallPairMap(info)
	if len(callPairMap) == 0 {
		return nil
	}

	var res []UafProg
	for freeIndex, callMap := range callPairMap {
		for callIndex, _ := range callMap {
			uafProg := UafProg{
				Prog:      p.Serialize(),
				FreeIndex: freeIndex,
				UseIndex:  callIndex,
			}
			res = append(res, uafProg)
		}
	}

	return res
}
