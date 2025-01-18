package uaf

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/common"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

type UafCandiate struct {
	Prog *prog.Prog
	common.UafInfo
}

type Address struct {
	ptr        uint64
	size       uint64
	callIndex  int
	eventIndex int
}

type UafProg struct {
	Prog []byte
	common.UafInfo
	FreeEvent prog.EvtrackEvent
	UseEvent  prog.EvtrackEvent
}

type UafPair struct {
	FreeIdx      int
	UseIdx       int
	FreeEventIdx int
	UseEventIdx  int
}

func ComputeSig(p, ui []byte) string {
	return hash.String(append(p, ui...))
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

func (p *UafProg) ToRpcType() rpctype.UafCandInput {
	return rpctype.UafCandInput{
		Prog:      p.Prog,
		FreeIndex: p.FreeIndex,
		UseIndex:  p.UseIndex,
		FreeEvent: p.FreeEvent,
		UseEvent:  p.UseEvent,
	}
}

func FromRpcType(inp rpctype.UafCandInput) *UafProg {
	uafInfo := common.UafInfo{
		FreeIndex: inp.FreeIndex,
		UseIndex:  inp.UseIndex,
	}
	return &UafProg{
		Prog:      inp.Prog,
		UafInfo:   uafInfo,
		FreeEvent: inp.FreeEvent,
		UseEvent:  inp.UseEvent,
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

func BuildFreeMap(allocMap map[uint64]uint64, info *ipc.ProgInfo, p *prog.Prog) map[uint64]Address {

	// free内存操作对应的地址、大小、调用函数索引
	freeMap := make(map[uint64]Address)

	// 遍历函数调用信息数据
	for _, call := range info.Calls {
		// 遍历每个函数对应的事件记录数组
		for _, ev := range call.EvList {
			// 如果是alloc操作
			if ev.EventType == prog.EVTRACK_EVENT_HEAP_ALLOCATION {
				// 记录alloc内存操作对应的地址、大小
				allocMap[ev.Ptr] = uint64(ev.Size)
			}
		}
	}
	clean := make(map[uint64]bool)

	// 遍历函数调用信息数据
	for callIndex, call := range info.Calls {
		// 遍历每个函数对应的事件记录数组
		for evIdx, ev := range call.EvList {
			// 如果是free操作
			if ev.EventType == prog.EVTRACK_EVENT_HEAP_DEALLOCATION {
				// 检查是否是已分配的地址
				if add, ok := allocMap[ev.Ptr]; ok {
					addr := Address{
						ptr:        ev.Ptr,
						size:       add,
						callIndex:  callIndex,
						eventIndex: evIdx,
					}
					freeMap[ev.Ptr] = addr
					clean[ev.Ptr] = true
				}
			}
		}
	}

	for c, _ := range clean {
		delete(allocMap, c)
	}
	return freeMap
}

func BuildCallPairMap(allocMap map[uint64]uint64, info *ipc.ProgInfo, p *prog.Prog) []UafPair {

	// free内存操作对应的地址、大小、调用函数索引
	freeMap := BuildFreeMap(allocMap, info, p)

	// free操作和访问操作内存地址有重叠的函数调用对
	callPairs := make([]UafPair, 0)

	// 遍历函数调用信息数据
	for callIndex, callInfo := range info.Calls {
		// 遍历每个函数对应的事件记录数组
		for evIdx, ev := range callInfo.EvList {

			// 如果是内存访问操作
			if ev.EventType == prog.EVTRACK_EVENT_HEAP_READ || ev.EventType == prog.EVTRACK_EVENT_HEAP_WRITE ||
				ev.EventType == prog.EVTRACK_EVENT_HEAP_POINTER_READ || ev.EventType == prog.EVTRACK_EVENT_HEAP_POINTER_WRITE ||
				ev.EventType == prog.EVTRACK_EVENT_HEAP_INDEX_READ || ev.EventType == prog.EVTRACK_EVENT_HEAP_INDEX_WRITE {
				// the top 2 of the trace is stack_trace_save and record_event
				if len(ev.Trace) <= 2 {
					continue
				}
				// 遍历所有free操作记录
				for _, freeAdress := range freeMap {
					// 检查是否是同一函数调用
					if freeAdress.callIndex == callIndex {
						continue
					}
					//检查内存地址是否重叠
					if freeAdress.ptr <= ev.Ptr && freeAdress.ptr+freeAdress.size >= ev.Ptr {
						callPairs = append(callPairs, UafPair{
							FreeIdx:      freeAdress.callIndex,
							UseIdx:       callIndex,
							FreeEventIdx: freeAdress.eventIndex,
							UseEventIdx:  evIdx,
						})
					}
				}
			}
		}
	}
	return callPairs
}

func BuildUafProgList(allocMap map[uint64]uint64, p *prog.Prog, info *ipc.ProgInfo) []UafProg {
	if p == nil {
		return nil
	}
	callPairs := BuildCallPairMap(allocMap, info, p)
	if len(callPairs) == 0 {
		return nil
	}

	var res []UafProg
	for _, uafPair := range callPairs {
		uafInfo := common.UafInfo{
			FreeIndex: uafPair.FreeIdx,
			UseIndex:  uafPair.UseIdx,
		}
		uafProg := UafProg{
			Prog:      p.Serialize(),
			UafInfo:   uafInfo,
			FreeEvent: info.Calls[uafPair.FreeIdx].EvList[uafPair.FreeEventIdx],
			UseEvent:  info.Calls[uafPair.UseIdx].EvList[uafPair.UseEventIdx],
		}
		res = append(res, uafProg)

	}

	return res
}
