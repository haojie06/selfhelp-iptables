package ipt

import (
	"fmt"
	"log"
	"os"
	"selfhelp-iptables-whitelist/config"
	"selfhelp-iptables-whitelist/utils"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/hpcloud/tail"
)

//实时读取iptables写入的内核日志，并非所有系统都支持（文件路径大概不一样）

type Record struct {
	SrcIp     string
	SrcPort   string
	DstIp     string
	DstPort   string
	Proto     string
	TTL       string
	Interface string
}

func ReadIPLogs() {
	var logRecordPool = sync.Pool{
		New: func() interface{} {
			return new(Record)
		},
	}
	var kernLogURL string
	// 对不同的系统进行区分
	if utils.FileExist("/var/log/iptables.log") {
		kernLogURL = "/var/log/iptables.log"
	} else if utils.FileExist("/var/log/kern.log") {
		kernLogURL = "/var/log/kern.log"
	} else if utils.FileExist("/var/log/messages ") {
		kernLogURL = "/var/log/messages "
	}
	if kernLogURL != "" {
		cfg := tail.Config{
			ReOpen:    true,                                           //重新打开
			Follow:    true,                                           //跟随
			Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}, //从哪个地方开始读
			MustExist: false,                                          //不存在不报错
			Poll:      true,
		}
		tails, err := tail.TailFile(kernLogURL, cfg)
		if err != nil {
			fmt.Println("tail file failed, err:", err)
			return
		}

		var (
			line *tail.Line
			ok   bool
		)

		for {
			//这个写法 一次从管道里面接收了两个值
			line, ok = <-tails.Lines
			if !ok {
				fmt.Printf("tail file close reopen, filename:%s\n", tails.Filename)
				time.Sleep(time.Second)
				continue
			}
			isDetectLog := strings.Contains(line.Text, "[netfilter]")
			isTriggerLog := strings.Contains(line.Text, "[netfilter-trigger]")
			if isDetectLog || isTriggerLog {
				fields := strings.Fields(line.Text)
				logRecord := logRecordPool.Get().(*Record)
				for _, field := range fields {
					pair := strings.Split(field, "=")
					if len(pair) > 1 {
						switch pair[0] {
						case "IN":
							logRecord.Interface = pair[1]
						case "SRC":
							logRecord.SrcIp = pair[1]
						case "DST":
							logRecord.DstIp = pair[1]
						case "SPT":
							logRecord.SrcPort = pair[1]
						case "DPT":
							logRecord.DstPort = pair[1]
						case "PROTO":
							logRecord.Proto = pair[1]
						case "TTL":
							logRecord.TTL = pair[1]
						}
					}
				}
				boldRed := color.New(color.FgRed).Add(color.Bold)
				boldBlue := color.New(color.FgBlue).Add(color.Bold)
				remoteIp := logRecord.SrcIp
				if isDetectLog {
					// 新增记录为探测记录时
					RecordIP(remoteIp)
					boldRed.Printf("%s 端口被探测 IP:%s SPT:%s DPT:%s TTL:%s COUNT:%s\n", time.Now().Format("2006-01-02 15:04:05"), logRecord.SrcIp, logRecord.SrcPort, logRecord.DstPort, logRecord.TTL, strconv.Itoa(RecordedIPs[remoteIp]))
					// 如果开启了自动添加，当失败次数大于设置的时候 添加ip白名单
					threshold := config.GetConfig().AddThreshold
					//TODO 速率触发和计数触发二选一
					if threshold != 0 && RecordedIPs[remoteIp] > threshold && !WhiteIPs[remoteIp] && config.GetConfig().RateTrigger == "" {
						log.Printf("失败次数超过%d次,已为%s自动添加ip白名单\n", threshold, remoteIp)
						WhiteIPs[remoteIp] = true
						AddIPWhitelist(remoteIp)
					}
				} else if isTriggerLog {
					boldBlue.Printf("%s SYN速率触发 IP:%s SPT:%s DPT:%s TTL:%s [%s packets in %s seconds]\n", time.Now().Format("2006-01-02 15:04:05"), logRecord.SrcIp, logRecord.SrcPort, logRecord.DstPort, logRecord.TTL, pStr, tStr)
					log.Printf("SYN速率触发,已为%s自动添加ip白名单\n", remoteIp)
					WhiteIPs[remoteIp] = true
					AddIPWhitelist(remoteIp)
				}
				logRecordPool.Put(logRecord)
			}
		}
	} else {
		utils.CmdColorYellow.Println("找不到日志文件,无法实时显示探测ip")
	}
}

// 记录探测ip
func RecordIP(ip string) {
	RecordedIPs[ip] = RecordedIPs[ip] + 1
}
