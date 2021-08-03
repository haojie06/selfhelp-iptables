package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hpcloud/tail"
)

//实时读取iptables写入的内核日志，并非所有系统都支持（文件路径大概不一样）
type Record struct {
	SrcIp string
	SrcPort string
	DstIp string
	DstPort string
	Proto string
	TTL string
	Interface string
}
func readIPLogs() {
	///var/log/secure
	if FileExist("/var/log/iptables.log") {
		kernLogURL = "/var/log/iptables.log"
	} else if FileExist("/var/log/kern.log") {
		kernLogURL = "/var/log/kern.log"
	} else if FileExist("/var/log/messages ") {
		kernLogURL = "/var/log/messages "
	}
	if kernLogURL != "" {
		config := tail.Config{
			ReOpen:    true,                                           //重新打开
			Follow:    true,                                           //跟随
			Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}, //从哪个地方开始读
			MustExist: false,                                          //不存在不报错
			Poll:      true,
		}
		tails, err := tail.TailFile(kernLogURL, config)
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
			if strings.Contains(line.Text, "[netfilter]") {
				fields := strings.Fields(line.Text)
				logRecord := &Record{}
				for _, field := range fields {
					pair := strings.Split(field,"=")
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
				red := color.New(color.FgRed)
				boldRed := red.Add(color.Bold)
				remoteIp := logRecord.SrcIp
				recordIP(remoteIp)
				boldRed.Printf("%s 端口被探测 IP:%s SPT:%s DPT:%s TTL:%s COUNT:%s\n",time.Now().Format("2006-01-02 15:04:05"),logRecord.SrcIp,logRecord.SrcPort,logRecord.DstPort,logRecord.TTL,strconv.Itoa(recordedIPs[remoteIp]))
				// 如果开启了自动添加，当失败次数大于5的时候 添加ip白名单
				if autoAdd && recordedIPs[remoteIp] > 5 && !whiteIPs[remoteIp]{
					log.Println("失败次数超过五次,已为",remoteIp,"自动添加ip白名单")
					whiteIPs[remoteIp] = true
					addIPWhitelist(remoteIp)
				}
			}
		}
	} else {
		cmdColorYellow.Println("找不到日志文件,无法实时显示探测ip")
	}
}
