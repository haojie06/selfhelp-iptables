package main

import (
	"fmt"
	"os"
	"os/exec"
)

func checkCommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	if err != nil {
		fmt.Printf("没有找到命令%s\n", cmd)
		os.Exit(1)
	}
	return true
}

func execCommand(cmd string) string {
	cmdl := exec.Command("bash", "-c", cmd)
	result, err := cmdl.CombinedOutput()
	if err != nil {
		resultStr := string(result)
		fmt.Println("执行命令" + cmd + "出错\n" + err.Error() + "\n" + resultStr)
	}
	return string(result)
}

func execCommandWithoutOutput(cmd string) string {
	cmdl := exec.Command("bash", "-c", cmd)
	result, _ := cmdl.CombinedOutput()
	return string(result)
}

//注意时左闭右开
func removeFromSlice(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}

//探测ip记录
func recordIP(ip string) {
	recordedIPs[ip] = recordedIPs[ip] + 1
}

//检查文件是否存在
func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}
