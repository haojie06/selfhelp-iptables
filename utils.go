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

func execCommand(cmd string) {
	cmdl := exec.Command("bash", "-c", cmd)
	result, err := cmdl.CombinedOutput()
	if err != nil {
		resultStr := string(result)
		fmt.Println("执行命令" + cmd + "出错\n" + err.Error() + "\n" + resultStr)
	}
}

//注意时左闭右开
func removeFromSlice(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}
