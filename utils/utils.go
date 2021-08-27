package utils

import (
	"os"
	"os/exec"
)

func CheckCommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	if err != nil {
		CmdColorRed.Printf("没有找到命令%s\n", cmd)
		os.Exit(1)
	}
	return true
}

func ExecCommand(cmd string) string {
	cmdl := exec.Command("bash", "-c", cmd)
	result, err := cmdl.CombinedOutput()
	if err != nil {
		resultStr := string(result)
		CmdColorRed.Println("执行命令" + cmd + "出错\n" + err.Error() + "\n" + resultStr)
	}
	return string(result)
}

func ExecCommandWithoutOutput(cmd string) string {
	cmdl := exec.Command("bash", "-c", cmd)
	result, _ := cmdl.CombinedOutput()
	return string(result)
}

//注意时左闭右开
func RemoveFromSlice(slice []string, s int) []string {
	if s != len(slice)-1 {
		return append(slice[:s], slice[s+1:]...)
	} else if s == 0 {
		return slice[1:]
	} else {
		return slice[:s-1]
	}
}


//检查文件是否存在
func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}
