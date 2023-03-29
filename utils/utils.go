package utils

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// 注意时左闭右开
func RemoveFromSlice(slice []string, s int) []string {
	if s != len(slice)-1 {
		return append(slice[:s], slice[s+1:]...)
	} else if s == 0 {
		return slice[1:]
	} else {
		return slice[:s-1]
	}
}

// 检查文件是否存在
func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

// 检查端口是否合法
func CheckPorts(ports []int32) (result bool) {
	result = true
	for _, p := range ports {
		if p < 1 || p > 65535 {
			result = false
			return
		}
	}
	return
}

// 将逗号分隔的端口字符串转换为整型数组
func PortsToIntArray(strPorts string) (result []int) {
	ports := strings.Split(strPorts, ",")
	for _, p := range ports {
		port, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil {
			result = append(result, port)

		}
	}
	return
}

// convert []int32 to []int
func Int32sToInts(int32s []int32) []int {
	result := make([]int, len(int32s))
	for i, n := range int32s {
		result[i] = int(n)
	}
	return result
}

// 判断一个字符串是否是ip或者cidr形式
func IsIPorCIDR(ip string) bool {
	if strings.Contains(ip, "/") {
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return false
		}
	} else {
		if net.ParseIP(ip) == nil {
			return false
		}
	}
	return true
}

// 部分错误，我们只需要输出其内容就好
func LogError(err error) {
	if err != nil {
		CmdColorRed.Println(err.Error())
	}
}
