# selfhelp-iptables 通过http api 添加iptables黑/白名单

自助添加iptables白名单的工具，可以通过http请求来向iptables添加白名单，防止不怀好意之人的端口扫描和恶意探测。

**暂时不支持docker bridge network模式(host模式可用)**

只在debian/ubuntu上测试过，另外需要关闭自带的一些防火墙管理程序，仅使用iptables。有ufw的话先执行`ufw disable`，有firewalld(如centos)的话先执行`systemctl stop firewalld`。

```bash
wget https://github.com/haojie06/selfhelp-iptables/releases/download/[version]/selfhelp-iptables
chmod +x selfhelp-iptables && setcap 'cap_net_admin=+ep' selfhelp-iptables
# 查看帮助
./selfhelp-iptables help
#拦截1080端口与1081端口
./selfhelp-iptables start -u userkey -a adminkey -p 1080 1081
#或者全端口拦截 放行 22 80 443
./selfhelp-iptables start -u userkey -a adminkey -w 22 80 443
```

有两种运行模式

1. 全端口访问白名单限制

   默认阻止任何外部ip访问本机的任何端口（**除了22以及程序http api监听的端口**）

2. 特定端口访问白名单限制 

   默认阻止任何外部ip访问本地的特定端口 带上参数 -protect后自动启用 **建议使用该模式**

使用第一种运行模式，执行程序后，所有的端口都会被禁止访问（默认放行了22端口的访问和icmp请求），之后请求 `http://example.com:8080/api/add?key=[你设置的key]` 可以将你的ip添加到白名单里面。

使用第二种运行模式，启动程序时还要指定一个参数 -protect [端口号 多个端口的话需要重复多次] 如 --protect 80 --protect 443 ，程序启动后会阻断对80 443的访问，在访问 `http://example.com:8080/api/add?key=[你设置的key]` 后可以添加白名单

**注意，程序需要能获取到访问者的ip才能添加白名单，需要确保真实的ip能传递给该服务，如果使用nginx等程序对http api进行反向代理，需要带上 --reverse 参数以开启反向代理支持，然后在nginx中添加 X-Real-Ip 或者 X-Forwarded-For 字段传递请求者的ip。**

**建议使用第二种方法，全端口拦截会出现很多问题，如DNS无法查询之类的。**

## 实时日志设置

～～开始运行后，程序会尝试去寻找iptables的日志文件，并实时读取文件，当文件更新时，实时输出内容。不同系统的日志目录有差异。～～

在新版本中，程序已经改为从nflog中读取日志，不再依赖系统日志文件。

## 参数介绍

启动参数介绍

- -a adminkey

  必须带上，用于控制api的key
- -u userkey

  userkey仅作为访问 /api/add?key=  时添加访问者ip到白名单的密钥使用，可分享给他人

- -l port

  **可选参数**，该程序监听的端口，默认8080

- -p port1

  **可选参数**，如果 带上了该参数，程序以第二种模式运行，即只限制部分端口的访问 空格分隔，或者使用多个 -p 参数

- --allow ip1

  **可选参数**，放行的ip，**使用多个 --allow 参数** 以添加多个ip, 支持 cidr(如192.168.0.1/24) 

- -w port1

  **可选参数**，放行的端口
- -t n

  **可选参数** 自动添加白名单的阈值(依赖日志读取),当连接失败次数超过n次时，自动为该ip添加白名单。
- -r [param]

  可选参数, 如果开启了自动添加白名单的功能时，是否需要进行自动重置，并指定重置周期，可选周期如下:
  - hh 每半小时重置
  - h 每小时重置
  - hd 每半天重置
  - d 每天重置
  - w 每周重置
- --reject -d
  可选参数，开启后对于被拦截端口的访问会返回一个拒绝连接的icmp包
  
- --reverse
  开启反向代理支持，读取http请求头获取客户端ip，请仅在使用可信反向代理的情况下使用,nginx示例: 
  ```
          location /api {
           proxy_set_header  X-real-ip $remote_addr;
           proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_pass http://127.0.0.1:8080/api;
        }
  ```
  **需要注意，在开启反向代理支持之后，不会默认为http api端口添加白名单，所以可以使用 -p [http api 监听的端口] 来阻止外部直接请求http api(必须走反向代理)**

- --trigger [counts]/[seconds]

  包速率触发器，一个有意思的小功能，可以实现*基本无感的白名单添加*,当某一ip向指定端口发送包的速率超过某一个阈值的时候(比如 --trigger 9/3 表示平均三秒内有多于9个包),为其添加白名单。 不过这个添加方式存在误判的可能性，但是对于大范围的nmap扫描等探测方式,可以实现既能够拦截恶意探测,也能够为用户自动地添加白名单。
  


控制台参数介绍

程序启动后，可以直接通过标准输入输入命令进行操作

- help 显示帮助
- add 添加ip白名单
- list 列出当前添加的ip
- remove 移除添加的ip
- record 列出 探测ip以及次数记录
- reset 重置所有记录 包括连接记录和白名单
几种请求 (不通过浏览器，直接使用curl也可以)

- 添加白名单

  `http://example.com:8080/api/add?key=[你设置的userkey]` 程序会获取访问者的ip，并添加到iptables白名单中。

- 列出当前白名单

  `http://example.com:8080/api/list?key=[你设置的adminkey]`

- 删除白名单

  `http://example.com:8080/api/remove/[要删除的ip]?key=[你设置的adminkey]`

- 查看探测记录

  `http://example.com:8080/api/log?key=[你设置的adminkey]`

- 查看探测计数

   `http://example.com:8080/api/record?key=[你设置的adminkey]`

## 程序对系统的影响

该程序的拦截规则是在一条新的链里面进行的，在**退出程序**后程序会清空这条规则链，所以如果设置错了导致连不上ssh，那么可以尝试使用vnc连接到机器上，ps aux |grep self 找到进程并kill即可, 或者直接重启系统，也能清空规则链。

或者手动清理规则链


```bash
iptables -vnL # 查看多出来的链
iptables -D INPUT -j PROTECT_LIST
iptables -F PROTECT_LIST
iptables -X PROTECT_LIST
```
