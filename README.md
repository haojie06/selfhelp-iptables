# selfhelp-iptables-whitelist 通过http api 添加iptables白名单

自助添加iptables白名单的工具，可以通过http请求来向iptables添加白名单，防止恶意探测。

只在debian/ubuntu上测试过，centos要用的话请`systemctl stop firewalld`，仅使用iptables。

```bash
wget https://github.com/aoyouer/selfhelp-iptables-whitelist/releases/download/1.1/selfhelp-iptables-whitelist
chmod +x selfhelp-iptables-whitelist
#拦截1080端口
./selfhelp-iptables-whitelist -k key -protect 1080
#或者全端口拦截
./selfhelp-iptables-whitelist -k key -white 22,80,443
#另外添加了一个自动添加ip白名单的参数，当失败次数超过5次的时候便添加白名单(因为某分布式系统对于一些服务的探测，只会尝试最开始的四个包，如果无法建立连接便放弃)
#该模式必须要能够读取到iptables的日志才可行
./selfhelp-iptables-whitelist -k key -auto -protect 1080
```

有两种运行模式

1. 全端口访问白名单限制

   默认阻止任何外部ip访问本机的任何端口（**除了22以及程序监听的端口**）

2. 特定端口访问白名单限制 

   默认阻止任何外部ip访问本地的特定端口 带上参数 -protect后自动启用 **强烈建议使用该模式**

使用第一种运行模式，执行程序后，所有的端口都会被禁止访问（默认放行了22端口的访问和icmp请求），之后请求 `http://example.com:8080/api/add?key=[你设置的key]` 可以将你的ip添加到白名单里面。

使用第二种运行模式，启动程序时还要指定一个参数 -protect [端口号 多个端口号用逗号分隔] 如 -protect 80,443 ，程序启动后会阻断对80 443的访问，在访问 `http://example.com:8080/api/add?key=[你设置的key]` 后可以添加白名单

**注意，程序需要能获取到访问者的ip才能添加白名单，所以不要再frp的客户端上运行这个程序，不然得到的ip会是 127.0.0.1，默认放行**

**强烈建议使用第二种方法，全端口拦截会出现很多问题，如DNS无法查询之类的。**

## 实时日志设置

开始运行后，程序会尝试去寻找iptables的日志文件，并实时读取文件，当文件更新时，实时输出内容。不同系统的日志目录有差异。

在 Ubuntu/debian中，日志位于 */var/log/kern.log* 而 centos/rhel中，日志位于 */var/log/messages*,理论上程序已经做了判断，当然你也可以把iptables日志记录到单独的文件中,**需使用下面的名字**。

**！！！！建议不需要修改保存路径**

**个人尝试，在某些系统下，把日志保存到其他文件中的尝试失败了，所以如果你修改了保存文件后发现iptables.log迟迟没有写入信息，那么删掉这个文件和配置文件中的设置并重新运行程序吧。或者[参考此文](https://askubuntu.com/questions/348439/where-can-i-find-the-iptables-log-file-and-how-can-i-change-its-location)折腾一下，如果还是不行，就删掉自己新建的文件，使用默认的系统日志文件。**

```bash
# 如果实在想要改，就像下面这样操作
# 编辑rsyslog的配置文件
vi /etc/rsyslog.conf
# 加上下面这一行
kern.warning /var/log/iptables.log
# 手动创建该文件
touch /var/log/iptables.log
# 重启服务
systemctl restart rsyslog
```

之后程序会优先读取该日志文件。 

![](https://img.aoyouer.com/images/2021/04/02/20210402170829.png)

## 参数介绍

启动参数介绍

- -k key

  必须带上，http请求时需要带上这里设置的key

- -p port

  **可选参数**，该程序监听的端口，默认8080（不指定的时候）

- -protect port1,port2

  **可选参数**，如果 带上了该参数，程序以第二种模式运行，即只限制部分端口的访问 逗号分隔

- -white port1,port2

  **可选参数**，放行的端口
- -auto

  **可选参数** 是否自动添加白名单(依赖日志读取),当连接失败次数超过五次时（某大型分布式系统在进行探测的时候，只会尝试四次连接），自动为ip添加白名单。

控制台参数介绍

程序启动后，可以直接通过标准输入输入命令进行操作

- help 显示帮助
- add 添加ip白名单
- list 列出当前添加的ip
- remove 移除添加的ip
- record 列出 探测ip以及次数记录

几种请求

- 添加白名单

  `http://example.com:8080/api/add?key=[你设置的key]` 程序会获取访问者的ip，并添加到iptables白名单中。

- 列出当前白名单

  `http://example.com:8080/api/list?key=[你设置的key]`

- 删除白名单

  `http://example.com:8080/api/remove/[要删除的ip]?key=[你设置的key]`

- 查看探测记录

  `http://example.com:8080/api/log?key=[你设置的key]`

- 查看探测计数

   `http://example.com:8080/api/record?key=[你设置的key]`

退出程序后，程序会清空添加的iptables规则链（**程序自己新建了一条链，不会影响之前的链**），如果自动清理失败，可以采取手动清理的方式。

```bash
iptables -D INPUT -j SELF_WHITELIST
iptables -F SELF_WHITELIST
iptables -X SELF_WHITELIST
```
