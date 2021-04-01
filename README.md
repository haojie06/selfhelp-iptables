# selfhelp-iptables-whitelist 通过http api 添加iptables白名单

自助添加iptables白名单的工具，可以通过http请求来向iptables添加白名单，防止恶意探测。

只在debian/ubuntu上测试过，centos要用的话请`systemctl stop firewalld`，仅使用iptables。

```bash
wget https://github.com/aoyouer/selfhelp-iptables-whitelist/releases/download/1.0/selfhelp-iptables-whitelist
chmod +x selfhelp-iptables-whitelist
./selfhelp-iptables-whitelist -key 123 -protect 1080
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

启动参数介绍

- -k key

  必须带上，http请求时需要带上这里设置的key

- -p port

  **可选参数**，该程序监听的端口，默认8080（不指定的时候）

- -protect port1,port2

  **可选参数**，如果 带上了该参数，程序以第二种模式运行，即只限制部分端口的访问 逗号分隔

- -white port1,port2

  **可选参数**，放行的端口

几种请求

- 添加白名单

  `http://example.com:8080/api/add?key=[你设置的key]` 程序会获取访问者的ip，并添加到iptables白名单中。

- 列出当前白名单

  `http://example.com:8080/api/list?key=[你设置的key]`

- 删除白名单

  `http://example.com:8080/api/remove/[要删除的ip]?key=[你设置的key]`

退出程序后，程序会清空添加的iptables规则链（**程序自己新建了一条链，不会影响之前的链**），如果自动清理失败，可以采取手动清理的方式。

```bash
iptables -D INPUT -j SELF_WHITELIST
iptables -F SELF_WHITELIST
iptables -X SELF_WHITELIST
```

