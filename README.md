# 华工DrCOM登录端（FSCUTNET）

## 运行环境
本程序是适用于 linux平台（ubuntu 和 openwrt已测试）
依赖库只有 pthread（一般系统自带）
目前，测试成功路由器：
小米路由器青春版、极路由1S、极路由2、TPLink-wr720n、水星MW305R改装版

## 配置文件
文件放置于 /etc/fsn.conf

#####格式如下:
account（用户名）
password （密码）
interface （连接外网的网络接口名称，详情在linux下执行ifconfig）
server_ip:port  （局域网的IP，还有端口一般填7288，不要有空格）


#####内容样例:
2020300030000
2020300030000
eth0
192.168.1.1:7288



## 跑起来
根据CPU架构，把相应的fsn_server_xxx拷贝到路由器任意目录，并改名为fsn_server。

直接输入 `./fsn_server` 运行

后台运行：输入 `(./fsn_server &)` ，带括号的

运行的过程中，可能会遇到permission denied的问题，首先确保自己是root，然后运行 `chmod +x ./fsn_server` 给其添加运行权限。

运行成功后，可以使用浏览器打开，地址是 http://server_ip:port， 也就是配置文件最后填的地址和端口，即可看到详情页面。

fsn_server 会自动登录，刷新页面，即可看登录的情况。同时，当连接断开时，fsn_server也会无限尝试自动重连。

## 声明
特别指出禁止任何个人或者公司将 该程序投入商业使用，由此造成的后果和法律责任均与本人无关。
