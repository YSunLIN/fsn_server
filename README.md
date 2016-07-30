# 华工DrCOM开源登录端

## 运行环境
本程序是适用于 linux平台，windows请移步。
依赖库是 pthread


## 配置文件
文件放置于 /etc/scut_8021x.conf

#####格式如下:
account（用户名）<br/>
password （密码）<br/>
interface （连接外网的网络接口名称，详情在linux下执行ifconfig）<br/>
server_ip:port  （局域网的IP，还有端口一般填7288，不要有空格）<br/>


#####内容样例:
2020300030000<br/>
2020300030000<br/>
eth0<br/>
192.168.1.1:7288<br/>



## 跑起来
make编译后，可以直接输入 ./fsn_server 运行

后台运行：输入 (./fsn_server &) ，带括号的

运行成功后，可以使用浏览器打开，地址是 http://server_ip:port， 也就是配置文件最后填的地址和端口，即可看到详情页面。

点击详情页面的 login，即可登录。然后刷新页面，看登录的情况。


## 声明
特别指出禁止任何个人或者公司将 drcom 的代码投入商业使用，由此造成的后果和法律责任均与本人无关。
