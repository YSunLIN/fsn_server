# 华工DrCOM登录端（FSCUTNET）

## 运行环境
本程序是适用于 linux平台（ubuntu 和 openwrt已测试）
依赖库只有 pthread（一般系统自带）
目前，测试成功路由器：
小米路由器青春版、极路由1S、极路由2、TPLink-wr720n、水星MW305R v1改装版

## 新版
去除了配置文件。
美化了WEB页面，并添加了登录界面。
同时，在登录状态下，当连接断开时，将会已两秒的间隔，无限尝试自动重连。

## 跑起来（OpenWrt路由器）
### windows系统
**准备工具：**  WinSCP（文件传输）

**步骤：**
1. 配置好路由器的WAN为学校提供的静态IP和DNS，并克隆MAC（这一步不会的，请放弃使用fscutnet）

2. 打开WinSCP，新建站点，协议为SCP，IP为路由器后台管理界面IP，用户名为root，密码为路由器后台管理界面密码

3. 登录成功后，根据CPU架构，把相应的fsn_server_xxx拷贝到路由器任意目录(如 /bin, /root, /data 等)，推荐放 /root 下，方便后面更新升级。

    | 路由器 | CPU架构 |
    |  -----------   |:  -----------   :|
    | 小米路由器青春版  |      mt762x      |
    | 小米路由器mini   |      mt762x      |
    | 极路由1S        |      mt762x       |
    | 极路由2         |      mt762x       |
    | TPLink-wr720n  |      ar71xx       |
    | 水星MW305R v1   |      mt762x       |

4. 然后在WinSCP中右击编辑文件 /etc/rc.local， 并在 `exit 0` 前面添加以下两句：

	```bash
	sleep 20;
	(/dddd/fsn_server_xxx &);
	```
其中，dddd为你存放的目录路径，xxx为CPU架构。
例如，放置于 /root下，cpu为mt762x的，就是 `(/root/fsn_server_mt762x &)`

5.  重启路由器，然后使用浏览器打开 http://路由器IP:7288 ，例如 http://192.168.10.1:7288/
不断刷新，直到登录界面出现，输入学号登录即可。

### linux系统
一般使用linux都为高手，你们直接用scp拷贝上去，并用ssh登录修改 /etc/rc.local，其他步骤类似。

## 声明
特别指出禁止任何个人或者公司将 该程序投入商业使用，由此造成的后果和法律责任均与本人无关。
