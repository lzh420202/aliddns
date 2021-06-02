# 基于官方TPlINK路由器的aliddns使用方法(win/linux/mac通用)

配合TPLINK的阿里DDNS脚本，无需破解刷机TPLINK路由器，采用POST方法登录路由器管理并获取网络信息包来得到路由器WAN口IP地址。

### 使用方法
程序为python脚本，只要安装了阿里sdk和pyyaml库就可以使用，基本需求为python3。

测试机型: TL-WDR5620千兆版

#### 参数配置
程序运行参数放置在config.yaml文件中，主要字段如下：
```yaml
alidns:
  DomainName: xidian-ai-intranet.top
  id: xxxxxxxxxxxxxxxxx                         #阿里云的AccessKey ID
  password: xxxxxxxxxxxxxxxxxxx                 #阿里云的AccessKey 密码
  regionId: cn-hangzhou                         #阿里云的区域代码
  ttl: 600                                      #阿里云DNS的TTL,单位秒
  type: A                                       #阿里云DNS解析类型，A表示解析为IPv4地址
internet:                                       #公网参数
  url: http://www.3322.org/dyndns/getip         #公网IP获取URL
ip_interface: router                            #IP获取方式
router:                                         #路由器参数
  type: tplink                                  #路由器类型
  ip: 192.168.1.1                               #路由器管理地址
  password: xxxxxxxxxx                          #路由器管理密码
  username: NULL                                #路由器管理账号
wan:                                            #本机网络参数
  ip: 8.8.8.8                                   #test stock IP
  port: 80                                      #test stock port
```
需要修改的部分为alidns中的DomainName、id、password，ip_interface，router中的type、password和username。

ip_interface取值包括: internet、router、wan。

router/type的取值包括:tplink、padavan。

配置正确后即可参照update_domain_test.py文件进行修改，并加入计划任务中，这里仅介绍ubuntu系统的计划任务设置方法。

#### 设置计划任务/ubuntu(linux)
```shell
# crontab 增加计划任务
crontab -e
# 加入 */5 * * * * python3 fullpath_to_script.py，添加完成后:wq保存即可
```

#### 检查网络状况，获取IP命令
```shell
python3 checkIPaddr.py
```

#### 更新域名记录
```shell
python3 update_domain_test.py
```