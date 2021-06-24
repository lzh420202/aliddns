#!/usr/bin/env python
#coding=utf-8

# 加载核心SDK
from enum import Flag
from posixpath import expanduser
from sys import flags
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException

# 加载获取 、 新增、 更新、 删除接口
from aliyunsdkalidns.request.v20150109 import DescribeSubDomainRecordsRequest, AddDomainRecordRequest, UpdateDomainRecordRequest, DeleteDomainRecordRequest

# 加载内置模块
import json, urllib, socket, requests, base64, re, os
from aliyunsdkcore.vendored.six import with_metaclass

class aliyunAccount():
    def __init__(self, AccessKey: str, SECRET: str, regionId: str,
                 DomainName: str, subDomainHead) -> None:
        self.mainDomain = DomainName
        self.subDomainHead = subDomainHead
        try:
            self.client = AcsClient(AccessKey, SECRET, regionId)
            self.status = True
        except:
            self.status = False

class routerConfig():
    def __init__(self, router_type: str, password: str, ip: str='192.168.1.1', username: str='') -> None:
        assert router_type in ['tplink', 'padavan']
        self.router_type = router_type
        if self.router_type == 'tplink':
            self.router_username = ''
        else:
            self.router_username = username
        self.router_ip = ip
        self.router_password = password

class TPLinkRouter():
    def __init__(self, password: str, ip: str='192.168.1.1') -> None:
        self.ip = ip
        self.password = password
    def encrypt_pwd(self):
        input1 = "RDpbLfCPsJZ7fiv"
        input3 = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
        len1 = len(input1)
        len2 = len(self.password)
        dictionary = input3
        lenDict = len(dictionary)
        output = ''
        if len1 > len2:
            length = len1
        else:
            length = len2
        index = 0
        while index < length:
            # 十六进制数 0xBB 的十进制为 187
            cl = 187
            cr = 187
            if index >= len1:
                # ord() 函数返回字符的整数表示
                cr = ord(self.password[index])
            elif index >= len2:
                cl = ord(input1[index])
            else:
                cl = ord(input1[index])
                cr = ord(self.password[index])
            index += 1
            # chr() 函数返回整数对应的字符
            output = output + chr(ord(dictionary[cl ^ cr]) % lenDict)
        return output
    def post_tp_link(self, payload, stok):
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        url = 'http://{}/stok={}/ds'.format(self.ip, stok)
        response = requests.post(url, data=payload, headers=headers, timeout=1)
        return response
    def login(self):
        encryptPwd = self.encrypt_pwd()
        url = 'http://{}/'.format(self.ip)
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        payload = '{"method":"do","login":{"password":"%s"}}' % encryptPwd
        response = requests.post(url, data=payload, headers=headers, timeout=1)
        stok = json.loads(response.text)['stok']
        return stok
    
    def logout(self, stok):
        payload = '{"system":{"logout":"null"},"method":"do"}'
        self.post_tp_link(payload, stok)
    
    def getWanIP(self):
        try:
            stok = self.login()
            payload = '{"network":{"name":["wan_status"]},"method":"get"}'
            response = self.post_tp_link(payload, stok)
            data = json.loads(response.text)
            if data['network']['wan_status']['link_status'] == 1:
                ip = data['network']['wan_status']['ipaddr']
            else:
                ip = None
            self.logout(stok)
        except:
            ip = None
        return ip


class DDNS(aliyunAccount, routerConfig):
    def __init__(self, cfg, sub) -> None:
        ali_cfg = cfg['alidns']
        aliyunAccount.__init__(self, ali_cfg['id'], ali_cfg['password'], ali_cfg['regionId'], ali_cfg['DomainName'], sub)
        router_cfg = cfg['router']
        routerConfig.__init__(self, str(router_cfg['type']), str(router_cfg['password']),
                              router_cfg['ip'],str(router_cfg['username']))
        getIPMethod = cfg['ip_interface']
        assert getIPMethod in ['wan', 'internet', 'router']
        self.ip_method = getIPMethod
        self.dns_type = ali_cfg['type']
        self.TTL = ali_cfg['ttl']
        self.wan_path = (cfg['wan']['ip'], cfg['wan']['port'])
        self.public_path = cfg['internet']['url']

    def subDomainName(self, mainDomain, sub):
        return '.'.join([mainDomain, sub])

    def getIP(self):
        if self.ip_method == 'wan':
            value = self.getWanIP()
        elif self.ip_method == 'router':
            value = self.getRouterWanIP()
        elif self.ip_method == 'internet':
            value = self.getPublicIp()
        else:
            value = None
        return value

    def getWanIP(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(self.wan_path)
            ip = s.getsockname()[0]
        except:
            ip = None
        finally:
            s.close()
        return ip
    
    def getPadavanRouterWanIP(self):
        token = base64.standard_b64encode('{}:{}'.format(self.router_username, self.router_password).encode('utf-8')).decode('utf-8')
        router_token = 'Basic {}'.format(token)
        ss = requests.Session()
        response_t = ss.post('http://{}/status_internet.asp'.format(self.router_ip),
                        headers={'Authorization': router_token}).text
        status = [t.replace(' ', '') for t in response_t.splitlines() if 'now_wan_internet' in t][-1]
        status_pattern = re.compile('(?<=\=[\'\"])\d+(?=[\'\"];.*)')
        status_result = int(status_pattern.findall(status)[0])
        if status_result != 1:
            return None
        response = ss.post('http://{}/status_wanlink.asp'.format(self.router_ip), headers={'Authorization': router_token})
        text = response.text
        target = [t.replace(' ', '') for t in text.splitlines() if 'wanlink_ip4_wan' in t][-1]

        pattern = re.compile('(?<=return[\'\"])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=[\'\"];.*)')
        result = pattern.findall(target)
        if len(result) == 0:
            return None
        else:
            return result[0]

    def getTPLinkRouterWanIP(self):
        tp = TPLinkRouter(self.router_password, self.router_ip)
        return tp.getWanIP()

    def getRouterWanIP(self):
        if self.router_type == 'tplink':
            ip = self.getTPLinkRouterWanIP()
        elif self.router_type == 'padavan':
            ip = self.getPadavanRouterWanIP()
        else:
            ip = None
        return ip

    def getPublicIp(self):
        # 备选地址： 1， http://pv.sohu.com/cityjson?ie=utf-8    2，curl -L tool.lu/ip
        try:
            with urllib.request.urlopen(self.public_path, timeout=1) as response:
                html = response.read()
                ip = str(html, encoding='utf-8').replace("\n", "")
        except:
            ip = None
        return ip


    # 查询记录
    def getDomainInfo(self, subDomain):
        request = DescribeSubDomainRecordsRequest.DescribeSubDomainRecordsRequest()
        request.set_accept_format('json')

        # 设置要查询的记录类型为 A记录   官网支持A / CNAME / MX / AAAA / TXT / NS / SRV / CAA / URL隐性（显性）转发  如果有需要可将该值配置为参数传入
        request.set_Type(self.dns_type)

        # 指定查记的域名 格式为 'test.example.com'
        request.set_SubDomain(subDomain)

        try:
            response = self.client.do_action_with_exception(request)
            response = str(response, encoding='utf-8')
        except:
            response = '{"TotalCount":-1}'
        # 将获取到的记录转换成json对象并返回
        return json.loads(response)

    # 新增记录 (默认都设置为A记录，通过配置set_Type可设置为其他记录)
    def addDomainRecord(self, value, rr):
        request = AddDomainRecordRequest.AddDomainRecordRequest()
        request.set_accept_format('json')

        # request.set_Priority('1')  # MX 记录时的必选参数
        request.set_TTL(self.TTL)       # 可选值的范围取决于你的阿里云账户等级，免费版为 600 - 86400 单位为秒 
        request.set_Value(value)     # 新增的 ip 地址
        request.set_Type(self.dns_type)        # 记录类型
        request.set_RR(rr)           # 子域名名称  
        request.set_DomainName(self.mainDomain) #主域名

        try:
            self.client.do_action_with_exception(request)
            print('添加成功')
        except:
            print('添加失败')

    # 更新记录
    def _updateDomainRecord(self, value, rr, record_id):
        request = UpdateDomainRecordRequest.UpdateDomainRecordRequest()
        request.set_accept_format('json')

        # request.set_Priority('1')
        request.set_TTL(self.TTL)
        request.set_Value(value) # 新的ip地址
        request.set_Type(self.dns_type)
        request.set_RR(rr)
        request.set_RecordId(record_id)  # 更新记录需要指定 record_id ，该字段为记录的唯一标识，可以在获取方法的返回信息中得到该字段的值

        try:
            self.client.do_action_with_exception(request)
            flag = True
        except:
            flag = False
        return flag
    
    def updateDomainRecord(self, old_ip, record_id):
        cur_ip = self.getIP()
        if cur_ip == None or cur_ip == '0.0.0.0':
            print('检查网络是否正常连接')
        elif cur_ip == old_ip:
            print ("IP地址未变更，无需更新！")
        else:
            if self._updateDomainRecord(cur_ip, self.subDomainHead, record_id):
                print('更新成功!')
            else:
                print('更新失败，检查网络')

    # 删除记录
    def delDomainRecord(self, fullDomain):
        info = self.getDomainInfo(fullDomain)
        if info['TotalCount'] == 0:
            print('没有相关的记录信息，删除失败！')
        elif info["TotalCount"] == 1:
            print('准备删除记录')
            request = DeleteDomainRecordRequest.DeleteDomainRecordRequest()
            request.set_accept_format('json')

            record_id = info["DomainRecords"]["Record"][0]["RecordId"]
            request.set_RecordId(record_id) # 删除记录需要指定 record_id ，该字段为记录的唯一标识，可以在获取方法的返回信息中得到该字段的值
            try:
                self.client.do_action_with_exception(request)
                print('删除成功!')
            except:
                print('删除失败！')
        else:
            # 正常不应该有多条相同的记录，如果存在这种情况，应该手动去网站检查核实是否有操作失误
            print("存在多个相同子域名解析记录值，请核查后再操作！")

    # 有记录则更新，没有记录则新增
    def setDomainRecord(self):
        fullDomain = self.subDomainName(self.subDomainHead, self.mainDomain)
        info = self.getDomainInfo(fullDomain)
        if info['TotalCount'] == 0:
            print('准备添加新记录')
            value = self.getIP()
            if value == None or value == '0.0.0.0':
                print('检查网络是否正常连接')
            else:
                self.addDomainRecord(value, self.subDomainHead)
        elif info["TotalCount"] == 1:
            print('准备更新已有记录')
            record_id = info["DomainRecords"]["Record"][0]["RecordId"]
            old_ip = info['DomainRecords']['Record'][0]['Value']
            self.updateDomainRecord(old_ip, record_id)
        elif info["TotalCount"] == -1:
            print('检查网络是否正常连接')
        else:
            # 正常不应该有多条相同的记录，如果存在这种情况，应该手动去网站检查核实是否有操作失误
            print("存在多个相同子域名解析记录值，请核查删除后再操作！")


import yaml
LOAD_MAX_TIMES = 10


def iniConfig(folder='.'):
    cfg = {}
    cfg['alidns'] = {'regionId': 'cn-hangzhou',
                     'id': 'xxxxxxxxxxxxxx',
                     'password': 'xxxxxxxxxxxxxx',
                     'DomainName': 'xxxxxxxxxxxxxx',
                     'type': 'A',
                     'ttl': 600}
    cfg['router'] = {'type': 'tplink',
                     'ip': '192.168.1.1',
                     'username': 'NULL',
                     'password': 'xxxxxxxxx'}
    cfg['wan'] = {'ip': '8.8.8.8',
                  'port': 80}
    cfg['internet'] = {'url': 'http://www.3322.org/dyndns/getip'}
    cfg['ip_interface'] = 'router'
    with open(os.path.join(folder, 'config.yaml'), 'w', encoding='utf-8') as f:
        yaml.dump(cfg, f)


def loadConfig(folder='.'):
    global LOAD_MAX_TIMES
    LOAD_MAX_TIMES = LOAD_MAX_TIMES - 1
    if LOAD_MAX_TIMES >= 0:
        try:
            with open(os.path.join(folder, 'config.yaml'), 'r', encoding='utf-8') as f:
                cfg = yaml.load(f, Loader=yaml.FullLoader)
        except:
            print("加载参数文件出错，重新生成默认参数文件。剩余尝试次数{}".format(LOAD_MAX_TIMES))
            iniConfig()
            cfg = loadConfig(folder)
    else:
        cfg = None
    return cfg

