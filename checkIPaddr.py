#!/usr/bin/env python
#coding=utf-8

from core import DDNS, loadConfig

if __name__ == '__main__':
    # 地区节点 可选地区取决于你的阿里云帐号等级，普通用户只有四个，分别是杭州、上海、深圳、河北，具体参考官网API
    cfg = loadConfig()
    subDomainHead = 'test1'
    ddns = DDNS(cfg, subDomainHead)
    print('IP模式: {}'.format(ddns.ip_method))
    print('Wan IP: {}'.format(ddns.getWanIP()))
    print('Internet IP: {}'.format(ddns.getPublicIp()))
    print('Router IP: {}'.format(ddns.getRouterWanIP()))
    print('实际IP: {}'.format(ddns.getIP()))