from core import DDNS, loadConfig

if __name__ == "__main__":
    cfg = loadConfig()
    if cfg == None:
        print('达到最大参数文件读取次数，请确保文件正常！')
    else:
        subDomainHead = 'test1'
        ddns = DDNS(cfg, subDomainHead)
        ddns.setDomainRecord()