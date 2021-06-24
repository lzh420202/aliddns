from core import DDNS, loadConfig
import os

if __name__ == "__main__":
    file_path = os.path.abspath(__file__)
    real_workdir = os.path.dirname(file_path)
    cfg = loadConfig(real_workdir)
    if cfg == None:
        print('达到最大参数文件读取次数，请确保文件正常！')
    else:
        subDomainHead = 'test1'
        ddns = DDNS(cfg, subDomainHead)
        ddns.setDomainRecord()