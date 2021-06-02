from core import DDNS, iniConfig, loadConfig

if __name__ == "__main__":
    # iniConfig()
    cfg = loadConfig()
    subDomainHead = 'test1'
    ddns = DDNS(cfg, subDomainHead)
    ddns.setDomainRecord()