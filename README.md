# python-vaultwarden <!-- omit in toc -->
## 自建 VaultWarden 服务器的简单 API 脚本 <!-- omit in toc -->

- [依赖要求](#依赖要求)
- [使用方法](#使用方法)

## 依赖要求
注：requirement.txt 附带的版本号为开发使用的版本  
- python>=3
- requests>=2.31.0
- passlib>=1.7.4
- hkdf>=0.0.3
- cryptography>=41.0.5
- argon2-cffi>=23.1.0

## 使用方法
```python
from vaultwarden import *                                                 # VaultwardenAPI, UriMatchType
with VaultwardenAPI(baseUrl, email, masterPassword) as vapi:              # 配置服务器与账号消息
    vapi.fullLogin()                                                      # 登录
    vapi.sync(86400)                                                      # 如果与上次同步间隔小于86400秒（一天）则不同步
    alist = list(vapi.searchCiphers(name = 'somename'))                   # 模糊搜索
    blist = list(vapi.searchCiphers(name = 'JustThisName', equal = True)) # 全匹配搜索
    blist = list(vapi.searchCiphers(domain = 'http://github.com', domain_type = UriMatchType.Host))
                                                                          # 匹配域名查询
    allItemInFolders = list(vapi.searchFolders(name = 'somefoldername'))  # 模糊搜索目录
    allItemInOneFolder = list(vapi.searchFolders(name = 'JustThisFolder', equal = True)) 
                                                                          # 全匹配目录
    allCiphers = vapi.Ciphers                                             # 拿所有解密后的 Ciphers
    allFolders = vapi.Folders                                             # 拿所有解密后的 Folders
```