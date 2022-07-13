# python-vaultwarden <!-- omit in toc -->
## 自建 VaultWarden 服务器的简单 API 脚本 <!-- omit in toc -->

- [依赖要求](#依赖要求)
- [使用方法](#使用方法)

## 依赖要求
注：requirement.txt 附带的版本号为开发使用的版本  
- python >= 3, < 3.10  
  请根据 pycrypto 支持情况自行决定Python版本
- requests>=2.27.1
- passlib>=1.7.4
- hkdf>=0.0.3
- pycrypto>=2.6.1

## 使用方法
```python
from api import VaultwardenAPI
vapi = VaultwardenAPI(baseUrl, email, masterPassword) # 配置服务器与账号消息
vapi.fullLogin() # 登录
vapi.sync(86400) # 如果与上次同步间隔小于86400秒（一天）则不同步
alist = vapi.searchByName('somename') # 模糊搜索
blist = vapi.searchByName('JustThisName', equal = True) # 全匹配搜索
allItemInFolders = vapi.getListByFolder('somefoldername') # 模糊搜索目录
allItemInOneFolder = vapi.getListByFolder('JustThisFolder', equal = True) # 全匹配目录
allCiphers = vapi.decryptedCiphers # 拿所有解密后的 Ciphers
allFolders = vapi.decryptedFolders # 拿所有解密后的 Folders
```