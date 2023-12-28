import os
import hmac
import json
import uuid
import hashlib
import requests
from copy import deepcopy
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from typing import Callable, Dict, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

TYPE_AESCBC256_B64 = 0
TYPE_AESCBC128_HMACSHA256_B64 = 1
TYPE_AESCBC256_HMACSHA256_B64 = 2
TYPE_RSA2048_OAEPSHA256_B64 = 3
TYPE_RSA2048_OAEPSHA1_B64 = 4
TYPE_RSA2048_OAEPSHA256_HMACSHA256_B64 = 5
TYPE_RSA2048_OAEPSHA1_HMACSHA256_B64 = 6

class CipherString():
    @property
    def Type(self): return self.__type
    @property
    def IV(self): return self.__iv
    @property
    def IV_B64_str(self): return b64encode(self.__iv).decode('UTF-8')
    @property
    def CT(self): return self.__ct
    @property
    def CT_B64_str(self): return b64encode(self.__ct).decode('UTF-8')
    @property
    def MAC(self): return self.__mac
    @property
    def MAC_B64_str(self): return b64encode(self.__mac).decode('UTF-8')
    __type:int = None
    __iv:bytes = None
    __ct:bytes = None
    __mac:bytes = None
    def __init__(self, data:str) -> None:
        t, edata = data.split('.', 1)
        self.__type = int(t)
        datas = edata.split('|')
        if self.Type == TYPE_AESCBC256_B64:
            self.__iv = b64decode(datas[0].encode('UTF-8'))
            self.__ct = b64decode(datas[1].encode('UTF-8'))
        elif self.Type in [TYPE_AESCBC128_HMACSHA256_B64, TYPE_AESCBC256_HMACSHA256_B64]:
            self.__iv = b64decode(datas[0].encode('UTF-8'))
            self.__ct = b64decode(datas[1].encode('UTF-8'))
            self.__mac = b64decode(datas[2].encode('UTF-8'))
        elif self.Type in [TYPE_RSA2048_OAEPSHA256_B64, TYPE_RSA2048_OAEPSHA1_B64]:
            self.__ct = b64decode(datas[0].encode('UTF-8'))

    def HasMAC(self) -> bool:
        return self.Type not in [TYPE_AESCBC256_B64, TYPE_RSA2048_OAEPSHA256_B64, TYPE_RSA2048_OAEPSHA1_B64]

    def IsZero(self) -> bool:
        return bool(self.Type) and bool(self.__iv) and bool(self.__ct) and bool(self.__mac)

    def __str__(self) -> str:
        if self.IsZero():
            return ""
        if self.Type == TYPE_AESCBC256_B64:
            return '%d.%s.%s' % (self.Type, self.IV_B64_str, self.CT_B64_str)
        elif self.Type in [TYPE_AESCBC128_HMACSHA256_B64, TYPE_AESCBC256_HMACSHA256_B64]:
            return '%d.%s.%s.%s' % (self.Type, self.IV_B64_str, self.CT_B64_str, self.MAC_B64_str)
        elif self.Type in [TYPE_RSA2048_OAEPSHA256_B64, TYPE_RSA2048_OAEPSHA1_B64]:
            return '%d.%s' % (self.Type, self.CT_B64_str)
        return ""


class HttpStatusErrror(Exception): pass
class UnSupportKdfError(Exception): pass
class DecryptHmacMisMatchError(Exception): pass
class DecryptUnSupportTypeError(Exception): pass

class VaultwardenAPI():
    @property
    def session(self): return self.__session
    @property
    def baseUrl(self): return self.__baseUrl
    @property
    def email(self): return self.__email
    @property
    def Kdf(self): return (self.__ident or self.__kdf)['Kdf']
    @property
    def KdfIterations(self): return (self.__ident or self.__kdf)['KdfIterations']
    @property
    def masterKey(self):
        if not self.__masterKey:
            self.__masterKey = hashlib.pbkdf2_hmac(
                hash_name = 'sha256',
                password = self.__masterPassword.encode('UTF-8'), 
                salt = self.__email.encode('UTF-8'),
                iterations = self.KdfIterations
            )
        return self.__masterKey
    @property
    def deviceId(self): return self.__devInfo['device_id']
    @property
    def ident(self): return deepcopy(self.__ident)
    @property
    def decryptKey(self): return self.__decryptKey
    @property
    def decryptHmacKey(self): return self.__decryptHmacKey
    @property
    def decryptPrivateKey(self): return self.__decryptPrivateKey
    @property
    def tokenType(self): return self.__ident['token_type']
    @property
    def accessToken(self): return self.__ident['access_token']
    @property
    def refreshToken(self): return self.__ident['refresh_token']
    @property
    def decryptedCiphers(self): return deepcopy(self.__decrypt_ciphers)
    @property
    def decryptedFolders(self): return deepcopy(self.__decrypt_folders)
    def __init__(self, baseUrl:str, email:str, masterPassword:str, configPath:str = None) -> None:
        self.__init_vars()
        self.__baseUrl = baseUrl.rstrip("/")
        self.__email = email
        self.__masterPassword = masterPassword
        self.__session = requests.session()
        configPath = configPath or os.path.join(os.path.expanduser('~'), ".config", "python-vaultwarden")
        if not os.path.exists(configPath):
            os.makedirs(configPath)
        self.__deviceInfoFile = os.path.join(configPath, "deviceInfo.json")
        self.__syncFile = os.path.join(configPath, "syncData.json")
        self.__idnetFile = os.path.join(configPath, "tokenInfo.json")
        self.loadDevInfo()
        self.loadIdent()
        self.loadSync()

    def __init_vars(self):
        self.__baseUrl:str = None
        self.__email:str = None
        self.__masterPassword:str = None
        self.__session:requests.Session = None
        self.__masterKey:bytes = None
        self.__ident:dict = None
        self.__decryptKey:bytes = None
        self.__decryptHmacKey:bytes = None
        self.__kdf:dict = None
        self.__sync:dict = None
        self.__decrypt_folders:Dict[str, str] = None
        self.__decrypt_ciphers:Dict[str, dict] = None
        self.__decryptPrivateKey:str = None

    def saveDevInfo(self):
        devInfo = {
            'device_id': self.deviceId,
            'last_sync': goUTCStrftime(self.__devInfo['last_sync'])
        }
        with open(self.__deviceInfoFile, 'w', encoding='UTF-8') as f:
            json.dump(devInfo, f)

    def loadDevInfo(self):
        try:
            with open(self.__deviceInfoFile, 'r', encoding='UTF-8') as f:
                self.__devInfo = json.load(f)
                self.__devInfo['last_sync'] = goUTCStrptime(self.__devInfo['last_sync'])
        except:
            self.__devInfo = {'device_id': str(uuid.uuid4()), 'last_sync': datetime.now()}
            self.saveDevInfo()

    def saveIdent(self):
        data = self.ident
        data['token_expiry'] = goUTCStrftime(self.__ident['token_expiry'])
        with open(self.__idnetFile, 'w', encoding='UTF-8') as f:
            json.dump(data, f, ensure_ascii=False)

    def loadIdent(self):
        try:
            now = datetime.now()
            with open(self.__idnetFile, 'r', encoding='UTF-8') as f:
                self.__ident = json.load(f)
            self.__ident['token_expiry'] = goUTCStrptime(self.__ident['token_expiry'])
            if self.__ident['token_expiry'] < now:
                self.__ident = None
            else:
                self.decryptProfileKey(self.__ident['Key'])
                self.__decryptPrivateKey = self.decryptUserData(self.__ident['PrivateKey'])
        except:
            pass

    def saveSync(self):
        with open(self.__syncFile, 'w', encoding='UTF-8') as f:
            json.dump(self.__sync, f, ensure_ascii=False)

    def loadSync(self):
        try:
            with open(self.__syncFile, 'r', encoding='UTF-8') as f:
                self.__sync = json.load(f)
            self.__fullDecrypt()
        except:
            pass

    def _persureResponse(self, resp:requests.Response) -> dict:
        if resp.status_code != 200:
            raise HttpStatusErrror("HTTP status code: %s; message: %s" % (resp.status_code, resp.text))
        return resp.json()

    def account_prelogin(self):
        uri = self.baseUrl + '/api/accounts/prelogin'
        res = self.session.post(uri, json={"Email": self.email})
        self.__kdf = self._persureResponse(res)
        return self.__kdf.copy()

    def getHashedPassword(self) -> str:
        if self.Kdf != 0:
            raise UnSupportKdfError("hash password only support Kdf == 0 (PBKDF2_SHA256)")
        hashlibPwd = b64encode(hashlib.pbkdf2_hmac('sha256', self.masterKey, self.__masterPassword.encode('UTF-8'), 1)).decode()
        return hashlibPwd

    def identity_token(self, hashedPassword:str) -> dict:
        uri = self.baseUrl + '/identity/connect/token'
        res = self.session.post(uri, data={
            "grant_type": "password",
            "username": self.email,
            "password": hashedPassword,
            "scope": "api offline_access",
            "client_id": "connector",
            "deviceType": "6",
            "deviceName": "bitwarden-http-api",
            "deviceIdentifier": self.deviceId
        })
        self.__ident = self._persureResponse(res)
        self.__ident['token_expiry'] = datetime.now() + timedelta(seconds=self.__ident['expires_in'])
        self.saveIdent()
        self.decryptProfileKey(self.__ident['Key'])
        self.__decryptPrivateKey = self.decryptUserData(self.__ident['PrivateKey'])
        return self.ident

    def identity_token_refresh(self, refresh_token:str = None) -> dict:
        uri = self.baseUrl + '/identity/connect/token'
        res = self.session.post(uri, data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token or self.refreshToken,
        })
        self.__ident = self._persureResponse(res)
        self.__ident['token_expiry'] = datetime.now() + timedelta(seconds=self.__ident['expires_in'])
        self.saveIdent()
        self.decryptProfileKey(self.__ident['Key'])
        self.__decryptPrivateKey = self.decryptUserData(self.__ident['PrivateKey'])
        return self.ident

    def decryptProfileKey(self, data:str) -> Tuple[str, str]:
        from hkdf import hkdf_expand
        cstr = CipherString(data)
        decKey = hkdf_expand(self.masterKey, info=b'enc', hash=hashlib.sha256)
        decMacKey = hkdf_expand(self.masterKey, info=b'mac', hash=hashlib.sha256)
        dst = decryptWith(cstr, decKey, decMacKey)
        if len(dst) == 64:
            self.__decryptKey = dst[:32]
            self.__decryptHmacKey = dst[32:]
        elif len(dst) == 32:
            self.__decryptKey = dst
        return self.decryptKey, self.decryptHmacKey

    def fullLogin(self, token:str = None) -> bool:
        if not token and self.__ident:
            token = self.refreshToken
        if token:
            if self.__ident['token_expiry'] < datetime.now():
                self.identity_token_refresh(token)
        else:
            self.account_prelogin()
            hpwd = self.getHashedPassword()
            self.identity_token(hpwd)

    def sync(self, after:int = 0):
        if (datetime.now() - self.__devInfo['last_sync']).total_seconds() < after:
            return
        if self.__ident['token_expiry'] < datetime.now():
            self.identity_token_refresh()
        uri = self.baseUrl + '/api/sync'
        res = self.session.get(uri, headers={
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "Authorization": "%s %s" % (self.tokenType, self.accessToken),
        })
        self.__sync = self._persureResponse(res)
        self.__devInfo['last_sync'] = datetime.now()
        self.__fullDecrypt()
        self.saveDevInfo()
        self.saveSync()

    def dump(self) -> dict:
        return deepcopy(self.__sync)

    def decryptUserData(self, data:str):
        return decryptWith(CipherString(data), self.decryptKey, self.decryptHmacKey)

    def __fullDecrypt(self):
        if not self.__sync:
            return
        self.__fullFoldersDecrypt()
        self.__fullCiphersDecrypt()

    def __fullFoldersDecrypt(self):
        self.__decrypt_folders = {}
        for f in self.__sync['Folders']:
            name = self.decryptUserData(f['Name']).decode('UTF-8')
            self.__decrypt_folders[name] = f['Id']

    def __fullCiphersDecrypt(self):
        def decryptData(d:str) -> str:
            if not d:
                return d
            s = CipherString(d)
            if s.Type in [TYPE_AESCBC256_B64, TYPE_AESCBC256_HMACSHA256_B64]:
                return decryptWith(s, self.decryptKey, self.decryptHmacKey).decode('UTF-8')
            elif s.Type in [
                    TYPE_RSA2048_OAEPSHA1_B64, TYPE_RSA2048_OAEPSHA1_HMACSHA256_B64,
                    TYPE_RSA2048_OAEPSHA256_B64, TYPE_RSA2048_OAEPSHA256_HMACSHA256_B64
                ]:
                return rsaDecryptWith(s, self.decryptPrivateKey).decode('UTF-8')
            else:
                raise DecryptUnSupportTypeError(s.Type)
        self.__decrypt_ciphers = {}
        for c in self.__sync['Ciphers']:
            if c['Type'] == 1: # Login
                d = self.__decryptLoginData(c, decryptData)
                self.__decrypt_ciphers[d['Name']] = d
            elif c['Type'] == 2: # SecureNote
                d = self.__decryptSecureNoteData(c, decryptData)
                self.__decrypt_ciphers[d['Name']] = d

    @staticmethod
    def __decryptLoginData(cipher:dict, decryptFunc:Callable[[str], str]) -> dict:
        resp = deepcopy(cipher)
        resp['Data']['Name'] = decryptFunc(cipher['Data']['Name'])
        resp['Data']['Password'] = decryptFunc(cipher['Data']['Password'])
        resp['Data']['Totp'] = decryptFunc(cipher['Data']['Totp'])
        resp['Data']['Uri'] = decryptFunc(cipher['Data']['Uri'])
        for idx, uri in enumerate(cipher['Data']['Uris'] or []):
            resp['Data']['Uris'][idx]['Uri'] = decryptFunc(uri['Uri'])
        if cipher['Data']['Fields']:
            for idx, field in enumerate(cipher['Data']['Fields'] or []):
                resp['Data']['Fields'][idx]['Name'] = decryptFunc(field['Name'])
                resp['Data']['Fields'][idx]['Value'] = decryptFunc(field['Value'])
        if cipher['Data']['PasswordHistory']:
            for idx, his in enumerate(cipher['Data']['PasswordHistory'] or []):
                resp['Data']['PasswordHistory'][idx]['Password'] = decryptFunc(his['Password'])
                resp['Data']['PasswordHistory'][idx]['LastUsedDate'] = datetime.strptime(his['LastUsedDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        resp['Data']['Username'] = decryptFunc(cipher['Data']['Username'])
        resp['Login']['Password'] = decryptFunc(cipher['Login']['Password'])
        resp['Login']['Totp'] = decryptFunc(cipher['Login']['Totp'])
        resp['Login']['Uri'] = decryptFunc(cipher['Login']['Uri'])
        resp['Login']['Username'] = decryptFunc(cipher['Login']['Username'])
        for idx, uri in enumerate(cipher['Login']['Uris'] or []):
            resp['Login']['Uris'][idx]['Uri'] = decryptFunc(uri['Uri'])
        if cipher['Fields']:
            for idx, field in enumerate(cipher['Fields'] or []):
                resp['Fields'][idx]['Name'] = decryptFunc(field['Name'])
                resp['Fields'][idx]['Value'] = decryptFunc(field['Value'])
        if cipher['PasswordHistory']:
            for idx, his in enumerate(cipher['PasswordHistory'] or []):
                resp['PasswordHistory'][idx]['Password'] = decryptFunc(his['Password'])
                resp['PasswordHistory'][idx]['LastUsedDate'] = datetime.strptime(his['LastUsedDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        resp['Name'] = decryptFunc(cipher['Name'])
        return resp

    @staticmethod
    def __decryptSecureNoteData(cipher:dict, decryptFunc:Callable[[str], str]) -> dict:
        resp = deepcopy(cipher)
        resp['Data']['Name'] = decryptFunc(cipher['Data']['Name'])
        resp['Data']['Notes'] = decryptFunc(cipher['Data']['Notes'])
        if cipher['Data']['Fields']:
            for idx, field in enumerate(cipher['Data']['Fields']):
                resp['Data']['Fields'][idx]['Name'] = decryptFunc(field['Name'])
                resp['Data']['Fields'][idx]['Value'] = decryptFunc(field['Value'])
        resp['Name'] = decryptFunc(cipher['Name'])
        resp['Notes'] = decryptFunc(cipher['Notes'])
        if cipher['Fields']:
            for idx, field in enumerate(cipher['Fields']):
                resp['Fields'][idx]['Name'] = decryptFunc(field['Name'])
                resp['Fields'][idx]['Value'] = decryptFunc(field['Value'])
        return resp

    def searchByName(self, name:str, equal:bool = False):
        if not name:
            return []
        if name in self.__decrypt_ciphers:
            return [self.__decrypt_ciphers[name]]
        resp = []
        if equal:
            return resp
        for cname, d in self.__decrypt_ciphers.items():
            if name in cname:
                resp.append(deepcopy(d))
        return resp

    def searchByUserName(self, name:str, equal:bool = False):
        if not name:
            return []
        resp = []
        for d in self.__decrypt_ciphers.values():
            if d['Type'] == 1 and ( # Login
                (name in d['Login']['Username'] and not equal)
                or (name == d['Login']['Username'] and equal)
            ):
                resp.append(deepcopy(d))
        return resp

    def getListByFolder(self, name:str, equal:bool = False):
        if not name:
            return []
        fids = []
        if equal:
            fid = self.__decrypt_folders.get(name, None)
            if not fid:
                return resp
            fids.append(fid)
        else:
            for fname, d in self.__decrypt_folders.items():
                if name in fname:
                    fids.append(d)
        resp = []
        for d in self.__decrypt_ciphers.values():
            if d['FolderId'] in fids:
                resp.append(deepcopy(d))
        return resp


def unpadPKCS7(src:bytes, size:int) -> bytes:
    n = src[-1]
    if len(src) % size != 0:
        raise RuntimeError("expected PKCS7 padding for block size %d, but have %d bytes" % (size, len(src)))
    if len(src) < n:
        raise RuntimeError("cannot unpad %d bytes out of a total of %d" % (n, len(src)))
    return src[:-n]

def decryptWith(s:CipherString, key:bytes, macKey:bytes) -> bytes:
    if s.Type not in [TYPE_AESCBC256_B64, TYPE_AESCBC256_HMACSHA256_B64]:
        raise DecryptUnSupportTypeError()
    if s.HasMAC():
        msg = s.IV + s.CT
        mac = hmac.new(macKey, digestmod=hashlib.sha256)
        mac.update(msg)
        expectedMAC = mac.digest()
        if not hmac.compare_digest(s.MAC, expectedMAC):
            raise DecryptHmacMisMatchError()
    cipher = Cipher(algorithms.AES(key), modes.CBC(s.IV))
    dst = cipher.decryptor()
    block = dst.update(s.CT) + dst.finalize()
    data = unpadPKCS7(block, algorithms.AES.block_size / 16)
    return data

def rsaDecryptWith(s:CipherString, privateKey:bytes) -> bytes:
    if s.Type not in [
            TYPE_RSA2048_OAEPSHA1_B64, TYPE_RSA2048_OAEPSHA1_HMACSHA256_B64,
            TYPE_RSA2048_OAEPSHA256_B64, TYPE_RSA2048_OAEPSHA256_HMACSHA256_B64
        ]:
        raise DecryptUnSupportTypeError()

    pri:rsa.RSAPrivateKey = serialization.load_der_private_key(privateKey)

    if s.Type in [TYPE_RSA2048_OAEPSHA256_B64, TYPE_RSA2048_OAEPSHA256_HMACSHA256_B64]:
        oaep = padding.OAEP(mgf=padding.PKCS1v15(), algorithm=hashes.SHA256())
    elif s.Type in [TYPE_RSA2048_OAEPSHA1_B64, TYPE_RSA2048_OAEPSHA1_HMACSHA256_B64]:
        oaep = padding.OAEP(mgf=padding.PKCS1v15(), algorithm=hashes.SHA1())
    else:
        raise DecryptUnSupportTypeError()
    return pri.decrypt(s.CT, oaep)

def goUTCStrftime(time:datetime) -> str:
    return datetime.utcfromtimestamp(time.timestamp()).strftime("%Y-%m-%dT%H:%M:%S.%f00Z")

def goUTCStrptime(time:str) -> datetime:
    return datetime.fromtimestamp(
        datetime.strptime(time[:-3],"%Y-%m-%dT%H:%M:%S.%f").timestamp()+28800
    )
