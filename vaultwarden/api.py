import re
import os
import hmac
import gzip
import json
import uuid
import hashlib
import logging
import requests
import typing as _t
from copy import deepcopy
from traceback import format_exc
from urllib.parse import urlparse
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .response import SyncResponse, CipherResponse
from .types import *
from .errors import *

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
    __type:EncryptionType = None
    __iv:bytes = None
    __ct:bytes = None
    __mac:bytes = None
    def __init__(self, data:str) -> None:
        self.__logger = logging.getLogger(__package__).getChild(type(self).__name__)
        t, edata = data.split('.', 1)
        self.__logger.debug('EncryptionType: %s', t)
        self.__type = EncryptionType(int(t))
        datas = edata.split('|')
        self.__logger.debug('datas: %s', datas)
        if self.Type == EncryptionType.AesCbc256_B64:
            self.__iv = b64decode(datas[0].encode('UTF-8'))
            self.__ct = b64decode(datas[1].encode('UTF-8'))
        elif self.Type in [EncryptionType.AesCbc128_HmacSha256_B64, EncryptionType.AesCbc256_HmacSha256_B64]:
            self.__iv = b64decode(datas[0].encode('UTF-8'))
            self.__ct = b64decode(datas[1].encode('UTF-8'))
            self.__mac = b64decode(datas[2].encode('UTF-8'))
        elif self.Type in [EncryptionType.Rsa2048_OaepSha256_B64, EncryptionType.Rsa2048_OaepSha1_B64]:
            self.__ct = b64decode(datas[0].encode('UTF-8'))
        else:
            raise DecryptUnSupportTypeError(t)

    def HasMAC(self) -> bool:
        return self.Type not in [EncryptionType.AesCbc256_B64, EncryptionType.Rsa2048_OaepSha256_B64, EncryptionType.Rsa2048_OaepSha1_B64]

    def IsZero(self) -> bool:
        return self.Type is None and self.__iv is None and self.__ct is None and self.__mac is None

    def __str__(self) -> str:
        if self.IsZero():
            return ""
        if self.Type == EncryptionType.AesCbc256_B64:
            return '%d.%s.%s' % (self.Type.value, self.IV_B64_str, self.CT_B64_str)
        elif self.Type in [EncryptionType.AesCbc128_HmacSha256_B64, EncryptionType.AesCbc256_HmacSha256_B64]:
            return '%d.%s.%s.%s' % (self.Type.value, self.IV_B64_str, self.CT_B64_str, self.MAC_B64_str)
        elif self.Type in [EncryptionType.Rsa2048_OaepSha256_B64, EncryptionType.Rsa2048_OaepSha1_B64]:
            return '%d.%s' % (self.Type.value, self.CT_B64_str)
        return ""

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
    def KdfMemory(self): return (self.__ident or self.__kdf)['KdfMemory'] * 1024
    @property
    def KdfParallelism(self): return (self.__ident or self.__kdf)['KdfParallelism']
    @property
    def masterKey(self):
        if not self.__masterKey:
            if self.Kdf == 0:
                self.__masterKey = hashlib.pbkdf2_hmac(
                    hash_name = 'sha256',
                    password = self.__masterPassword.encode('UTF-8'), 
                    salt = self.__email.encode('UTF-8'),
                    iterations = self.KdfIterations
                )
            elif self.Kdf == 1:
                self.__masterKey = hash_secret_raw(
                    secret = self.__masterPassword.encode('UTF-8'),
                    salt = hashlib.sha256(self.__email.encode('UTF-8')).digest(),
                    time_cost = self.KdfIterations,
                    memory_cost = self.KdfMemory,
                    parallelism = self.KdfParallelism,
                    hash_len = 32,
                    type = Type.ID
                )
            else:
                raise UnSupportKdfError("hash password only support Kdf == 0 (PBKDF2_SHA256) or Kdf == 1 (Argon2id)")
        return self.__masterKey
    @property
    def deviceId(self): return self.__devInfo['device_id']
    @property
    def ident(self): return self.__ident
    @ident.deleter
    def ident(self): self.__ident = None
    @property
    def decryptPrivateKey(self): return self.__decryptPrivateKey
    @property
    def tokenType(self): return self.__ident['token_type']
    @property
    def accessToken(self): return self.__ident['access_token']
    @property
    def refreshToken(self): return self.__ident.get('refresh_token', None)
    @property
    def Ciphers(self): return self.__sync.ciphers
    @property
    def Folders(self): return self.__sync.folders
    @property
    def Collections(self): return self.__sync.collections
    @property
    def Domains(self): return self.__sync.domains
    @property
    def Policies(self): return self.__sync.policies
    @property
    def Sends(self): return self.__sync.sends
    def __init__(self, baseUrl:str, email:str, masterPassword:str, api_scope:str = "api" ,configPath:str = None) -> None:
        self.__init_vars()
        self.__baseUrl = baseUrl.rstrip("/")
        self.__email = email
        self.__masterPassword = masterPassword
        self.__scope = api_scope
        self.__session = requests.session()
        baseDomain = urlparse(self.baseUrl).hostname
        configPath = configPath or os.path.join(os.path.expanduser('~'), ".config", "python-vaultwarden", baseDomain)
        if not os.path.exists(configPath):
            os.makedirs(configPath)
        self.__deviceInfoFile = os.path.join(configPath, "deviceInfo.json")
        self.__syncFile = os.path.join(configPath, "syncData.json.gz")
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
        self.__kdf:dict = None
        self.__sync:SyncResponse = None
        self.__decryptPrivateKey:str = None
        self.__decryptKeys:_t.Dict[str, _t.Tuple[bytes, bytes]] = {}
        self.__logger = logging.getLogger(__package__).getChild(type(self).__name__)

    def __enter__(self):
        self.fullLogin()
        self.sync(86400)
        return self
    
    def __exit__(self, *args, **kwargs): pass

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
        data = deepcopy(self.ident)
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
                self.__decryptPrivateKey = self.decryptData(self.__ident['PrivateKey'])
        except:
            self.__logger.debug(format_exc())

    def saveSync(self, data):
        with gzip.open(self.__syncFile, 'wt', compresslevel=9, encoding='UTF-8') as f:
            json.dump(data, f, ensure_ascii=False)

    def loadSync(self):
        try:
            with gzip.open(self.__syncFile, 'rt', encoding='UTF-8') as f:
                self.__sync = SyncResponse(json.load(f))
            self.decryptSync()
        except:
            self.__logger.debug(format_exc())

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
        return b64encode(hashlib.pbkdf2_hmac('sha256', self.masterKey, self.__masterPassword.encode('UTF-8'), 1)).decode()

    def identity_token_credentials(self):
        uri = self.baseUrl + '/identity/connect/token'
        res = self.session.post(uri, data={
            "grant_type": "client_credentials",
            "scope": self.__scope,
            "client_id": self.__client_id,
            "client_secret": self.__client_secret,
            "deviceType": "6",
            "deviceName": "python-vaultwarden",
            "deviceIdentifier": self.deviceId
        })
        self.__ident = self._persureResponse(res)
        self.decryptIdent()

    def identity_token_password(self, hashedPassword:str) -> dict:
        uri = self.baseUrl + '/identity/connect/token'
        res = self.session.post(uri, data={
            "grant_type": "password",
            "username": self.email,
            "password": hashedPassword,
            "scope": "api offline_access",
            "client_id": "connector",
            "deviceType": "6",
            "deviceName": "python-vaultwarden",
            "deviceIdentifier": self.deviceId
        })
        self.__ident = self._persureResponse(res)
        self.decryptIdent()

    def identity_token_refresh(self, refresh_token:str = None):
        uri = self.baseUrl + '/identity/connect/token'
        res = self.session.post(uri, data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token or self.refreshToken,
        })
        self.__ident = self._persureResponse(res)
        self.decryptIdent()

    def decryptIdent(self):
        if 'token_expiry' in self.__ident:
            self.__ident['token_expiry'] = goUTCStrptime(self.__ident['token_expiry'])
        else:
            self.__ident['token_expiry'] = datetime.now() + timedelta(seconds=self.__ident['expires_in'])
        self.saveIdent()
        self.decryptProfileKey(self.__ident['Key'])
        self.__decryptPrivateKey = self.decryptData(self.__ident['PrivateKey'], encoding=False)

    def decryptProfileKey(self, data:str) -> _t.Tuple[str, str]:
        from hkdf import hkdf_expand
        cstr = CipherString(data)
        decKey = hkdf_expand(self.masterKey, info=b'enc', hash=hashlib.sha256)
        decMacKey = hkdf_expand(self.masterKey, info=b'mac', hash=hashlib.sha256)
        dst = decryptWith(cstr, decKey, decMacKey)
        self.__decryptKeys[None] = splitKey(cstr.Type, dst)

    def fullLogin(self, token:str = None):
        if not token and self.__ident:
            token = self.refreshToken
        if self.__ident and self.__ident['token_expiry'] >= datetime.now():
            return
        if token:
            self.identity_token_refresh(token)
        else:
            self.account_prelogin()
            hpwd = self.getHashedPassword()
            self.identity_token_password(hpwd)

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
        sync = self._persureResponse(res)
        self.saveSync(sync)
        self.__sync = SyncResponse(sync)
        self.decryptSync()
        self.__devInfo['last_sync'] = datetime.now()
        self.saveDevInfo()

    def decryptSync(self):
        self.decryptProfileKey(self.__sync.profile.key)
        self.__decryptPrivateKey = self.decryptData(self.__sync.profile.privateKey, encoding=None)
        for org in self.__sync.profile.organizations or []:
            self.__decryptKeys[org.id] = splitKey(None, self.decryptData(org.key, encoding=None))
        self.__sync.DecryptAll(self.decryptData)

    def dump(self) -> dict: return self.__sync.toJson()

    def decryptData(self, src:str, orgId:str = None, encoding:str = 'UTF-8') -> str:
        if not src:
            return src
        try:
            cipher = CipherString(src)
        except:
            return src
        if cipher.Type in EncryptionTypeAes:
            self.__logger.debug('orgId: %s', orgId)
            dst = decryptWith(cipher, *self.__decryptKeys.get(orgId, self.__decryptKeys[None]))
        elif cipher.Type in EncryptionTypeRsa:
            dst = rsaDecryptWith(cipher, self.decryptPrivateKey)
        else:
            raise DecryptUnSupportTypeError(cipher.Type)
        if encoding:
            return dst.decode(encoding)
        return dst

    def searchCiphers(
            self, id:str = None, folder_id:str = None, folder:str = None, name:str = None, username:str = None,
            domain:str = None, domain_type:UriMatchType = UriMatchType.Domain, equal:bool = False, deleted:bool = False
        ):
        iter = filter(lambda x:not bool(x.deletedDate) or deleted, self.Ciphers)
        if id is not None:
            iter = filter(lambda x:x.id == id, iter)
        elif name is not None:
            iter = filter(lambda x:x.name == name, iter) if equal else filter(lambda x:name in x.name, iter)
        if folder is not None:
            try:
                folder_id = next(self.searchFolders(id=folder_id))
            except StopIteration:
                folder_id = None
        if folder_id is not None:
            iter = filter(lambda x:x.folderId == folder_id, iter)
        if username is not None:
            iter = filter(lambda x:x.type == 1 and x.login.username == username, iter) if equal else filter(lambda x:x.type == 1 and name in x.login.username, iter)
        if domain is not None:
            iter = filter(domainMatch(domain_type, domain), iter)
        yield from iter

    def searchFolders(self, id:str = None, name:str = None, equal:bool = False):
        iter = self.Folders
        if id is not None:
            iter = filter(lambda x:x.id == id, iter)
        elif name is not None:
            iter = filter(lambda x:x.name == name, iter) if equal else filter(lambda x:name in x.name, iter)
        yield from iter

def splitKey(t:EncryptionType, key:bytes) -> _t.Tuple[bytes, _t.Optional[bytes]]:
    if t == None:
        if len(key) == 32:
            t = EncryptionType.AesCbc256_B64
        elif len(key) == 64:
            t = EncryptionType.AesCbc256_HmacSha256_B64
        else:
            raise DecryptUnSupportTypeError("Unable to determine encType.")
    if t == EncryptionType.AesCbc256_B64 and len(key) == 32:
        return key, None
    elif t == EncryptionType.AesCbc128_HmacSha256_B64 and len(key) == 32:
        return key[:16], key[16:]
    elif t == EncryptionType.AesCbc256_HmacSha256_B64 and len(key) == 64:
        return key[:32], key[32:]
    raise DecryptUnSupportTypeError("Unsupported encType/key length.")

def unpadPKCS7(src:bytes, size:int) -> bytes:
    n = src[-1]
    if len(src) % size != 0:
        raise RuntimeError("expected PKCS7 padding for block size %d, but have %d bytes" % (size, len(src)))
    if len(src) < n:
        raise RuntimeError("cannot unpad %d bytes out of a total of %d" % (n, len(src)))
    return src[:-n]

def decryptWith(s:CipherString, key:bytes, macKey:bytes) -> bytes:
    if s.Type not in EncryptionTypeAes:
        raise DecryptUnSupportTypeError(s.Type)
    if s.HasMAC() and macKey:
        msg = s.IV + s.CT
        mac = hmac.new(macKey, digestmod=hashlib.sha256)
        mac.update(msg)
        expectedMAC = mac.digest()
        if not hmac.compare_digest(s.MAC, expectedMAC):
            raise DecryptHmacMisMatchError(f'{b64encode(s.MAC).decode()} != {b64encode(expectedMAC).decode()}')
    cipher = Cipher(algorithms.AES(key), modes.CBC(s.IV))
    dst = cipher.decryptor()
    block = dst.update(s.CT) + dst.finalize()
    data = unpadPKCS7(block, algorithms.AES.block_size / 16)
    return data

def rsaDecryptWith(s:CipherString, privateKey:bytes) -> bytes:
    if s.Type not in EncryptionTypeRsa:
        raise DecryptUnSupportTypeError()

    pri:rsa.RSAPrivateKey = serialization.load_der_private_key(privateKey, None)

    if s.Type in [EncryptionType.Rsa2048_OaepSha256_B64, EncryptionType.Rsa2048_OaepSha256_HmacSha256_B64]:
        oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    elif s.Type in [EncryptionType.Rsa2048_OaepSha1_B64, EncryptionType.Rsa2048_OaepSha1_HmacSha256_B64]:
        oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    else:
        raise DecryptUnSupportTypeError()
    return pri.decrypt(s.CT, oaep)

def goUTCStrftime(time:datetime) -> str:
    return datetime.utcfromtimestamp(time.timestamp()).strftime("%Y-%m-%dT%H:%M:%S.%f00Z")

def goUTCStrptime(time:str) -> datetime:
    return datetime.fromtimestamp(
        datetime.strptime(time[:-3],"%Y-%m-%dT%H:%M:%S.%f").timestamp()+28800
    )

def domainMatch(mode:int, dst:str) -> _t.Callable[[dict], bool]:
    def dmatch(cipher:CipherResponse) -> bool:
        if cipher.type != 1:
            return False
        status = False
        for uri in cipher.login.uris or []:
            _mode = uri.match or mode
            if _mode == UriMatchType.Domain:
                srcu = urlparse(uri.uri)
                srch = srcu.hostname or srcu.path
                src = '.'.join(srch.split('.')[1:] or [srch])
                dstu = urlparse(dst)
                dsth = dstu.hostname or dstu.path
                _dst = '.'.join(dsth.split('.')[1:] or [dsth])
                status |= _dst == src
            elif _mode == UriMatchType.Host:
                status |= urlparse(dst).hostname == urlparse(uri.uri).hostname
            elif _mode == UriMatchType.Exact:
                status |= dst == uri.uri
            elif _mode == UriMatchType.StartsWith:
                status |=  uri.uri.startswith(dst)
            elif _mode == UriMatchType.RegularExpression:
                status |= re.match(uri.uri, dst) is not None
            else:
                status |= False
        return status
    return dmatch

