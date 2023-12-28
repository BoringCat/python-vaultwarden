from enum import Enum

class EncryptionType(Enum):
    AesCbc256_B64 = 0
    AesCbc128_HmacSha256_B64 = 1
    AesCbc256_HmacSha256_B64 = 2
    Rsa2048_OaepSha256_B64 = 3
    Rsa2048_OaepSha1_B64 = 4
    Rsa2048_OaepSha256_HmacSha256_B64 = 5
    Rsa2048_OaepSha1_HmacSha256_B64 = 6

EncryptionTypeAes = [
    EncryptionType.AesCbc256_B64,
    EncryptionType.AesCbc128_HmacSha256_B64,
    EncryptionType.AesCbc256_HmacSha256_B64
]

EncryptionTypeRsa = [
    EncryptionType.Rsa2048_OaepSha1_B64, 
    EncryptionType.Rsa2048_OaepSha1_HmacSha256_B64,
    EncryptionType.Rsa2048_OaepSha256_B64, 
    EncryptionType.Rsa2048_OaepSha256_HmacSha256_B64
]

class UriMatchType(Enum):
    Domain = 0
    Host = 1
    StartsWith = 2
    Exact = 3
    RegularExpression = 4
    Never = 5