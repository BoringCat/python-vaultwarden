import typing as _t
from datetime import datetime

DecryptFunc = _t.Callable[[str, _t.Optional[str]], str]

def Decrypt(val, fn:DecryptFunc, orgId:str = None):
    if isinstance(val, str):
        return fn(val, orgId)
    elif isinstance(val, list):
        for idx, _v in enumerate(val):
            val[idx] = Decrypt(_v, fn, orgId)
    elif isinstance(val, dict):
        for k, v in val.items():
            val[k] = Decrypt(v, fn, orgId)
    elif isinstance(val, BaseResponse):
        getattr(val, 'DecryptAll')(fn, orgId)
    return val

class BaseResponse():
    __not_decrypt__ = []
    __repr_item__ = []
    def __init__(self, response:dict) -> None:
        self.__response = response
    
    def getResponseProperty(self, propertyName:str, response:dict = None, exactName:bool = False):
        if not propertyName:
            raise ValueError('propertyName must not be null/empty.')
        _response = response or self.__response
        if not _response:
            return
        if not exactName and propertyName not in _response:
            otherCasePropertyName:str = None
            if propertyName[0] == propertyName[0].upper():
                otherCasePropertyName = propertyName[0].lower()
            else:
                otherCasePropertyName = propertyName[0].upper()
            if len(propertyName) > 1:
                otherCasePropertyName += propertyName[1:]
            propertyName = otherCasePropertyName
            if propertyName not in _response:
                propertyName = propertyName.lower()
            if propertyName not in _response:
                propertyName = propertyName.upper()
        return _response.get(propertyName, None)
    def toJson(self): return self.__response
    def DecryptAll(self, fn:DecryptFunc, orgId:str = None):
        _orgId = orgId or self.getResponseProperty('OrganizationId')
        for k in dir(self):
            if k.startswith('_') or k.endswith('_'):
                continue
            if k in self.__not_decrypt__:
                continue
            setattr(self, k, Decrypt(getattr(self, k), fn, _orgId))
    def __str__(self):
        return f'<{type(self).__name__}: >'
    def __repr__(self):
        if not self.__repr_item__:
            return super().__repr__()
        return f'<{type(self).__name__}: {" ".join(map(lambda x:"%s=%s" % x, map(lambda x:(x,getattr(self, x)), self.__repr_item__)))}>'

class PermissionsApi(BaseResponse):
    accessEventLogs          :bool
    accessImportExport       :bool
    accessReports            :bool
    createNewCollections     :bool
    editAnyCollection        :bool
    deleteAnyCollection      :bool
    editAssignedCollections  :bool
    deleteAssignedCollections:bool
    manageCiphers            :bool
    manageGroups             :bool
    manageSso                :bool
    managePolicies           :bool
    manageUsers              :bool
    manageResetPassword      :bool
    manageScim               :bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        if not response:
            return
        self.accessEventLogs = self.getResponseProperty("AccessEventLogs")
        self.accessImportExport = self.getResponseProperty("AccessImportExport")
        self.accessReports = self.getResponseProperty("AccessReports")

        self.createNewCollections = self.getResponseProperty("CreateNewCollections")
        self.editAnyCollection = self.getResponseProperty("EditAnyCollection")
        self.deleteAnyCollection = self.getResponseProperty("DeleteAnyCollection")
        self.editAssignedCollections = self.getResponseProperty("EditAssignedCollections")
        self.deleteAssignedCollections = self.getResponseProperty("DeleteAssignedCollections")

        self.manageCiphers = self.getResponseProperty("ManageCiphers")
        self.manageGroups = self.getResponseProperty("ManageGroups")
        self.manageSso = self.getResponseProperty("ManageSso")
        self.managePolicies = self.getResponseProperty("ManagePolicies")
        self.manageUsers = self.getResponseProperty("ManageUsers")
        self.manageResetPassword = self.getResponseProperty("ManageResetPassword")
        self.manageScim = self.getResponseProperty("ManageScim")

class ProfileOrganizationResponse(BaseResponse):
    id                                  :str
    name                                :str
    usePolicies                         :bool
    useGroups                           :bool
    useDirectory                        :bool
    useEvents                           :bool
    useTotp                             :bool
    use2fa                              :bool
    useApi                              :bool
    useSso                              :bool
    useKeyConnector                     :bool
    useScim                             :bool
    useCustomPermissions                :bool
    useResetPassword                    :bool
    useSecretsManager                   :bool
    usePasswordManager                  :bool
    useActivateAutofillPolicy           :bool
    selfHost                            :bool
    usersGetPremium                     :bool
    seats                               :int
    maxCollections                      :int
    maxStorageGb                        :_t.Optional[int]
    key                                 :str
    hasPublicAndPrivateKeys             :bool
    status                              :int
    type                                :int
    enabled                             :bool
    ssoBound                            :bool
    identifier                          :str
    permissions                         :PermissionsApi
    resetPasswordEnrolled               :bool
    userId                              :str
    providerId                          :str
    providerName                        :str
    providerType                        :_t.Optional[int]
    familySponsorshipFriendlyName       :str
    familySponsorshipAvailable          :bool
    planProductType                     :int
    keyConnectorEnabled                 :bool
    keyConnectorUrl                     :str
    familySponsorshipLastSyncDate       :_t.Optional[datetime]
    familySponsorshipValidUntil         :_t.Optional[datetime]
    familySponsorshipToDelete           :_t.Optional[bool]
    accessSecretsManager                :bool
    limitCollectionCreationDeletion     :bool
    allowAdminAccessToAllCollectionItems:bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.name = self.getResponseProperty("Name")
        self.usePolicies = self.getResponseProperty("UsePolicies")
        self.useGroups = self.getResponseProperty("UseGroups")
        self.useDirectory = self.getResponseProperty("UseDirectory")
        self.useEvents = self.getResponseProperty("UseEvents")
        self.useTotp = self.getResponseProperty("UseTotp")
        self.use2fa = self.getResponseProperty("Use2fa")
        self.useApi = self.getResponseProperty("UseApi")
        self.useSso = self.getResponseProperty("UseSso")
        self.useKeyConnector = self.getResponseProperty("UseKeyConnector") or False
        self.useScim = self.getResponseProperty("UseScim") or False
        self.useCustomPermissions = self.getResponseProperty("UseCustomPermissions") or False
        self.useResetPassword = self.getResponseProperty("UseResetPassword")
        self.useSecretsManager = self.getResponseProperty("UseSecretsManager")
        self.usePasswordManager = self.getResponseProperty("UsePasswordManager")
        self.useActivateAutofillPolicy = self.getResponseProperty("UseActivateAutofillPolicy")
        self.selfHost = self.getResponseProperty("SelfHost")
        self.usersGetPremium = self.getResponseProperty("UsersGetPremium")
        self.seats = self.getResponseProperty("Seats")
        self.maxCollections = self.getResponseProperty("MaxCollections")
        self.maxStorageGb = self.getResponseProperty("MaxStorageGb")
        self.key = self.getResponseProperty("Key")
        self.hasPublicAndPrivateKeys = self.getResponseProperty("HasPublicAndPrivateKeys")
        self.status = self.getResponseProperty("Status")
        self.type = self.getResponseProperty("Type")
        self.enabled = self.getResponseProperty("Enabled")
        self.ssoBound = self.getResponseProperty("SsoBound")
        self.identifier = self.getResponseProperty("Identifier")
        self.permissions = PermissionsApi(self.getResponseProperty("permissions"))
        self.resetPasswordEnrolled = self.getResponseProperty("ResetPasswordEnrolled")
        self.userId = self.getResponseProperty("UserId")
        self.providerId = self.getResponseProperty("ProviderId")
        self.providerName = self.getResponseProperty("ProviderName")
        self.providerType = self.getResponseProperty("ProviderType")
        self.familySponsorshipFriendlyName = self.getResponseProperty("FamilySponsorshipFriendlyName")
        self.familySponsorshipAvailable = self.getResponseProperty("FamilySponsorshipAvailable")
        self.planProductType = self.getResponseProperty("PlanProductType")
        self.keyConnectorEnabled = self.getResponseProperty("KeyConnectorEnabled") or False
        self.keyConnectorUrl = self.getResponseProperty("KeyConnectorUrl")

class ProfileProviderResponse(BaseResponse):
    id         :str
    name       :str
    key        :str
    status     :int
    type       :int
    enabled    :bool
    permissions:PermissionsApi
    userId     :str
    useEvents  :bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.name = self.getResponseProperty("Name")
        self.key = self.getResponseProperty("Key")
        self.status = self.getResponseProperty("Status")
        self.type = self.getResponseProperty("Type")
        self.enabled = self.getResponseProperty("Enabled")
        self.permissions = PermissionsApi(self.getResponseProperty("permissions"))
        self.userId = self.getResponseProperty("UserId")
        self.useEvents = self.getResponseProperty("UseEvents")

class ProfileProviderOrganizationResponse(BaseResponse):
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.keyConnectorEnabled = False

class ProfileResponse(BaseResponse):
    id                     :str
    name                   :str
    email                  :str
    emailVerified          :bool
    masterPasswordHint     :str
    premiumPersonally      :bool
    premiumFromOrganization:bool
    culture                :str
    twoFactorEnabled       :bool
    key                    :str
    avatarColor            :str
    privateKey             :str
    securityStamp          :str
    forcePasswordReset     :bool
    usesKeyConnector       :bool
    organizations          :_t.List[ProfileOrganizationResponse] = []
    providers              :_t.List[ProfileProviderResponse] = []
    providerOrganizations  :_t.List[ProfileProviderOrganizationResponse] = []
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.name = self.getResponseProperty("Name")
        self.email = self.getResponseProperty("Email")
        self.emailVerified = self.getResponseProperty("EmailVerified")
        self.masterPasswordHint = self.getResponseProperty("MasterPasswordHint")
        self.premiumPersonally = self.getResponseProperty("Premium")
        self.premiumFromOrganization = self.getResponseProperty("PremiumFromOrganization")
        self.culture = self.getResponseProperty("Culture")
        self.twoFactorEnabled = self.getResponseProperty("TwoFactorEnabled")
        self.key = self.getResponseProperty("Key")
        self.avatarColor = self.getResponseProperty("AvatarColor")
        self.privateKey = self.getResponseProperty("PrivateKey")
        self.securityStamp = self.getResponseProperty("SecurityStamp")
        self.forcePasswordReset = self.getResponseProperty("ForcePasswordReset") or False
        self.usesKeyConnector = self.getResponseProperty("UsesKeyConnector") or False
        organizations = self.getResponseProperty("Organizations")
        self.organizations = list(map(ProfileOrganizationResponse, organizations)) if organizations else []
        providers = self.getResponseProperty("Providers")
        self.providers = list(map(ProfileProviderResponse, providers)) if providers else []
        providerOrganizations = self.getResponseProperty("ProviderOrganizations")
        self.providerOrganizations = list(map(ProfileProviderOrganizationResponse, providerOrganizations)) if providerOrganizations else []

class FolderResponse(BaseResponse):
    id          :str
    name        :str
    revisionDate:str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.name = self.getResponseProperty("Name")
        self.revisionDate = self.getResponseProperty("RevisionDate")

class CollectionResponse(BaseResponse):
    id            :str
    organizationId:str
    name          :str
    externalId    :str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.organizationId = self.getResponseProperty("OrganizationId")
        self.name = self.getResponseProperty("Name")
        self.externalId = self.getResponseProperty("ExternalId")

class CollectionDetailsResponse(CollectionResponse):
    readOnly     :bool
    manage       :bool
    hidePasswords:bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.readOnly = self.getResponseProperty("ReadOnly") or False
        self.manage = self.getResponseProperty("Manage") or False
        self.hidePasswords = self.getResponseProperty("HidePasswords") or False

class LoginUriApi(BaseResponse):
    uri  :str
    match:int
    __repr_item__ = ['uri']
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.uri = self.getResponseProperty("Uri")
        self.match = self.getResponseProperty("Match")

class Fido2CredentialApi(BaseResponse):
    credentialId   :str
    keyType        :str
    keyAlgorithm   :str
    keyCurve       :str
    keyValue       :str
    rpId           :str
    userHandle     :str
    userName       :str
    counter        :str
    rpName         :str
    userDisplayName:str
    discoverable   :str
    creationDate   :str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        if not response:
            return
        self.credentialId = self.getResponseProperty("CredentialId")
        self.keyType = self.getResponseProperty("KeyType")
        self.keyAlgorithm = self.getResponseProperty("KeyAlgorithm")
        self.keyCurve = self.getResponseProperty("KeyCurve")
        self.keyValue = self.getResponseProperty("keyValue")
        self.rpId = self.getResponseProperty("RpId")
        self.userHandle = self.getResponseProperty("UserHandle")
        self.userName = self.getResponseProperty("UserName")
        self.counter = self.getResponseProperty("Counter")
        self.rpName = self.getResponseProperty("RpName")
        self.userDisplayName = self.getResponseProperty("UserDisplayName")
        self.discoverable = self.getResponseProperty("Discoverable")
        self.creationDate = self.getResponseProperty("CreationDate")

class FieldApi(BaseResponse):
    type    :str
    name    :str
    value   :int
    linkedId:int
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        if not response:
            return
        self.type = self.getResponseProperty("Type")
        self.name = self.getResponseProperty("Name")
        self.value = self.getResponseProperty("Value")
        self.linkedId = self.getResponseProperty("linkedId")

class AttachmentResponse(BaseResponse):
    id      :str
    url     :str
    fileName:str
    key     :str
    size    :str
    sizeName:str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.url = self.getResponseProperty("Url")
        self.fileName = self.getResponseProperty("FileName")
        self.key = self.getResponseProperty("Key")
        self.size = self.getResponseProperty("Size")
        self.sizeName = self.getResponseProperty("SizeName")

class PasswordHistoryResponse(BaseResponse):
    password    :str
    lastUsedDate:str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.password = self.getResponseProperty("Password")
        self.lastUsedDate = self.getResponseProperty("LastUsedDate")

class LoginApi(BaseResponse):
    uris                :_t.List[LoginUriApi]
    username            :str
    password            :str
    passwordRevisionDate:str
    totp                :str
    autofillOnPageLoad  :bool
    fido2Credentials:_t.Optional[_t.List[Fido2CredentialApi]]
    __repr_item__ = ['username']
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.username = self.getResponseProperty("Username")
        self.password = self.getResponseProperty("Password")
        self.passwordRevisionDate = self.getResponseProperty("PasswordRevisionDate")
        self.totp = self.getResponseProperty("Totp")
        self.autofillOnPageLoad = self.getResponseProperty("AutofillOnPageLoad")
        uris = self.getResponseProperty("Uris")
        self.uris = list(map(LoginUriApi, uris)) if uris else None
        fido2Credentials = self.getResponseProperty("Fido2Credentials")
        self.fido2Credentials = list(map(Fido2CredentialApi, fido2Credentials)) if fido2Credentials else None

class CardApi(BaseResponse):
    cardholderName:str
    brand         :str
    number        :str
    expMonth      :str
    expYear       :str
    code          :str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        if not response:
            return
        self.cardholderName = self.getResponseProperty('CardholderName')
        self.brand = self.getResponseProperty('Brand')
        self.number = self.getResponseProperty('Number')
        self.expMonth = self.getResponseProperty('ExpMonth')
        self.expYear = self.getResponseProperty('ExpYear')
        self.code = self.getResponseProperty('Code')

class IdentityApi(BaseResponse):
    title         :str
    firstName     :str
    middleName    :str
    lastName      :str
    address1      :str
    address2      :str
    address3      :str
    city          :str
    state         :str
    postalCode    :str
    country       :str
    company       :str
    email         :str
    phone         :str
    ssn           :str
    username      :str
    passportNumber:str
    licenseNumber :str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        if not response:
            return
        self.title = self.getResponseProperty('Title')
        self.firstName = self.getResponseProperty('FirstName')
        self.middleName = self.getResponseProperty('MiddleName')
        self.lastName = self.getResponseProperty('LastName')
        self.address1 = self.getResponseProperty('Address1')
        self.address2 = self.getResponseProperty('Address2')
        self.address3 = self.getResponseProperty('Address3')
        self.city = self.getResponseProperty('City')
        self.state = self.getResponseProperty('State')
        self.postalCode = self.getResponseProperty('PostalCode')
        self.country = self.getResponseProperty('Country')
        self.company = self.getResponseProperty('Company')
        self.email = self.getResponseProperty('Email')
        self.phone = self.getResponseProperty('Phone')
        self.ssn = self.getResponseProperty('SSN')
        self.username = self.getResponseProperty('Username')
        self.passportNumber = self.getResponseProperty('PassportNumber')
        self.licenseNumber = self.getResponseProperty('LicenseNumber')

class SecureNoteApi(BaseResponse):
    type:int
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        if not response:
            return
        self.type = self.getResponseProperty('Type')

class CipherResponse(BaseResponse):
    id                 :str
    organizationId     :str
    folderId           :str
    type               :int
    name               :str
    notes              :str
    fields             :_t.List[FieldApi]
    login              :LoginApi
    card               :CardApi
    identity           :IdentityApi
    secureNote         :SecureNoteApi
    favorite           :bool
    edit               :bool
    viewPassword       :bool
    organizationUseTotp:bool
    revisionDate       :str
    attachments        :_t.List[AttachmentResponse]
    passwordHistory    :_t.List[PasswordHistoryResponse]
    collectionIds      :_t.List[str]
    creationDate       :str
    deletedDate        :str
    reprompt           :int
    key                :str
    __repr_item__ = ['name']
    def __init__(self, response:dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty('Id')
        self.organizationId = self.getResponseProperty("OrganizationId")
        self.folderId = self.getResponseProperty("FolderId")
        self.type = self.getResponseProperty("Type")
        self.name = self.getResponseProperty("Name")
        self.notes = self.getResponseProperty("Notes")
        self.favorite = self.getResponseProperty("Favorite") or False
        self.edit = not self.getResponseProperty("Edit")
        self.viewPassword = self.getResponseProperty("ViewPassword") or True
        login = self.getResponseProperty("Login")
        self.login = LoginApi(login) if login else None
        card = self.getResponseProperty("Card")
        self.card = CardApi(card) if card else None
        identity = self.getResponseProperty("Identity")
        self.identity = IdentityApi(identity) if identity else None
        secureNote = self.getResponseProperty("SecureNote")
        self.secureNote = SecureNoteApi(secureNote) if secureNote else None
        self.organizationUseTotp = self.getResponseProperty("OrganizationUseTotp")
        self.revisionDate = self.getResponseProperty("RevisionDate")
        self.collectionIds = self.getResponseProperty("CollectionIds")
        self.creationDate = self.getResponseProperty("CreationDate")
        self.deletedDate = self.getResponseProperty("DeletedDate")
        fields = self.getResponseProperty("Fields")
        self.fields = list(map(FieldApi, fields)) if fields else None
        attachments = self.getResponseProperty("Attachments")
        self.attachments = list(map(AttachmentResponse, attachments)) if attachments else None
        passwordHistory = self.getResponseProperty("PasswordHistory")
        self.passwordHistory = list(map(PasswordHistoryResponse, passwordHistory)) if passwordHistory else None
        self.reprompt = self.getResponseProperty("Reprompt") or 0
        self.key = self.getResponseProperty("Key")

class GlobalDomainResponse(BaseResponse):
    type    :int
    domains :_t.List[str]
    excluded:bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.type = self.getResponseProperty("Type")
        self.domains = self.getResponseProperty("Domains")
        self.excluded = self.getResponseProperty("Excluded")

class DomainsResponse(BaseResponse):
    equivalentDomains      :_t.List[_t.List[str]]
    globalEquivalentDomains:_t.List[GlobalDomainResponse]
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.equivalentDomains = self.getResponseProperty("EquivalentDomains")
        globalEquivalentDomains = self.getResponseProperty("GlobalEquivalentDomains")
        self.globalEquivalentDomains = list(map(GlobalDomainResponse, globalEquivalentDomains)) if globalEquivalentDomains else []

class PolicyResponse(BaseResponse):
    id            :str
    organizationId:str
    type          :int
    data          :_t.Any
    enabled       :bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.organizationId = self.getResponseProperty("OrganizationId")
        self.type = self.getResponseProperty("Type")
        self.data = self.getResponseProperty("Data")
        self.enabled = self.getResponseProperty("Enabled")

class SendFileApi(BaseResponse):
    id      :str
    fileName:str
    size    :str
    sizeName:str
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.fileName = self.getResponseProperty("FileName")
        self.size = self.getResponseProperty("Size")
        self.sizeName = self.getResponseProperty("SizeName")

class SendTextApi(BaseResponse):
    text  :str
    hidden:bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.text = self.getResponseProperty("Text")
        self.hidden = self.getResponseProperty("Hidden") or False


class SendResponse(BaseResponse):
    id             :str
    accessId       :str
    type           :int
    name           :str
    notes          :str
    file           :SendFileApi
    text           :SendTextApi
    key            :str
    maxAccessCount :_t.Optional[int]
    accessCount    :int
    revisionDate   :str
    expirationDate :str
    deletionDate   :str
    password       :str
    disable        :bool
    hideEmail      :bool
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        self.id = self.getResponseProperty("Id")
        self.accessId = self.getResponseProperty("AccessId")
        self.type = self.getResponseProperty("Type")
        self.name = self.getResponseProperty("Name")
        self.notes = self.getResponseProperty("Notes")
        self.key = self.getResponseProperty("Key")
        self.maxAccessCount = self.getResponseProperty("MaxAccessCount")
        self.accessCount = self.getResponseProperty("AccessCount")
        self.revisionDate = self.getResponseProperty("RevisionDate")
        self.expirationDate = self.getResponseProperty("ExpirationDate")
        self.deletionDate = self.getResponseProperty("DeletionDate")
        self.password = self.getResponseProperty("Password")
        self.disable = self.getResponseProperty("Disabled") or False
        self.hideEmail = self.getResponseProperty("HideEmail") or False
        text = self.getResponseProperty("Text")
        self.text = SendTextApi(text) if text else None

        file = self.getResponseProperty("File")
        self.file = SendFileApi(file) if file else None

class SyncResponse(BaseResponse):
    profile    :_t.Optional[ProfileResponse]
    folders    :_t.List[FolderResponse]
    collections:_t.List[CollectionDetailsResponse]
    ciphers    :_t.List[CipherResponse]
    domains    :_t.Optional[DomainsResponse]
    policies   :_t.List[PolicyResponse]
    sends      :_t.List[SendResponse]
    __not_decrypt__ = ['profile']
    def __init__(self, response: dict) -> None:
        super().__init__(response)
        profile = self.getResponseProperty("Profile")
        self.profile = ProfileResponse(profile) if profile else None
        folders = self.getResponseProperty("Folders")
        self.folders = list(map(FolderResponse, folders)) if folders else []
        collections = self.getResponseProperty("Collections")
        self.collections = list(map(CollectionDetailsResponse, collections)) if collections else []
        ciphers = self.getResponseProperty("Ciphers")
        self.ciphers = list(map(CipherResponse, ciphers)) if ciphers else []
        domains = self.getResponseProperty("Domains")
        self.domains = DomainsResponse(domains) if domains else None
        policies = self.getResponseProperty("Policies")
        self.policies = list(map(PolicyResponse, policies)) if policies else []
        sends = self.getResponseProperty("Sends")
        self.sends = list(map(SendResponse, sends)) if sends else []
