export interface SignalProtocolAddressType {
    readonly name: string
    readonly deviceId: number
    toString: () => string
    equals: (other: SignalProtocolAddressType) => boolean
}

export interface FingerprintGeneratorType {
    createFor: (
        localIdentifier: string,
        localIdentityKey: ArrayBuffer,
        remoteIdentifier: string,
        remoteIdentityKey: ArrayBuffer
    ) => Promise<string>
}

export interface KeyPairType {
    pubKey: ArrayBuffer
    privKey: ArrayBuffer
}

export interface PreKeyType {
    keyId: number
    keyPair: KeyPairType
}

export interface SignedPreKeyType extends PreKeyType {
    signature: ArrayBuffer
}

export interface RecordType {
    archiveCurrentState: () => void
    deleteAllSessions: () => void
    getOpenSession: () => void
    getSessionByBaseKey: () => void
    getSessions: () => void
    haveOpenSession: () => void
    promoteState: () => void
    serialize: () => void
    updateSessionState: () => void
}

// TODO: any????
export type SessionRecordType = any

export interface StorageType {
    Direction: {
        SENDING: number
        RECEIVING: number
    }
    getIdentityKeyPair: () => Promise<KeyPairType>
    getLocalRegistrationId: () => Promise<number>
    isTrustedIdentity: () => Promise<void>
    loadPreKey: (encodedAddress: string, publicKey: ArrayBuffer | undefined, direction: number) => Promise<void>
    loadSession: (encodedAddress: string) => Promise<SessionRecordType>
    loadSignedPreKey: (keyId: number) => Promise<SignedPreKeyType>
    removePreKey: (keyId: number) => Promise<void>
    saveIdentity: (encodedAddress: string, publicKey: ArrayBuffer, nonblockingApproval?: boolean) => Promise<boolean>
    storeSession: (encodedAddress: string, record: SessionRecordType) => Promise<void>
}

export interface CurveType {
    generateKeyPair: () => Promise<KeyPairType>
    createKeyPair: (privKey: ArrayBuffer) => Promise<KeyPairType>
    calculateAgreement: (pubKey: ArrayBuffer, privKey: ArrayBuffer) => Promise<ArrayBuffer>
    verifySignature: (pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer) => Promise<void>
    calculateSignature: (privKey: ArrayBuffer, message: ArrayBuffer) => ArrayBuffer | Promise<ArrayBuffer>
    validatePubKeyFormat: (buffer: ArrayBuffer) => ArrayBuffer
}
