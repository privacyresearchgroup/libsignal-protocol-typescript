/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
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
// eslint-disable-next-line @typescript-eslint/no-explicit-any
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

export interface AsyncCurveType {
    generateKeyPair: () => Promise<KeyPairType>
    createKeyPair: (privKey: ArrayBuffer) => Promise<KeyPairType>
    calculateAgreement: (pubKey: ArrayBuffer, privKey: ArrayBuffer) => Promise<ArrayBuffer>
    verifySignature: (pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer) => Promise<boolean>
    calculateSignature: (privKey: ArrayBuffer, message: ArrayBuffer) => Promise<ArrayBuffer>
}

// Type guards

export function isKeyPairType(kp: any): kp is KeyPairType {
    return !!(kp?.privKey && kp?.pubKey)
}

export function isPreKeyType(pk: any): pk is PreKeyType {
    return typeof pk?.keyId === 'number' && isKeyPairType(pk?.keyPair)
}

export function isSignedPReKeyType(spk: any): spk is SignedPreKeyType {
    return spk?.signature && isPreKeyType(spk)
}
