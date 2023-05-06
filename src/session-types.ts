import { KeyPairType, SignedPublicPreKeyType, PreKeyType } from './types'

export enum ChainType {
    SENDING = 1,
    RECEIVING = 2,
}

export enum BaseKeyType {
    OURS = 1,
    THEIRS = 2,
}

export interface SessionType<T = ArrayBuffer> {
    indexInfo: IndexInfo<T>
    registrationId?: number
    currentRatchet: Ratchet<T>
    pendingPreKey?: PendingPreKey<T>

    oldRatchetList: OldRatchetInfo<T>[]

    chains: { [ephKeyString: string]: Chain<T> }
}

export interface IndexInfo<T> {
    closed: number
    remoteIdentityKey: T
    baseKey?: T
    baseKeyType?: BaseKeyType
}

export interface Ratchet<T> {
    rootKey: T
    ephemeralKeyPair?: KeyPairType<T>
    lastRemoteEphemeralKey: T
    previousCounter: number
    added?: number //timestamp
}
export interface OldRatchetInfo<T> {
    ephemeralKey: T
    added: number //timestamp
}

export interface Chain<T> {
    chainType: ChainType
    chainKey: { key?: T; counter: number }
    messageKeys: { [key: number]: T }
}

export interface PendingPreKey<T> {
    baseKey: T
    preKeyId?: number
    signedKeyId: number
}

export enum EncryptionResultMessageType {
    WhisperMessage = 1,
    PreKeyWhisperMessage = 3,
}

export interface EncryptionResult {
    type: EncryptionResultMessageType
    body: ArrayBuffer
    registrationId: number
}

export interface DeviceType<T = ArrayBuffer> {
    identityKey: T
    signedPreKey: SignedPublicPreKeyType<T>
    preKey?: PreKeyType<T>
    registrationId?: number
}

export interface RecordType {
    archiveCurrentState: () => void
    deleteAllSessions: () => void
    getOpenSession: () => SessionType | undefined
    getSessionByBaseKey: (baseKey: ArrayBuffer) => SessionType | undefined
    getSessionByRemoteEphemeralKey: (remoteEphemeralKey: ArrayBuffer) => SessionType | undefined
    getSessions: () => SessionType[]
    haveOpenSession: () => boolean
    promoteState: (session: SessionType) => void
    serialize: () => string
    updateSessionState: (session: SessionType) => void
}
