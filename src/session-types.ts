import { KeyPairType, SignedPublicPreKeyType, PreKeyType } from './types'

export enum ChainType {
    SENDING = 1,
    RECEIVING = 2,
}

export enum BaseKeyType {
    OURS = 1,
    THEIRS = 2,
}

export interface SessionType {
    indexInfo: IndexInfo
    registrationId: number
    currentRatchet: Ratchet
    pendingPreKey?: PendingPreKey

    oldRatchetList: OldRatchetInfo[]

    // TODO: In the original lib this map was part of the session type - you'd
    // say `chain = session[ephKey]`.  We're changing it to `chain = session.chains[ephKey]`
    chains: { [ephKeyString: string]: Chain }
}

export interface IndexInfo {
    closed: number
    remoteIdentityKey: ArrayBuffer
    baseKey?: ArrayBuffer
    baseKeyType?: BaseKeyType
}

export interface Ratchet {
    rootKey: ArrayBuffer
    ephemeralKeyPair?: KeyPairType
    lastRemoteEphemeralKey: ArrayBuffer
    previousCounter: number
    added?: number //timestamp
}
export interface OldRatchetInfo {
    ephemeralKey: ArrayBuffer
    added: number //timestamp
}

export interface Chain {
    chainType: ChainType
    chainKey: { key: ArrayBuffer; counter: number }
    messageKeys: ArrayBuffer[]
}

export interface PendingPreKey {
    baseKey: ArrayBuffer
    preKeyId?: number
    signedKeyId: number
}

export enum EncryptionResultMessageType {
    PreKeyWhisperMessage = 1,
    WhisperMessage = 3,
}

export interface EncryptionResult {
    type: EncryptionResultMessageType
    body: ArrayBuffer
    registrationId: number
}

export interface DeviceType {
    identityKey: ArrayBuffer
    signedPreKey: SignedPublicPreKeyType
    preKey?: PreKeyType
    registrationId: number
}
