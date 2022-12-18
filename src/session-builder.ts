import { SignalProtocolAddressType, StorageType, Direction, KeyPairType } from './types'
import { DeviceType, SessionType, BaseKeyType, ChainType } from './session-types'

import * as Internal from './internal'
import * as base64 from 'base64-js'
import { SessionRecord } from './session-record'
import { PreKeyWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'
import { SessionLock } from './session-lock'
import { uint8ArrayToArrayBuffer } from './helpers'

export class SessionBuilder {
    remoteAddress: SignalProtocolAddressType
    storage: StorageType

    constructor(storage: StorageType, remoteAddress: SignalProtocolAddressType) {
        this.remoteAddress = remoteAddress
        this.storage = storage
    }

    processPreKeyJob = async (device: DeviceType): Promise<SessionType> => {
        const trusted = await this.storage.isTrustedIdentity(
            this.remoteAddress.name,
            device.identityKey,
            Direction.SENDING
        )
        if (!trusted) {
            throw new Error('Identity key changed')
        }

        // This will throw if invalid
        await Internal.crypto.Ed25519Verify(
            device.identityKey,
            device.signedPreKey.publicKey,
            device.signedPreKey.signature
        )

        const ephemeralKey = await Internal.crypto.createKeyPair()

        const deviceOneTimePreKey = device.preKey?.publicKey

        const session = await this.startSessionAsInitiator(
            ephemeralKey,
            device.identityKey,
            device.signedPreKey.publicKey,
            deviceOneTimePreKey,
            device.registrationId
        )
        session.pendingPreKey = {
            signedKeyId: device.signedPreKey.keyId,
            baseKey: ephemeralKey.pubKey,
        }
        if (device.preKey) {
            session.pendingPreKey.preKeyId = device.preKey.keyId
        }
        const address = this.remoteAddress.toString()
        const serialized = await this.storage.loadSession(address)
        let record: SessionRecord
        if (serialized !== undefined && serialized != null) {
            record = SessionRecord.deserialize(serialized)
        } else {
            record = new SessionRecord()
        }

        record.archiveCurrentState()
        record.updateSessionState(session)
        await Promise.all([
            this.storage.storeSession(address, record.serialize()),
            this.storage.saveIdentity(this.remoteAddress.toString(), session.indexInfo.remoteIdentityKey),
        ])

        return session
    }

    // Arguments map to the X3DH spec: https://signal.org/docs/specifications/x3dh/#keys
    // We are Alice the initiator.
    startSessionAsInitiator = async (
        EKa: KeyPairType<ArrayBuffer>,
        IKb: ArrayBuffer,
        SPKb: ArrayBuffer,
        OPKb: ArrayBuffer | undefined,
        registrationId?: number
    ): Promise<SessionType> => {
        const IKa = await this.storage.getIdentityKeyPair()

        if (!IKa) {
            throw new Error(`No identity key. Cannot initiate session.`)
        }

        let sharedSecret: Uint8Array
        if (OPKb === undefined) {
            sharedSecret = new Uint8Array(32 * 4)
        } else {
            sharedSecret = new Uint8Array(32 * 5)
        }

        // As specified in X3DH spec secion 22, the first 32 bytes are
        // 0xFF for curve25519 (https://signal.org/docs/specifications/x3dh/#cryptographic-notation)
        for (let i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff
        }

        if (!SPKb) {
            throw new Error(`theirSignedPubKey is undefined. Cannot proceed with ECDHE`)
        }

        // X3DH Section 3.3. https://signal.org/docs/specifications/x3dh/
        // We'll handle the possible one-time prekey below
        const ecRes = await Promise.all([
            Internal.crypto.ECDHE(SPKb, IKa.privKey),
            Internal.crypto.ECDHE(IKb, EKa.privKey),
            Internal.crypto.ECDHE(SPKb, EKa.privKey),
        ])

        sharedSecret.set(new Uint8Array(ecRes[0]), 32)
        sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2)

        sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3)

        if (OPKb !== undefined) {
            const ecRes4 = await Internal.crypto.ECDHE(OPKb, EKa.privKey)
            sharedSecret.set(new Uint8Array(ecRes4), 32 * 4)
        }

        const masterKey = await Internal.HKDF(uint8ArrayToArrayBuffer(sharedSecret), new ArrayBuffer(32), 'WhisperText')

        const session: SessionType = {
            registrationId: registrationId,
            currentRatchet: {
                rootKey: masterKey[0],
                lastRemoteEphemeralKey: SPKb,
                previousCounter: 0,
            },
            indexInfo: {
                remoteIdentityKey: IKb,
                closed: -1,
            },
            oldRatchetList: [],
            chains: {},
        }

        // We're initiating so we go ahead and set our first sending ephemeral key now,
        // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key

        session.indexInfo.baseKey = EKa.pubKey
        session.indexInfo.baseKeyType = BaseKeyType.OURS
        const ourSendingEphemeralKey = await Internal.crypto.createKeyPair()
        session.currentRatchet.ephemeralKeyPair = ourSendingEphemeralKey

        await this.calculateSendingRatchet(session, SPKb)

        return session
    }

    // Arguments map to the X3DH spec: https://signal.org/docs/specifications/x3dh/#keys
    // We are Bob now.
    startSessionWthPreKeyMessage = async (
        OPKb: KeyPairType<ArrayBuffer> | undefined,
        SPKb: KeyPairType<ArrayBuffer>,
        message: PreKeyWhisperMessage
    ): Promise<SessionType> => {
        const IKb = await this.storage.getIdentityKeyPair()
        const IKa = message.identityKey
        const EKa = message.baseKey

        if (!IKb) {
            throw new Error(`No identity key. Cannot initiate session.`)
        }

        let sharedSecret: Uint8Array
        if (!OPKb) {
            sharedSecret = new Uint8Array(32 * 4)
        } else {
            sharedSecret = new Uint8Array(32 * 5)
        }

        // As specified in X3DH spec secion 22, the first 32 bytes are
        // 0xFF for curve25519 (https://signal.org/docs/specifications/x3dh/#cryptographic-notation)
        for (let i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff
        }

        // X3DH Section 3.3. https://signal.org/docs/specifications/x3dh/
        // We'll handle the possible one-time prekey below
        const ecRes = await Promise.all([
            Internal.crypto.ECDHE(IKa, SPKb.privKey),
            Internal.crypto.ECDHE(EKa, IKb.privKey),
            Internal.crypto.ECDHE(EKa, SPKb.privKey),
        ])

        sharedSecret.set(new Uint8Array(ecRes[0]), 32)
        sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2)
        sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3)

        if (OPKb) {
            const ecRes4 = await Internal.crypto.ECDHE(EKa, OPKb.privKey)
            sharedSecret.set(new Uint8Array(ecRes4), 32 * 4)
        }

        const masterKey = await Internal.HKDF(uint8ArrayToArrayBuffer(sharedSecret), new ArrayBuffer(32), 'WhisperText')

        const session: SessionType = {
            registrationId: message.registrationId,
            currentRatchet: {
                rootKey: masterKey[0],
                lastRemoteEphemeralKey: EKa,
                previousCounter: 0,
            },
            indexInfo: {
                remoteIdentityKey: IKa,
                closed: -1,
            },
            oldRatchetList: [],
            chains: {},
        }

        // If we're initiating we go ahead and set our first sending ephemeral key now,
        // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key

        session.indexInfo.baseKey = EKa
        session.indexInfo.baseKeyType = BaseKeyType.THEIRS
        session.currentRatchet.ephemeralKeyPair = SPKb

        return session
    }

    async calculateSendingRatchet(session: SessionType, remoteKey: ArrayBuffer): Promise<void> {
        const ratchet = session.currentRatchet
        if (!ratchet.ephemeralKeyPair) {
            throw new Error(`Invalid ratchet - ephemeral key pair is missing`)
        }

        const ephPrivKey = ratchet.ephemeralKeyPair.privKey
        const rootKey = ratchet.rootKey
        const ephPubKey = base64.fromByteArray(new Uint8Array(ratchet.ephemeralKeyPair.pubKey))
        if (!(ephPrivKey && ephPubKey && rootKey)) {
            throw new Error(`Missing key, cannot calculate sending ratchet`)
        }
        const sharedSecret = await Internal.crypto.ECDHE(remoteKey, ephPrivKey)
        const masterKey = await Internal.HKDF(sharedSecret, rootKey, 'WhisperRatchet')

        session.chains[ephPubKey] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: ChainType.SENDING,
        }
        ratchet.rootKey = masterKey[0]
    }

    async processPreKey(device: DeviceType): Promise<SessionType> {
        // return this.processPreKeyJob(device)
        const runJob = async () => {
            const sess = await this.processPreKeyJob(device)
            return sess
        }
        return SessionLock.queueJobForNumber(this.remoteAddress.toString(), runJob)
    }

    async processV3(record: SessionRecord, message: PreKeyWhisperMessage): Promise<number | void> {
        const trusted = this.storage.isTrustedIdentity(
            this.remoteAddress.name,
            uint8ArrayToArrayBuffer(message.identityKey),
            Direction.RECEIVING
        )

        if (!trusted) {
            throw new Error(`Unknown identity key: ${uint8ArrayToArrayBuffer(message.identityKey)}`)
        }
        const [preKeyPair, signedPreKeyPair] = await Promise.all([
            this.storage.loadPreKey(message.preKeyId),
            this.storage.loadSignedPreKey(message.signedPreKeyId),
        ])

        if (record.getSessionByBaseKey(message.baseKey)) {
            return
        }

        const session = record.getOpenSession()

        if (signedPreKeyPair === undefined) {
            // Session may or may not be the right one, but if its not, we
            // can't do anything about it ...fall through and let
            // decryptWhisperMessage handle that case
            if (session !== undefined && session.currentRatchet !== undefined) {
                return
            } else {
                throw new Error('Missing Signed PreKey for PreKeyWhisperMessage')
            }
        }

        if (session !== undefined) {
            record.archiveCurrentState()
        }
        if (message.preKeyId && !preKeyPair) {
            // console.log('Invalid prekey id', message.preKeyId)
        }

        const new_session = await this.startSessionWthPreKeyMessage(preKeyPair, signedPreKeyPair, message)
        record.updateSessionState(new_session)
        await this.storage.saveIdentity(this.remoteAddress.toString(), uint8ArrayToArrayBuffer(message.identityKey))

        return message.preKeyId
    }
}
