import { SignalProtocolAddressType, StorageType, Direction, KeyPairType } from './types'
import { DeviceType, SessionType, BaseKeyType, ChainType } from './session-types'

import * as Internal from './internal'
import * as base64 from 'base64-js'
import { SessionRecord } from './session-record'
import { PreKeyWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts/lib/protos/WhisperTextProtocol'
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
            throw new Error(`Identity key changed`)
        }

        // This will throw if invalid
        console.log(`verify device prekey sig`)
        await Internal.crypto.Ed25519Verify(
            device.identityKey,
            device.signedPreKey.publicKey,
            device.signedPreKey.signature
        )

        console.log(`create baseKey`)
        const baseKey = await Internal.crypto.createKeyPair()

        const devicePreKey = device.preKey?.publicKey
        if (!devicePreKey) {
            throw new Error(`device preKey missing`)
        }

        console.log(`initSession`)
        const session = await this.initSession(
            true,
            baseKey,
            undefined,
            device.identityKey,
            devicePreKey,
            device.signedPreKey.publicKey,
            device.registrationId
        )
        session.pendingPreKey = {
            signedKeyId: device.signedPreKey.keyId,
            baseKey: baseKey.pubKey,
        }
        if (device.preKey) {
            session.pendingPreKey.preKeyId = device.preKey.keyId
        }
        const address = this.remoteAddress.toString()
        const serialized = await this.storage.loadSession(address)
        let record: SessionRecord
        if (serialized !== undefined) {
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

    initSession = async (
        isInitiator: boolean,
        ourEphemeralKey: KeyPairType<ArrayBuffer>,
        ourSignedKey: KeyPairType<ArrayBuffer> | undefined,
        theirIdentityPubKey: ArrayBuffer,
        theirEphemeralPubKey: ArrayBuffer,
        theirSignedPubKey: ArrayBuffer | undefined,
        registrationId: number
    ): Promise<SessionType> => {
        const ourIdentityKey = await this.storage.getIdentityKeyPair()

        if (!ourIdentityKey) {
            throw new Error(`No identity key. Cannot initiate session.`)
        }
        if (isInitiator) {
            if (ourSignedKey !== undefined) {
                throw new Error('Invalid call to initSession')
            }
            ourSignedKey = ourEphemeralKey
        } else {
            if (theirSignedPubKey !== undefined) {
                throw new Error('Invalid call to initSession')
            }
            theirSignedPubKey = theirEphemeralPubKey
        }

        let sharedSecret: Uint8Array
        if (ourEphemeralKey === undefined || theirEphemeralPubKey === undefined) {
            sharedSecret = new Uint8Array(32 * 4)
        } else {
            sharedSecret = new Uint8Array(32 * 5)
        }

        for (let i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff
        }

        if (!ourSignedKey) {
            throw new Error(`ourSignedKey is undefined. Cannot proceed with ECDHE`)
        }
        if (!theirSignedPubKey) {
            throw new Error(`theirSignedPubKey is undefined. Cannot proceed with ECDHE`)
        }

        // X3DH Section 3.3. https://signal.org/docs/specifications/x3dh/
        // Note that `ourSignedKey` will be `ourEphemeralKey` if `isInitiator`.
        // ourSignedKey is serving as EK_A in the spec.
        // No One-time PreKey is being used yet
        const ecRes = await Promise.all([
            Internal.crypto.ECDHE(theirSignedPubKey, ourIdentityKey.privKey),
            Internal.crypto.ECDHE(theirIdentityPubKey, ourSignedKey.privKey),
            Internal.crypto.ECDHE(theirSignedPubKey, ourSignedKey.privKey),
        ])

        if (isInitiator) {
            sharedSecret.set(new Uint8Array(ecRes[0]), 32)
            sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2)
        } else {
            sharedSecret.set(new Uint8Array(ecRes[0]), 32 * 2)
            sharedSecret.set(new Uint8Array(ecRes[1]), 32)
        }
        sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3)

        if (ourEphemeralKey !== undefined && theirEphemeralPubKey !== undefined) {
            const ecRes4 = await Internal.crypto.ECDHE(theirEphemeralPubKey, ourEphemeralKey.privKey)
            sharedSecret.set(new Uint8Array(ecRes4), 32 * 4)
        }

        const masterKey = await Internal.HKDF(sharedSecret.buffer, new ArrayBuffer(32), 'WhisperText')

        const session: SessionType = {
            registrationId: registrationId,
            currentRatchet: {
                rootKey: masterKey[0],
                lastRemoteEphemeralKey: theirSignedPubKey,
                previousCounter: 0,
            },
            indexInfo: {
                remoteIdentityKey: theirIdentityPubKey,
                closed: -1,
            },
            oldRatchetList: [],
            chains: {},
        }

        // If we're initiating we go ahead and set our first sending ephemeral key now,
        // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key
        if (isInitiator) {
            session.indexInfo.baseKey = ourEphemeralKey.pubKey
            session.indexInfo.baseKeyType = BaseKeyType.OURS
            const ourSendingEphemeralKey = await Internal.crypto.createKeyPair()
            session.currentRatchet.ephemeralKeyPair = ourSendingEphemeralKey
            console.log(`initiating session`, {
                ourSendingEphemeralKey,
                typeofkey: typeof ourSendingEphemeralKey.pubKey,
            })
            await this.calculateSendingRatchet(session, theirSignedPubKey)
        } else {
            session.indexInfo.baseKey = theirEphemeralPubKey
            session.indexInfo.baseKeyType = BaseKeyType.THEIRS
            session.currentRatchet.ephemeralKeyPair = ourSignedKey
        }
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
            messageKeys: [],
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: ChainType.SENDING,
        }
        ratchet.rootKey = masterKey[0]
    }

    async processPreKey(device: DeviceType): Promise<SessionType> {
        // return this.processPreKeyJob(device)
        const runJob = async () => {
            const sess = await this.processPreKeyJob(device)
            console.log(`preKeyProccessed`, { sess })
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
            console.log('Duplicate PreKeyMessage for session')
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
            console.log('Invalid prekey id', message.preKeyId)
        }
        if (!preKeyPair) {
            throw new Error(`preKeyPair is missing`)
        }

        const new_session = await this.initSession(
            false,
            preKeyPair,
            signedPreKeyPair,
            uint8ArrayToArrayBuffer(message.identityKey),
            uint8ArrayToArrayBuffer(message.baseKey),
            undefined,
            message.registrationId
        )
        record.updateSessionState(new_session)
        await this.storage.saveIdentity(this.remoteAddress.toString(), message.identityKey.buffer)

        return message.preKeyId
    }
}
