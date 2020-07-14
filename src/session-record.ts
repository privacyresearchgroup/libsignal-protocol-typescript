/* eslint-disable @typescript-eslint/no-non-null-assertion */

import base64 from 'base64-js'

import * as util from './helpers'
import { KeyPairType } from './types'
import { SessionType, BaseKeyType, PendingPreKey, Chain, OldRatchetInfo, Ratchet, IndexInfo } from './session-types'

const ARCHIVED_STATES_MAX_LENGTH = 40
const OLD_RATCHETS_MAX_LENGTH = 10
const SESSION_RECORD_VERSION = 'v1'

export class SessionRecord {
    registrationId?: number
    sessions: { [k: string]: SessionType } = {}
    version = SESSION_RECORD_VERSION
    constructor(registrationId?: number) {
        this.registrationId = registrationId
    }

    static deserialize(serialized: string): SessionRecord {
        const data = JSON.parse(serialized)
        if (data.version !== SESSION_RECORD_VERSION) {
            // migrate(data)
        }

        const record = new SessionRecord()
        record.sessions = {}
        for (const k of Object.keys(data.sessions)) {
            record.sessions[k] = sessionTypeStringToArrayBuffer(data.sessions[k])
        }
        if (
            record.sessions === undefined ||
            record.sessions === null ||
            typeof record.sessions !== 'object' ||
            Array.isArray(record.sessions)
        ) {
            throw new Error('Error deserializing SessionRecord')
        }
        return record
    }

    serialize(): string {
        const sessions: { [k: string]: SessionType<string> } = {}
        for (const k of Object.keys(this.sessions)) {
            sessions[k] = sessionTypeArrayBufferToString(this.sessions[k])
        }
        const json = {
            sessions,
            version: this.version,
        }
        return JSON.stringify(json)
    }

    haveOpenSession(): boolean {
        const openSession = this.getOpenSession()
        return !!openSession && typeof openSession.registrationId === 'number'
    }

    getSessionByBaseKey(baseKey: ArrayBuffer): SessionType | undefined {
        const idx = util.toString(baseKey)
        if (!idx) {
            return undefined
        }
        const session = this.sessions[idx]
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            console.log('Tried to lookup a session using our basekey')
            return undefined
        }
        return session
    }

    getSessionByRemoteEphemeralKey(remoteEphemeralKey: ArrayBuffer): SessionType | undefined {
        this.detectDuplicateOpenSessions()
        const sessions = this.sessions

        const searchKey = util.toString(remoteEphemeralKey)

        if (searchKey) {
            let openSession
            for (const key in sessions) {
                if (sessions[key].indexInfo.closed == -1) {
                    openSession = sessions[key]
                }
                if (sessions[key].chains[searchKey] !== undefined) {
                    return sessions[key]
                }
            }
            if (openSession !== undefined) {
                return openSession
            }
        }

        return undefined
    }

    getOpenSession(): SessionType | undefined {
        const sessions = this.sessions
        if (sessions === undefined) {
            return undefined
        }

        this.detectDuplicateOpenSessions()

        for (const key in sessions) {
            if (sessions[key].indexInfo.closed == -1) {
                return sessions[key]
            }
        }
        return undefined
    }

    private detectDuplicateOpenSessions(): void {
        let openSession: SessionType | null = null
        const sessions = this.sessions
        for (const key in sessions) {
            if (sessions[key].indexInfo.closed == -1) {
                if (openSession !== null) {
                    throw new Error('Datastore inconsistensy: multiple open sessions')
                }
                openSession = sessions[key]
            }
        }
    }

    updateSessionState(session: SessionType): void {
        const sessions = this.sessions

        this.removeOldChains(session)

        const idx = util.toString(session.indexInfo.baseKey)
        if (!idx) {
            throw new Error(`invalid index for session`)
        }
        sessions[idx] = session

        this.removeOldSessions()
    }

    getSessions(): SessionType[] {
        // return an array of sessions ordered by time closed,
        // followed by the open session
        let list: SessionType[] = []
        let openSession: SessionType | null = null
        for (const k in this.sessions) {
            if (this.sessions[k].indexInfo.closed === -1) {
                openSession = this.sessions[k]
            } else {
                list.push(this.sessions[k])
            }
        }
        list = list.sort(function (s1, s2) {
            return s1.indexInfo.closed - s2.indexInfo.closed
        })
        if (openSession) {
            list.push(openSession)
        }
        return list
    }

    archiveCurrentState(): void {
        const open_session = this.getOpenSession()
        if (open_session !== undefined) {
            console.log('closing session')
            open_session.indexInfo.closed = Date.now()
            this.updateSessionState(open_session)
        }
    }
    promoteState(session: SessionType): void {
        console.log('promoting session')
        session.indexInfo.closed = -1
    }

    removeOldChains(session: SessionType): void {
        // Sending ratchets are always removed when we step because we never need them again
        // Receiving ratchets are added to the oldRatchetList, which we parse
        // here and remove all but the last ten.
        while (session.oldRatchetList.length > OLD_RATCHETS_MAX_LENGTH) {
            let index = 0
            let oldest = session.oldRatchetList[0]
            for (let i = 0; i < session.oldRatchetList.length; i++) {
                if (session.oldRatchetList[i].added < oldest.added) {
                    oldest = session.oldRatchetList[i]
                    index = i
                }
            }
            console.log('Deleting chain closed at', oldest.added)
            const idx = util.toString(oldest.ephemeralKey)
            if (!idx) {
                throw new Error(`invalid index for chain`)
            }
            delete session[idx]
            session.oldRatchetList.splice(index, 1)
        }
    }

    removeOldSessions(): void {
        // Retain only the last 20 sessions
        const { sessions } = this
        let oldestBaseKey: string | null = null
        let oldestSession: SessionType | null = null
        while (Object.keys(sessions).length > ARCHIVED_STATES_MAX_LENGTH) {
            for (const key in sessions) {
                const session = sessions[key]
                if (
                    session.indexInfo.closed > -1 && // session is closed
                    (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)
                ) {
                    oldestBaseKey = key
                    oldestSession = session
                }
            }
            console.log('Deleting session closed at', oldestSession?.indexInfo.closed)
            if (oldestBaseKey) {
                // TODO: there used to be a util.toString(oldestBaseKey).  is the key ALWAYS a string?
                // if so don't need it.
                delete sessions[oldestBaseKey]
            }
        }
    }
    deleteAllSessions(): void {
        // Used primarily in session reset scenarios, where we really delete sessions
        this.sessions = {}
    }
}

// Serialization helpers
function toAB(s: string): ArrayBuffer {
    return util.uint8ArrayToArrayBuffer(base64.toByteArray(s))
}
function abToS(b: ArrayBuffer): string {
    return base64.fromByteArray(new Uint8Array(b))
}

export function keyPairStirngToArrayBuffer(kp: KeyPairType<string>): KeyPairType<ArrayBuffer> {
    return {
        pubKey: toAB(kp.pubKey),
        privKey: toAB(kp.privKey),
    }
}

export function keyPairArrayBufferToString(kp: KeyPairType<ArrayBuffer>): KeyPairType<string> {
    return {
        pubKey: abToS(kp.pubKey),
        privKey: abToS(kp.privKey),
    }
}

export function pendingPreKeyStringToArrayBuffer(ppk: PendingPreKey<string>): PendingPreKey<ArrayBuffer> {
    const { preKeyId, signedKeyId } = ppk
    return {
        baseKey: toAB(ppk.baseKey),
        preKeyId,
        signedKeyId,
    }
}

export function pendingPreKeyArrayBufferToString(ppk: PendingPreKey<ArrayBuffer>): PendingPreKey<string> {
    const { preKeyId, signedKeyId } = ppk
    return {
        baseKey: abToS(ppk.baseKey),
        preKeyId,
        signedKeyId,
    }
}

export function chainStringToArrayBuffer(c: Chain<string>): Chain<ArrayBuffer> {
    const { chainType, chainKey, messageKeys } = c
    const { key, counter } = chainKey
    const newMessageKeys: { [k: number]: ArrayBuffer } = {}
    for (const k of Object.keys(messageKeys)) {
        newMessageKeys[k] = toAB(messageKeys[k])
    }
    return {
        chainType,
        chainKey: {
            key: util.uint8ArrayToArrayBuffer(base64.toByteArray(key)),
            counter,
        },
        messageKeys: newMessageKeys,
    }
}

export function chainArrayBufferToString(c: Chain<ArrayBuffer>): Chain<string> {
    const { chainType, chainKey, messageKeys } = c
    const { key, counter } = chainKey
    const newMessageKeys: { [k: number]: string } = {}
    for (const k of Object.keys(messageKeys)) {
        newMessageKeys[k] = abToS(messageKeys[k])
    }
    return {
        chainType,
        chainKey: {
            key: abToS(key),
            counter,
        },
        messageKeys: newMessageKeys,
    }
}

export function oldRatchetInfoStringToArrayBuffer(ori: OldRatchetInfo<string>): OldRatchetInfo<ArrayBuffer> {
    return {
        ephemeralKey: toAB(ori.ephemeralKey),
        added: ori.added,
    }
}

export function oldRatchetInfoArrayBufferToString(ori: OldRatchetInfo<ArrayBuffer>): OldRatchetInfo<string> {
    return {
        ephemeralKey: abToS(ori.ephemeralKey),
        added: ori.added,
    }
}

export function ratchetStringToArrayBuffer(r: Ratchet<string>): Ratchet<ArrayBuffer> {
    return {
        rootKey: toAB(r.rootKey),
        ephemeralKeyPair: r.ephemeralKeyPair && keyPairStirngToArrayBuffer(r.ephemeralKeyPair),
        lastRemoteEphemeralKey: toAB(r.lastRemoteEphemeralKey),
        previousCounter: r.previousCounter,
        added: r.added,
    }
}

export function ratchetArrayBufferToString(r: Ratchet<ArrayBuffer>): Ratchet<string> {
    return {
        rootKey: abToS(r.rootKey),
        ephemeralKeyPair: r.ephemeralKeyPair && keyPairArrayBufferToString(r.ephemeralKeyPair),
        lastRemoteEphemeralKey: abToS(r.lastRemoteEphemeralKey),
        previousCounter: r.previousCounter,
        added: r.added,
    }
}

export function indexInfoStringToArrayBuffer(ii: IndexInfo<string>): IndexInfo<ArrayBuffer> {
    const { closed, remoteIdentityKey, baseKey, baseKeyType } = ii
    return {
        closed,
        remoteIdentityKey: toAB(remoteIdentityKey),
        baseKey: baseKey ? toAB(baseKey) : undefined,
        baseKeyType,
    }
}

export function indexInfoArrayBufferToString(ii: IndexInfo<ArrayBuffer>): IndexInfo<string> {
    const { closed, remoteIdentityKey, baseKey, baseKeyType } = ii
    return {
        closed,
        remoteIdentityKey: abToS(remoteIdentityKey),
        baseKey: baseKey ? abToS(baseKey) : undefined,
        baseKeyType,
    }
}

export function sessionTypeStringToArrayBuffer(sess: SessionType<string>): SessionType<ArrayBuffer> {
    const { indexInfo, registrationId, currentRatchet, pendingPreKey, oldRatchetList, chains } = sess
    const newChains: { [ephKeyString: string]: Chain<ArrayBuffer> } = {}
    for (const k of Object.keys(chains)) {
        newChains[k] = chainStringToArrayBuffer(chains[k])
    }
    return {
        indexInfo: indexInfoStringToArrayBuffer(indexInfo),
        registrationId,
        currentRatchet: ratchetStringToArrayBuffer(currentRatchet),
        pendingPreKey: pendingPreKey ? pendingPreKeyStringToArrayBuffer(pendingPreKey) : undefined,
        oldRatchetList: oldRatchetList.map(oldRatchetInfoStringToArrayBuffer),
        chains: newChains,
    }
}

export function sessionTypeArrayBufferToString(sess: SessionType<ArrayBuffer>): SessionType<string> {
    const { indexInfo, registrationId, currentRatchet, pendingPreKey, oldRatchetList, chains } = sess
    const newChains: { [ephKeyString: string]: Chain<string> } = {}
    for (const k of Object.keys(chains)) {
        newChains[k] = chainArrayBufferToString(chains[k])
    }
    return {
        indexInfo: indexInfoArrayBufferToString(indexInfo),
        registrationId,
        currentRatchet: ratchetArrayBufferToString(currentRatchet),
        pendingPreKey: pendingPreKey ? pendingPreKeyArrayBufferToString(pendingPreKey) : undefined,
        oldRatchetList: oldRatchetList.map(oldRatchetInfoArrayBufferToString),
        chains: newChains,
    }
}

/*

var Internal = Internal || {};

Internal.BaseKeyType = {
  OURS: 1,
  THEIRS: 2
};
Internal.ChainType = {
  SENDING: 1,
  RECEIVING: 2
};



    var migrations = [
      {
        version: 'v1',
        migrate: function migrateV1(data) {
          var sessions = data.sessions;
          var key;
          if (data.registrationId) {
              for (key in sessions) {
                  if (!sessions[key].registrationId) {
                      sessions[key].registrationId = data.registrationId;
                  }
              }
          } else {
              for (key in sessions) {
                  if (sessions[key].indexInfo.closed === -1) {
                      console.log('V1 session storage migration error: registrationId',
                          data.registrationId, 'for open session version',
                          data.version);
                  }
              }
          }
        }
      }
    ];

    function migrate(data) {
      var run = (data.version === undefined);
      for (var i=0; i < migrations.length; ++i) {
        if (run) {
          migrations[i].migrate(data);
        } else if (migrations[i].version === data.version) {
          run = true;
        }
      }
      if (!run) {
        throw new Error("Error migrating SessionRecord");
      }
    }

 ,

        ,
}();*/
