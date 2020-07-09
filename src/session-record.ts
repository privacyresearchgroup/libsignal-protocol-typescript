import ByteBuffer from 'bytebuffer'
import * as util from './helpers'
import { Stringable } from './types'
import { SessionType, BaseKeyType } from './session-types'

const ARCHIVED_STATES_MAX_LENGTH = 40
const OLD_RATCHETS_MAX_LENGTH = 10
const SESSION_RECORD_VERSION = 'v1'

export class SessionRecord {
    sessions: { [k: string]: SessionType } = {}
    version = SESSION_RECORD_VERSION

    static deserialize(serialized: string): SessionRecord {
        const data = JSON.parse(serialized)
        if (data.version !== SESSION_RECORD_VERSION) {
            // migrate(data)
        }

        const record = new SessionRecord()
        record.sessions = data.sessions
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
        return jsonThing({
            sessions: this.sessions,
            version: this.version,
        })
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

function isStringableObject(thing: unknown): thing is Stringable {
    return (
        thing === Object(thing) &&
        (thing instanceof ArrayBuffer || thing instanceof Uint8Array || thing instanceof ByteBuffer)
    )
}
function ensureStringed(thing: unknown) {
    if (typeof thing == 'string' || typeof thing == 'number' || typeof thing == 'boolean') {
        return thing
    } else if (isStringableObject(thing)) {
        return util.toString(thing)
    } else if (Array.isArray(thing)) {
        return thing.map(ensureStringed)
    } else if (typeof thing === 'object') {
        const obj = {}
        for (const key in thing) {
            try {
                obj[key] = ensureStringed(thing[key])
            } catch (ex) {
                console.log('Error serializing key', key)
                throw ex
            }
        }
        return obj
    } else if (thing === null) {
        return null
    } else {
        throw new Error('unsure of how to jsonify object of type ' + typeof thing)
    }
}

function jsonThing(thing: unknown): string {
    return JSON.stringify(ensureStringed(thing)) //TODO: jquery???
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
