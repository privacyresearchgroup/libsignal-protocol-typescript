import { SignalProtocolAddressType } from './'

export class SignalProtocolAddress implements SignalProtocolAddressType {
    static fromString(s: string): SignalProtocolAddress {
        if (!s.match(/.*\.\d+/)) {
            throw new Error(`Invalid SignalProtocolAddress string: ${s}`)
        }
        const parts = s.split('.')
        return new SignalProtocolAddress(parts[0], parseInt(parts[1]))
    }

    private _name: string
    private _deviceId: number
    constructor(_name: string, _deviceId: number) {
        this._name = _name
        this._deviceId = _deviceId
    }

    // Readonly properties
    get name(): string {
        return this._name
    }

    get deviceId(): number {
        return this._deviceId
    }

    // Expose properties as fuynctions for compatibility
    getName(): string {
        return this._name
    }

    getDeviceId(): number {
        return this._deviceId
    }

    toString(): string {
        return `${this._name}.${this._deviceId}`
    }

    equals(other: SignalProtocolAddressType): boolean {
        // TODO: do we really need the instanceof check here? Could just check that
        // name and deviceId are defined. Is there any chance that a different type of
        // object with a name and deviceId will get passed in?
        if (!(other instanceof SignalProtocolAddress)) {
            return false
        }
        return other.name === this._name && other.deviceId == this._deviceId
    }
}
