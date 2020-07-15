import { SignalProtocolAddress } from '../signal-protocol-address'

describe('SignalProtocolAddress', function () {
    const name = 'name'
    const deviceId = 42
    const serialized = 'name.42'

    describe('getName', function () {
        test('returns the name', () => {
            const address = new SignalProtocolAddress(name, 1)
            expect(address.getName()).toBe(name)
            expect(address.name).toBe(name)
        })
    })

    describe('getDeviceId', function () {
        test('returns the deviceId', () => {
            const address = new SignalProtocolAddress(name, deviceId)
            expect(address.getDeviceId()).toBe(deviceId)
            expect(address.deviceId).toBe(deviceId)
        })
    })

    describe('toString', function () {
        test('returns the address', () => {
            const address = new SignalProtocolAddress(name, deviceId)
            expect(address.toString()).toBe(serialized)
        })
    })
    describe('fromString', function () {
        test('throws on a bad inputs', () => {
            const bads = ['', null, {}]
            for (const bad of bads) {
                expect(() => {
                    // We are testing data that Typescript wouldn't allow
                    // because Javascript users might send it.
                    SignalProtocolAddress.fromString(bad as string)
                }).toThrow()
            }
        })

        test('constructs the address', () => {
            const address = SignalProtocolAddress.fromString(serialized)
            expect(address.getDeviceId()).toBe(deviceId)
            expect(address.deviceId).toBe(deviceId)
            expect(address.getName()).toBe(name)
            expect(address.name).toBe(name)
        })
    })
})
