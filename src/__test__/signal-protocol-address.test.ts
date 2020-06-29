import { SignalProtocolAddress } from '../signal-protocol-address'

const name = 'name'
const deviceId = 42
var serialized = 'name.42'

test('getName', () => {
    const address = new SignalProtocolAddress(name, 1)
    expect(address.getName()).toBe(name)
    expect(address.name).toBe(name)
})

test('getDeviceId', () => {
    const address = new SignalProtocolAddress(name, deviceId)
    expect(address.getDeviceId()).toBe(deviceId)
    expect(address.deviceId).toBe(deviceId)
})

test('toString', () => {
    const address = new SignalProtocolAddress(name, deviceId)
    expect(address.toString()).toBe(serialized)
})

test('fromString throws on bad inputs', () => {
    const bads = ['', null, {}]
    for (const bad of bads) {
        expect(() => {
            // We are testing data that Typescript wouldn't allow
            // because Javascript users might send it.
            SignalProtocolAddress.fromString(bad as string)
        }).toThrow()
    }
})
