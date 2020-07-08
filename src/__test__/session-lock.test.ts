import { SessionLock } from '../session-lock'

async function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms))
}

test('return something', async () => {
    let value = ''
    await Promise.all([
        SessionLock.queueJobForNumber('channel1', async () => {
            await sleep(10)
            value += 'long'
            return Promise.resolve()
        }),
    ])

    expect(value).toBe('long')
})

test('return longshort', async () => {
    let value = ''
    await Promise.all([
        SessionLock.queueJobForNumber('channel1', async () => {
            await sleep(3000)
            value += 'long'
            return Promise.resolve()
        }),
        sleep(1000),
        SessionLock.queueJobForNumber('channel1', async () => {
            await sleep(1)
            value += 'short'
            return Promise.resolve()
        }),
    ])

    expect(value).toBe('longshort')
})

test('return shortlong', async () => {
    let value = ''
    await Promise.all([
        SessionLock.queueJobForNumber('channel1', async () => {
            await sleep(1)
            value += 'short'
            return Promise.resolve()
        }),
        SessionLock.queueJobForNumber('channel1', async () => {
            await sleep(2000)
            value += 'long'
            return Promise.resolve()
        }),
    ])

    expect(value).toBe('shortlong')
})

test('multichannel', async () => {
    let value = ''
    await Promise.all([
        SessionLock.queueJobForNumber('channel1', async () => {
            await sleep(4000)
            value += 'long'
            return Promise.resolve()
        }),
        SessionLock.queueJobForNumber('channel2', async () => {
            await sleep(1)
            value += 'ch2'
            return Promise.resolve()
        }),
        SessionLock.queueJobForNumber('channel1', async () => {
            await sleep(1)
            value += 'short'
            return Promise.resolve()
        }),
    ])

    expect(value).toBe('ch2longshort')
})
