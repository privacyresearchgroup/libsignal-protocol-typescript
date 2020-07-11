/* eslint-disable @typescript-eslint/no-explicit-any */
/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */

const jobQueue: { [k: string]: Promise<any> } = {}

export type JobType<T> = () => Promise<T>

export class SessionLock {
    static queueJobForNumber<T>(id: string, runJob: JobType<T>): Promise<T> {
        const runPrevious = jobQueue[id] || Promise.resolve()
        const runCurrent = (jobQueue[id] = runPrevious.then(runJob, runJob))
        runCurrent
            .then(function () {
                if (jobQueue[id] === runCurrent) {
                    delete jobQueue[id]
                }
            })
            .catch((_) => {
                // console.warn(e)
            })
        return runCurrent
    }
}
