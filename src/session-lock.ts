/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */

let jobQueue = {}

export type JobType = () => Promise<any>

export class SessionLock {
    static queueJobForNumber(id: string, runJob: JobType): Promise<any> {
        const runPrevious = jobQueue[id] || Promise.resolve()
        const runCurrent = (jobQueue[id] = runPrevious.then(runJob, runJob))
        runCurrent.then(function () {
            if (jobQueue[id] === runCurrent) {
                delete jobQueue[id]
            }
        })
        return runCurrent
    }
}
