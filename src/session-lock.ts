/* eslint-disable @typescript-eslint/no-explicit-any */
/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */

const jobQueue: { [k: string]: Promise<any> } = {}

export type JobType = () => Promise<any>

export class SessionLock {
    static queueJobForNumber(id: string, runJob: JobType): Promise<any> {
        console.log(`queue job`, { id, jobQueue })
        const runPrevious = jobQueue[id] || Promise.resolve()
        const runCurrent = (jobQueue[id] = runPrevious.then(runJob, runJob))
        runCurrent
            .then(function () {
                console.log(`clear queue`, { id, jobQueue })
                if (jobQueue[id] === runCurrent) {
                    delete jobQueue[id]
                }
            })
            .catch((e) => {
                console.warn(e)
            })
        console.log(`returning runCurrent`, { id, jobQueue })
        return runCurrent
    }
}
