import {setFailed} from '@actions/core'
import Worker from './worker'

// Main function
;(async () => {
    // Start the worker
    try {
        const worker = new Worker()
        const twitterUrl = await worker.Start()
        console.log(twitterUrl)
    } catch (err) {
        setFailed(err.message || err)
    }
})()
