import {setFailed} from '@actions/core'
import Worker from './worker'

// Main function
;(async () => {
    // Start the worker
    try {
        const worker = new Worker()
        const res = await worker.Start()
        // Print the result
        console.log('Base64-encoded hash is: ' + res.hash)
        console.log('Tweet ID: ' + res.tweetId)
        console.log('Tweet URL: ' + res.tweetUrl)
    } catch (err) {
        setFailed(err.message || err)
    }
})()
