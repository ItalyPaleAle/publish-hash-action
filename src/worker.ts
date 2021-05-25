import {getInput, setOutput} from '@actions/core'
import {TwitterClient} from 'twitter-api-client'
import {createHash} from 'crypto'
import {createReadStream} from 'fs'

/**
 * Main class that performs the work required by this Action
 */
export default class Worker {
    private file: string
    private twitterClient: TwitterClient

    constructor() {
        // Get the input data and ensure it's not empty, and init the Twitter client
        this.file = this.getRequiredInput('file')
        this.twitterClient = new TwitterClient({
            apiKey: this.getRequiredInput('consumer-key'),
            apiSecret: this.getRequiredInput('consumer-secret'),
            accessToken: this.getRequiredInput('access-token'),
            accessTokenSecret: this.getRequiredInput('access-token-secret'),
        })
    }

    /**
     * Starts the process of hashing the file and then publishing the hash on Twitter
     * @returns The URL of the tweet that was posted
     */
    async Start(): Promise<string> {
        // First, hash the file
        const hash = await this.hashFile(this.file)

        // Create a Tweet
        const res = await this.twitterClient.tweets.statusesUpdate({
            status: 'Hash is ' + hash,
        })
        
        // Set the output
        const tweetUrl = 'https://twitter.com/' + res.user.name + '/status/' + res.id_str
        setOutput('tweet-id', res.id_str)
        setOutput('tweet-url', tweetUrl)

        return tweetUrl
    }

    /**
     * Calculates the hash of a file
     * @param file File to hash
     * @returns Hash of the file, as a hex-encoded string
     */
    private hashFile(file: string): Promise<string> {
        const read = createReadStream(file)
        return new Promise((resolve, reject) => {
            const hash = createHash('sha256')
            read.on('error', (err) => {
                reject(err)
            })
            read.on('end', () => {
                resolve(hash.digest('hex'))
            })
            read.pipe(hash)
        })
    }

    /**
     * Gets an input from the Action and ensures it's not empty
     * @param name Name of the input
     * @returns The value from the input of the Action
     * @throws Throws if the input is empty
     */
    private getRequiredInput(name: string): string {
        const val = getInput(name)
        if (!val) {
            throw Error('Input ' + name + ' is required')
        }
        return val
    }
}
