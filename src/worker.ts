import {getInput, setOutput} from '@actions/core'
import {TwitterClient} from 'twitter-api-client'
import {createHash} from 'crypto'
import {createReadStream} from 'fs'
import {basename} from 'path'
import {BufToBase64Url} from './utils'

/**
 * Main class that performs the work required by this Action
 */
export default class Worker {
    private file: string
    private twitterClient: TwitterClient
    private repoName: string
    private serverUrl: string
    private actionRunId: string
    private commitSha: string

    constructor() {
        // Get the input data and ensure it's not empty, and init the Twitter client
        this.file = this.getRequiredInput('file')
        this.twitterClient = new TwitterClient({
            apiKey: this.getRequiredInput('consumer-key', 'TWITTER_CONSUMER_KEY'),
            apiSecret: this.getRequiredInput(
                'consumer-secret',
                'TWITTER_CONSUMER_SECRET'
            ),
            accessToken: this.getRequiredInput('access-token', 'TWITTER_ACCESS_TOKEN'),
            accessTokenSecret: this.getRequiredInput(
                'access-token-secret',
                'TWITTER_ACCESS_TOKEN_SECRET'
            ),
        })

        // Values from env vars
        this.repoName = process.env.GITHUB_REPOSITORY || ''
        if (!this.repoName) {
            throw Error('Could not find variable GITHUB_REPOSITORY in the environment')
        }
        this.serverUrl = process.env.GITHUB_SERVER_URL || ''
        if (!this.serverUrl) {
            throw Error('Could not find variable GITHUB_SERVER_URL in the environment')
        }
        this.commitSha = process.env.GITHUB_SHA || ''
        if (!this.commitSha) {
            throw Error('Could not find variable GITHUB_SHA in the environment')
        }
        this.actionRunId = process.env.GITHUB_RUN_ID || ''
        if (!this.actionRunId) {
            throw Error('Could not find variable GITHUB_RUN_ID in the environment')
        }
    }

    /**
     * Starts the process of hashing the file and then publishing the hash on Twitter
     * @returns The values that were stored as output
     */
    async Start(): Promise<{hash: string; tweetId: string; tweetUrl: string}> {
        // First, hash the file
        const hash = await this.hashFile(this.file)

        // Create a Tweet
        const res = await this.twitterClient.tweets.statusesUpdate({
            status: this.tweetText(this.file, hash),
        })

        // Set the output
        const tweetUrl = 'https://twitter.com/' + res.user.name + '/status/' + res.id_str
        setOutput('hash', hash)
        setOutput('tweet-id', res.id_str)
        setOutput('tweet-url', tweetUrl)

        return {
            hash,
            tweetId: res.id_str,
            tweetUrl,
        }
    }

    /**
     * Returns the text for the tweet to send
     * @param file File to hash
     * @param hash Hash of the file
     * @returns Content for the tweet
     */
    private tweetText(file: string, hash: string): string {
        // Get file name
        const fileName = basename(file)

        // Short commit hash
        const commit = this.commitSha.substr(0, 7)

        // Link to the run
        const runLink = [
            this.serverUrl,
            this.repoName,
            'actions',
            'runs',
            this.actionRunId,
        ].join('/')

        // Tweet text (without the link)
        // Must be 255 characters (280 - t.co link)
        const text =
            'In repo ' +
            this.repoName +
            ', the hash of file ' +
            fileName +
            ' at commit ' +
            commit +
            ' is:\n' +
            hash
        if (text.length > 255) {
            throw Error('The tweet is too long')
        }

        return text + '\n' + runLink
    }

    /**
     * Calculates the hash of a file
     * @param file File to hash
     * @returns Hash of the file, as a base64-encoded string
     */
    private hashFile(file: string): Promise<string> {
        const read = createReadStream(file)
        return new Promise((resolve, reject) => {
            const hash = createHash('sha256')
            read.on('error', (err) => {
                reject(err)
            })
            read.on('end', () => {
                resolve(BufToBase64Url(hash.digest()))
            })
            read.pipe(hash)
        })
    }

    /**
     * Gets an input from the Action and ensures it's not empty, with an optional fallback on env vars
     * @param name Name of the input
     * @param env Name of the environmental variable to fall back to
     * @returns The value from the input of the Action
     * @throws Throws if the input is empty
     */
    private getRequiredInput(name: string, env?: string): string {
        let val = getInput(name)
        if (!val && env) {
            val = process.env[env] || ''
        }
        if (!val) {
            throw Error('Input ' + name + ' is required')
        }
        return val
    }
}
