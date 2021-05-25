// Invoke this file to build the app using esbuild
import esbuild from 'esbuild'
import rimraf from 'rimraf'

const outdir = 'dist/'

try {
    /** @type esbuild.BuildOptions */
    const esbuildOpts = {
        entryPoints: ['src/index.ts'],
        outfile: outdir + 'index.js',
        bundle: true,
        platform: 'node',
        target: 'es2018',
        charset: 'utf8',
        color: true,
        format: 'iife',
    }

    // Clean the output directory
    rimraf.sync(outdir)

    // Build with esbuild
    await esbuild.build(esbuildOpts)
} catch (err) {
    process.exit(1)
}
