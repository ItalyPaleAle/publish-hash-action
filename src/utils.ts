/**
 * Encodes a Buffer object to base64 in URL-safe format
 * @param buf Buffer to encode
 * @returns The buffer encoded to base64 URL-encoding
 */
export function BufToBase64Url(buf: Buffer): string {
    // Convert with a regex
    return buf
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
}
