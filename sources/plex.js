/**
 * Plex media source for posterrama.app
 * Handles fetching and processing media from a Plex server.
 */

const logger = require('../logger');

/**
 * Creates a Plex client with the specified options
 */
function createPlexClient(options) {
    const PlexAPI = require('plex-api');
    const clientOptions = {
        hostname: options.hostname,
        port: options.port,
        token: options.token,
        timeout: options.timeout || 10000
    };
    return new PlexAPI(clientOptions);
}

/**
 * Performs a lightweight connection test for a given media server configuration.
 * @param {object} serverConfig The configuration object for the server from config.json.
 * @returns {Promise<{status: ('ok'|'error'), message: string}>} The result of the connection test.
 */
async function testServerConnection(serverConfig) {
    if (serverConfig.type === 'plex') {
        const startTime = process.hrtime();
        
        logger.debug('Testing Plex server connection', {
            action: 'plex_connection_test',
            server: {
                name: serverConfig.name,
                hostnameVar: serverConfig.hostnameEnvVar,
                portVar: serverConfig.portEnvVar
            }
        });

        try {
            const hostname = process.env[serverConfig.hostnameEnvVar];
            const port = process.env[serverConfig.portEnvVar];
            const token = process.env[serverConfig.tokenEnvVar];

            if (!hostname || !port || !token) {
                throw new Error('Missing required environment variables (hostname, port, or token) for this server.');
            }

            const testClient = createPlexClient({
                hostname,
                port,
                token,
                timeout: 5000 // 5-second timeout for health checks
            });

            // A lightweight query to check reachability and authentication
            await testClient.query('/');

            // Calculate response time
            const [seconds, nanoseconds] = process.hrtime(startTime);
            const responseTime = seconds * 1000 + nanoseconds / 1000000;

            // Log success with metrics
            logger.info('Plex server connection test successful', {
                action: 'plex_connection_success',
                server: {
                    name: serverConfig.name,
                    hostname: hostname,
                    port: port
                },
                metrics: {
                    responseTime: `${responseTime.toFixed(2)}ms`
                }
            });

            // Log warning if connection was slow
            if (responseTime > 1000) { // 1 second threshold
                logger.warn('Slow Plex server response detected', {
                    action: 'plex_connection_slow',
                    server: {
                        name: serverConfig.name,
                        hostname: hostname,
                        port: port
                    },
                    responseTime: `${responseTime.toFixed(2)}ms`
                });
            }

            return { status: 'ok', message: 'Connection successful.' };
        } catch (error) {
            let errorMessage = error.message;
            if (error.code === 'ECONNREFUSED') {
                errorMessage = 'Connection refused. Check hostname and port.';
                
                logger.error('Plex server connection refused', {
                    action: 'plex_connection_refused',
                    server: {
                        name: serverConfig.name,
                        hostname: process.env[serverConfig.hostnameEnvVar],
                        port: process.env[serverConfig.portEnvVar]
                    },
                    error: {
                        code: error.code,
                        message: error.message
                    }
                });
            } else if (error.message.includes('401 Unauthorized')) {
                errorMessage = 'Unauthorized. Check token.';
            } else if (error.code === 'ETIMEDOUT') {
                errorMessage = 'Connection timed out.';
            }
            return { status: 'error', message: `Plex connection failed: ${errorMessage}` };
        }
    }
    // Future server types can be added here
    return { status: 'error', message: `Unsupported server type for health check: ${serverConfig.type}` };
}

class PlexSource {
    constructor(serverConfig, getPlexClient, processPlexItem, getPlexLibraries, shuffleArray, rtMinScore, isDebug) {
        this.server = serverConfig;
        this.getPlexClient = getPlexClient;
        this.processPlexItem = processPlexItem;
        this.getPlexLibraries = getPlexLibraries;
        this.shuffleArray = shuffleArray;
        this.rtMinScore = rtMinScore;
        this.isDebug = isDebug;
        this.plex = this.getPlexClient(this.server);
    }

    /**
     * Fetches a specified number of items from a list of libraries.
     * @param {string[]} libraryNames - The names of the libraries to fetch from.
     * @param {string} type - The type of media ('movie' or 'show').
     * @param {number} count - The number of items to fetch.
     * @returns {Promise<object[]>} A promise that resolves to an array of processed media items.
     */
    async fetchMedia(libraryNames, type, count) {
        if (!libraryNames || libraryNames.length === 0 || count === 0) {
            return [];
        }

        if (this.isDebug) {
            console.log(`[PlexSource:${this.server.name}] Fetching ${count} ${type}(s) from libraries: ${libraryNames.join(', ')}`);
        }

        try {
            const allLibraries = await this.getPlexLibraries(this.server);
            let allItems = [];

            for (const name of libraryNames) {
                const library = allLibraries.get(name);
                if (!library) {
                    console.warn(`[PlexSource:${this.server.name}] Library "${name}" not found.`);
                    continue;
                }

                const content = await this.plex.query(`/library/sections/${library.key}/all`);
                if (content?.MediaContainer?.Metadata) {
                    allItems = allItems.concat(content.MediaContainer.Metadata);
                }
            }

            if (this.isDebug) console.log(`[PlexSource:${this.server.name}] Found ${allItems.length} total items in specified libraries.`);

            const shuffledItems = this.shuffleArray(allItems);
            const selectedItems = count > 0 ? shuffledItems.slice(0, count) : shuffledItems;

            const processedItems = await Promise.all(
                selectedItems.map(item => this.processPlexItem(item, this.server, this.plex))
            );

            const finalItems = processedItems.filter(item => {
                if (!item) return false;
                if (this.rtMinScore > 0 && item.rottenTomatoes) {
                    return item.rottenTomatoes.originalScore * 10 >= this.rtMinScore;
                }
                return true;
            });

            if (this.isDebug) console.log(`[PlexSource:${this.server.name}] Returning ${finalItems.length} processed items.`);
            return finalItems;
        } catch (error) {
            console.error(`[PlexSource:${this.server.name}] Error fetching media: ${error.message}`);
            return [];
        }
    }
}

module.exports = PlexSource;
module.exports.testServerConnection = testServerConnection;