<?php

/**
 * Deepgram Flux Starter - PHP (Ratchet)
 *
 * WebSocket proxy server for Deepgram's Flux API using Ratchet + ReactPHP.
 * Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Key Features:
 * - WebSocket proxy: /api/flux -> wss://api.deepgram.com/v2/listen
 * - JWT session auth via access_token.<jwt> subprotocol
 * - HTTP endpoints: GET /api/session, GET /api/metadata
 * - CORS enabled for frontend communication
 * - Graceful shutdown on SIGINT/SIGTERM
 *
 * Usage: php server.php
 */

require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Yosymfony\Toml\Toml;
use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use Ratchet\Http\HttpServerInterface;
use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use Ratchet\WebSocket\WsServer;
use Ratchet\WebSocket\WsServerInterface;
use React\EventLoop\Loop;
use React\Socket\SocketServer;
use Ratchet\Http\Router;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

// ============================================================================
// ENVIRONMENT LOADING
// ============================================================================

Dotenv::createImmutable(__DIR__)->safeLoad();

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Server and Deepgram configuration.
 * Port and host can be overridden via environment variables.
 */
$CONFIG = [
    'port' => $_ENV['PORT'] ?? '8081',
    'host' => $_ENV['HOST'] ?? '0.0.0.0',
    'deepgramSttUrl' => 'wss://api.deepgram.com/v2/listen',
];

// ============================================================================
// API KEY LOADING
// ============================================================================

/**
 * Load the Deepgram API key from environment variables.
 * Exits with a helpful error message if not found.
 *
 * @return string The Deepgram API key
 */
function loadApiKey(): string
{
    $apiKey = $_ENV['DEEPGRAM_API_KEY'] ?? '';

    if (empty($apiKey)) {
        fwrite(STDERR, "\nERROR: Deepgram API key not found!\n\n");
        fwrite(STDERR, "Please set your API key using one of these methods:\n\n");
        fwrite(STDERR, "1. Create a .env file (recommended):\n");
        fwrite(STDERR, "   DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "2. Environment variable:\n");
        fwrite(STDERR, "   export DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "Get your API key at: https://console.deepgram.com\n\n");
        exit(1);
    }

    return $apiKey;
}

$API_KEY = loadApiKey();

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/**
 * Session secret for signing JWTs.
 * Generated at startup if SESSION_SECRET env var is not set.
 */
$SESSION_SECRET = $_ENV['SESSION_SECRET'] ?? bin2hex(random_bytes(32));

/** JWT expiry time in seconds (1 hour) */
define('JWT_EXPIRY', 3600);

/**
 * Create a signed JWT session token.
 *
 * @param string $secret The secret key for signing
 * @return string The encoded JWT token
 */
function createSessionToken(string $secret): string
{
    $now = time();
    $payload = [
        'iat' => $now,
        'exp' => $now + JWT_EXPIRY,
    ];
    return JWT::encode($payload, $secret, 'HS256');
}

/**
 * Validate JWT from WebSocket subprotocol: access_token.<jwt>
 * Returns the full subprotocol string if valid, null if invalid.
 *
 * @param string|null $protocolHeader The Sec-WebSocket-Protocol header value
 * @param string $secret The JWT signing secret
 * @return string|null The valid subprotocol string or null
 */
function validateWsToken(?string $protocolHeader, string $secret): ?string
{
    if ($protocolHeader === null || $protocolHeader === '') {
        return null;
    }

    $protocols = array_map('trim', explode(',', $protocolHeader));

    foreach ($protocols as $proto) {
        if (str_starts_with($proto, 'access_token.')) {
            $token = substr($proto, strlen('access_token.'));
            try {
                JWT::decode($token, new Key($secret, 'HS256'));
                return $proto;
            } catch (\Exception $e) {
                return null;
            }
        }
    }

    return null;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Reserved WebSocket close codes that cannot be set by applications.
 */
const RESERVED_CLOSE_CODES = [1004, 1005, 1006, 1015];

/**
 * Returns a safe close code, defaulting to 1000 if the given code is reserved.
 *
 * @param int $code The close code to check
 * @return int A safe close code
 */
function getSafeCloseCode(int $code): int
{
    if ($code >= 1000 && $code <= 4999 && !in_array($code, RESERVED_CLOSE_CODES)) {
        return $code;
    }
    return 1000;
}

/**
 * Build the Deepgram WebSocket URL from client query parameters.
 *
 * @param string $queryString The client's query string
 * @param string $baseUrl The base Deepgram STT URL
 * @return string The fully-qualified Deepgram URL
 */
function buildDeepgramUrl(string $queryString, string $baseUrl): string
{
    parse_str($queryString, $params);

    $model = 'flux-general-en';
    $encoding = $params['encoding'] ?? 'linear16';
    $sampleRate = $params['sample_rate'] ?? '16000';
    $channels = $params['channels'] ?? '1';

    $dgParams = [
        'model' => $model,
        'encoding' => $encoding,
        'sample_rate' => $sampleRate,
        'channels' => $channels,
    ];

    // Optional parameters
    if (!empty($params['eot_threshold'])) {
        $dgParams['eot_threshold'] = $params['eot_threshold'];
    }
    if (!empty($params['eager_eot_threshold'])) {
        $dgParams['eager_eot_threshold'] = $params['eager_eot_threshold'];
    }
    if (!empty($params['eot_timeout_ms'])) {
        $dgParams['eot_timeout_ms'] = $params['eot_timeout_ms'];
    }

    $url = $baseUrl . '?' . http_build_query($dgParams);

    // Handle keyterm parameters (can appear multiple times)
    // http_build_query cannot handle repeated keys, so we append them manually
    if (isset($params['keyterm'])) {
        $keyterms = is_array($params['keyterm']) ? $params['keyterm'] : [$params['keyterm']];
        foreach ($keyterms as $term) {
            $url .= '&keyterm=' . rawurlencode($term);
        }
    }

    return $url;
}

/**
 * Send a JSON HTTP response via Ratchet ConnectionInterface.
 *
 * @param ConnectionInterface $conn The HTTP connection
 * @param int $status HTTP status code
 * @param mixed $data Data to encode as JSON
 * @param array $extraHeaders Additional headers
 */
function sendHttpResponse(ConnectionInterface $conn, int $status, mixed $data, array $extraHeaders = []): void
{
    $body = json_encode($data, JSON_UNESCAPED_SLASHES);

    $headers = array_merge([
        'Content-Type' => 'application/json',
        'Content-Length' => strlen($body),
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Methods' => 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers' => 'Content-Type, Authorization',
    ], $extraHeaders);

    $statusTexts = [
        200 => 'OK',
        204 => 'No Content',
        404 => 'Not Found',
        500 => 'Internal Server Error',
    ];
    $statusText = $statusTexts[$status] ?? 'Unknown';

    $response = "HTTP/1.1 {$status} {$statusText}\r\n";
    foreach ($headers as $key => $value) {
        $response .= "{$key}: {$value}\r\n";
    }
    $response .= "\r\n";
    $response .= $body;

    $conn->send($response);
    $conn->close();
}

// ============================================================================
// WEBSOCKET PROXY HANDLER - /api/flux
// ============================================================================

/**
 * Flux WebSocket proxy handler.
 * Authenticates clients via JWT subprotocol, connects to Deepgram Flux API,
 * and forwards all messages bidirectionally.
 */
class FluxHandler implements WsServerInterface
{
    /** @var \SplObjectStorage Active client connections */
    private \SplObjectStorage $clients;

    /** @var array<int,\Ratchet\Client\WebSocket> Map of client resource ID to Deepgram WS */
    private array $deepgramConnections = [];

    /** @var string Deepgram API key */
    private string $apiKey;

    /** @var string JWT signing secret */
    private string $sessionSecret;

    /** @var string Base Deepgram STT URL */
    private string $deepgramSttUrl;

    /** @var array<int,int> Client message counts for logging */
    private array $clientMsgCounts = [];

    /** @var array<int,int> Deepgram message counts for logging */
    private array $dgMsgCounts = [];

    public function __construct(string $apiKey, string $sessionSecret, string $deepgramSttUrl)
    {
        $this->clients = new \SplObjectStorage();
        $this->apiKey = $apiKey;
        $this->sessionSecret = $sessionSecret;
        $this->deepgramSttUrl = $deepgramSttUrl;
    }

    /**
     * Return the list of subprotocols the server supports.
     * Ratchet calls this to negotiate with the client.
     *
     * @param array $protocols Protocols requested by the client
     * @return array Protocols the server agrees to
     */
    public function getSubProtocols(): array
    {
        // Ratchet uses this for the initial handshake; we handle protocol
        // negotiation dynamically in onOpen via the request headers.
        return [];
    }

    /**
     * Handle new WebSocket connection.
     * Validates JWT from subprotocol, then opens upstream Deepgram connection.
     *
     * @param ConnectionInterface $conn The client connection
     */
    public function onOpen(ConnectionInterface $conn): void
    {
        $resourceId = $conn->resourceId;

        // Extract query string from the request
        $queryString = '';
        if (isset($conn->httpRequest)) {
            $uri = $conn->httpRequest->getUri();
            $queryString = $uri->getQuery();

            // Validate JWT from subprotocol header
            $protocolHeader = $conn->httpRequest->getHeaderLine('Sec-WebSocket-Protocol');
            $validProto = validateWsToken($protocolHeader, $this->sessionSecret);

            if ($validProto === null) {
                echo "WebSocket auth failed: invalid or missing token (client #{$resourceId})\n";
                $conn->close();
                return;
            }

            echo "Client #{$resourceId} connected to /api/flux (authenticated)\n";
        }

        $this->clients->attach($conn);
        $this->clientMsgCounts[$resourceId] = 0;
        $this->dgMsgCounts[$resourceId] = 0;

        // Build Deepgram URL from client query params
        $deepgramUrl = buildDeepgramUrl($queryString, $this->deepgramSttUrl);

        echo "Connecting to Deepgram Flux: {$deepgramUrl}\n";

        // Connect to Deepgram via Pawl (ReactPHP WebSocket client)
        $connector = new \Ratchet\Client\Connector(Loop::get());

        $connector($deepgramUrl, [], [
            'Authorization' => 'Token ' . $this->apiKey,
        ])->then(
            function (\Ratchet\Client\WebSocket $dgWs) use ($conn, $resourceId) {
                echo "Connected to Deepgram Flux API (client #{$resourceId})\n";

                $this->deepgramConnections[$resourceId] = $dgWs;

                // Forward Deepgram messages to client
                $dgWs->on('message', function (\Ratchet\RFC6455\Messaging\MessageInterface $msg) use ($conn, $resourceId) {
                    $this->dgMsgCounts[$resourceId] = ($this->dgMsgCounts[$resourceId] ?? 0) + 1;
                    $count = $this->dgMsgCounts[$resourceId];

                    $payload = $msg->getPayload();
                    $isBinary = $msg->isBinary();

                    if ($count % 10 === 0 || !$isBinary) {
                        echo "  Deepgram message #{$count} (binary: " . ($isBinary ? 'true' : 'false') . ", size: " . strlen($payload) . ") -> client #{$resourceId}\n";
                    }

                    if ($conn->writable ?? true) {
                        if ($isBinary) {
                            $frame = new \Ratchet\RFC6455\Messaging\Frame($payload, true, \Ratchet\RFC6455\Messaging\Frame::OP_BINARY);
                            $conn->send($frame);
                        } else {
                            $conn->send($payload);
                        }
                    }
                });

                // Handle Deepgram close
                $dgWs->on('close', function ($code = null, $reason = null) use ($conn, $resourceId) {
                    $code = $code ?? 1000;
                    $reason = $reason ?? '';
                    echo "Deepgram connection closed (client #{$resourceId}): {$code} {$reason}\n";

                    unset($this->deepgramConnections[$resourceId]);

                    if ($this->clients->contains($conn)) {
                        $conn->close(getSafeCloseCode($code));
                    }
                });

                // Handle Deepgram errors
                $dgWs->on('error', function (\Exception $e) use ($conn, $resourceId) {
                    echo "Deepgram WebSocket error (client #{$resourceId}): {$e->getMessage()}\n";

                    unset($this->deepgramConnections[$resourceId]);

                    if ($this->clients->contains($conn)) {
                        $conn->close(1011);
                    }
                });
            },
            function (\Exception $e) use ($conn, $resourceId) {
                echo "Failed to connect to Deepgram (client #{$resourceId}): {$e->getMessage()}\n";

                if ($this->clients->contains($conn)) {
                    $conn->close(1011);
                }
            }
        );
    }

    /**
     * Handle incoming message from client. Forward to Deepgram.
     *
     * @param ConnectionInterface $conn The client connection
     * @param string $msg The message data
     */
    public function onMessage(ConnectionInterface $conn, $msg): void
    {
        $resourceId = $conn->resourceId;
        $this->clientMsgCounts[$resourceId] = ($this->clientMsgCounts[$resourceId] ?? 0) + 1;
        $count = $this->clientMsgCounts[$resourceId];

        $isBinary = $msg instanceof \Ratchet\RFC6455\Messaging\MessageInterface
            ? $msg->isBinary()
            : false;
        $payload = $msg instanceof \Ratchet\RFC6455\Messaging\MessageInterface
            ? $msg->getPayload()
            : (string) $msg;

        if ($count % 100 === 0 || !$isBinary) {
            echo "  Client #{$resourceId} message #{$count} (binary: " . ($isBinary ? 'true' : 'false') . ", size: " . strlen($payload) . ") -> Deepgram\n";
        }

        if (isset($this->deepgramConnections[$resourceId])) {
            $dgWs = $this->deepgramConnections[$resourceId];
            if ($isBinary) {
                $frame = new \Ratchet\RFC6455\Messaging\Frame($payload, true, \Ratchet\RFC6455\Messaging\Frame::OP_BINARY);
                $dgWs->send($frame);
            } else {
                $dgWs->send($payload);
            }
        }
    }

    /**
     * Handle client disconnect. Close corresponding Deepgram connection.
     *
     * @param ConnectionInterface $conn The client connection
     */
    public function onClose(ConnectionInterface $conn): void
    {
        $resourceId = $conn->resourceId;
        echo "Client #{$resourceId} disconnected\n";

        $this->clients->detach($conn);

        // Close Deepgram connection if open
        if (isset($this->deepgramConnections[$resourceId])) {
            $this->deepgramConnections[$resourceId]->close(1000, 'Client disconnected');
            unset($this->deepgramConnections[$resourceId]);
        }

        // Clean up counters
        unset($this->clientMsgCounts[$resourceId]);
        unset($this->dgMsgCounts[$resourceId]);
    }

    /**
     * Handle client WebSocket error.
     *
     * @param ConnectionInterface $conn The client connection
     * @param \Exception $e The error
     */
    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        $resourceId = $conn->resourceId;
        echo "Client #{$resourceId} WebSocket error: {$e->getMessage()}\n";

        // Close Deepgram connection if open
        if (isset($this->deepgramConnections[$resourceId])) {
            $this->deepgramConnections[$resourceId]->close(1011, 'Client error');
            unset($this->deepgramConnections[$resourceId]);
        }

        $conn->close();
    }

    /**
     * Get number of active connections.
     *
     * @return int Number of active connections
     */
    public function getConnectionCount(): int
    {
        return $this->clients->count();
    }

    /**
     * Close all active connections for graceful shutdown.
     */
    public function closeAll(): void
    {
        foreach ($this->clients as $conn) {
            try {
                $conn->close(1001);
            } catch (\Exception $e) {
                // Ignore errors during shutdown
            }
        }

        foreach ($this->deepgramConnections as $dgWs) {
            try {
                $dgWs->close(1000, 'Server shutting down');
            } catch (\Exception $e) {
                // Ignore errors during shutdown
            }
        }
    }
}

// ============================================================================
// HTTP HANDLER - /api/session, /api/metadata, and CORS
// ============================================================================

/**
 * HTTP request handler for REST endpoints.
 * Handles GET /api/session, GET /api/metadata, and CORS preflight.
 */
class HttpHandler implements HttpServerInterface
{
    /** @var string JWT signing secret */
    private string $sessionSecret;

    public function __construct(string $sessionSecret)
    {
        $this->sessionSecret = $sessionSecret;
    }

    /**
     * Handle incoming HTTP request.
     *
     * @param ConnectionInterface $conn The HTTP connection
     * @param RequestInterface $request The PSR-7 request
     */
    public function onOpen(ConnectionInterface $conn, RequestInterface $request = null): void
    {
        $path = $request?->getUri()->getPath() ?? '/';
        $method = $request?->getMethod() ?? 'GET';

        // Handle CORS preflight
        if ($method === 'OPTIONS') {
            $response = "HTTP/1.1 204 No Content\r\n";
            $response .= "Access-Control-Allow-Origin: *\r\n";
            $response .= "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
            $response .= "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
            $response .= "Content-Length: 0\r\n";
            $response .= "\r\n";
            $conn->send($response);
            $conn->close();
            return;
        }

        // GET /api/session - Issue JWT session token
        if ($path === '/api/session' && $method === 'GET') {
            $token = createSessionToken($this->sessionSecret);
            sendHttpResponse($conn, 200, ['token' => $token]);
            return;
        }

        // GET /health - Simple health check
        if ($path === '/health' && $method === 'GET') {
            sendHttpResponse($conn, 200, ['status' => 'ok']);
            return;
        }

        // GET /api/metadata - Return metadata from deepgram.toml
        if ($path === '/api/metadata' && $method === 'GET') {
            try {
                $tomlPath = __DIR__ . '/deepgram.toml';

                if (!file_exists($tomlPath)) {
                    sendHttpResponse($conn, 500, [
                        'error' => 'INTERNAL_SERVER_ERROR',
                        'message' => 'deepgram.toml not found',
                    ]);
                    return;
                }

                $config = Toml::parseFile($tomlPath);

                if (!isset($config['meta'])) {
                    sendHttpResponse($conn, 500, [
                        'error' => 'INTERNAL_SERVER_ERROR',
                        'message' => 'Missing [meta] section in deepgram.toml',
                    ]);
                    return;
                }

                sendHttpResponse($conn, 200, $config['meta']);
            } catch (\Exception $e) {
                error_log('Error reading metadata: ' . $e->getMessage());
                sendHttpResponse($conn, 500, [
                    'error' => 'INTERNAL_SERVER_ERROR',
                    'message' => 'Failed to read metadata from deepgram.toml',
                ]);
            }
            return;
        }

        // 404 for unknown routes
        sendHttpResponse($conn, 404, [
            'error' => 'Not Found',
            'message' => 'Endpoint not found',
        ]);
    }

    public function onMessage(ConnectionInterface $conn, $msg): void
    {
        // HTTP handler does not receive messages
    }

    public function onClose(ConnectionInterface $conn): void
    {
        // Nothing to clean up
    }

    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        echo "HTTP error: {$e->getMessage()}\n";
        $conn->close();
    }
}

// ============================================================================
// SERVER SETUP - Ratchet IoServer with Router
// ============================================================================

$loop = Loop::get();

// Create the WebSocket proxy handler
$fluxHandler = new FluxHandler($API_KEY, $SESSION_SECRET, $CONFIG['deepgramSttUrl']);

// Create the HTTP handler
$httpHandler = new HttpHandler($SESSION_SECRET);

// Build routes using Symfony Routing
$routes = new RouteCollection();

// WebSocket route for /api/flux
$routes->add('flux', new Route('/api/flux', [
    '_controller' => new WsServer($fluxHandler),
], [], [], '', [], ['GET']));

// HTTP routes for everything else
$routes->add('http_catch_all', new Route('/{path}', [
    '_controller' => $httpHandler,
], ['path' => '.*'], [], '', [], ['GET', 'POST', 'OPTIONS']));

$requestContext = new RequestContext();
$urlMatcher = new UrlMatcher($routes, $requestContext);
$router = new Router($urlMatcher);

// Create the server
$socket = new SocketServer("{$CONFIG['host']}:{$CONFIG['port']}", [], $loop);
$server = new IoServer(
    new HttpServer($router),
    $socket,
    $loop
);

echo "\n" . str_repeat('=', 70) . "\n";
echo "Backend API Server running at http://localhost:{$CONFIG['port']}\n";
echo "\n";
echo "GET  /api/session\n";
echo "WS   /api/flux (auth required)\n";
echo "GET  /api/metadata\n";
echo "GET  /health\n";
echo str_repeat('=', 70) . "\n\n";

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

/**
 * Handle shutdown signals to close connections cleanly.
 */
function gracefulShutdown(int $signal, $loop, FluxHandler $handler): void
{
    $signalName = match ($signal) {
        SIGINT => 'SIGINT',
        SIGTERM => 'SIGTERM',
        default => "Signal {$signal}",
    };

    echo "\n{$signalName} received: starting graceful shutdown...\n";

    $count = $handler->getConnectionCount();
    echo "Closing {$count} active WebSocket connection(s)...\n";
    $handler->closeAll();

    echo "Shutdown complete\n";
    $loop->stop();
}

// Register signal handlers if pcntl is available
if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGINT, function (int $sig) use ($loop, $fluxHandler) {
        gracefulShutdown($sig, $loop, $fluxHandler);
    });
    pcntl_signal(SIGTERM, function (int $sig) use ($loop, $fluxHandler) {
        gracefulShutdown($sig, $loop, $fluxHandler);
    });

    // Enable async signal handling in the event loop
    $loop->addPeriodicTimer(1, function () {
        pcntl_signal_dispatch();
    });
}

// ============================================================================
// START SERVER
// ============================================================================

$loop->run();
