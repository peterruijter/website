<?php
/**
 * Cross-Origin Proxy Service - Enhanced with WAF Bypass Techniques
 * 
 * This script allows fetching content from any URL while avoiding Same-origin policy problems.
 * It acts as a proxy between client-side JavaScript and external APIs or websites.
 * 
 * Usage:
 * GET /proxy.php?url=https://example.com - Returns raw content
 * GET /proxy.php?url=https://example.com&format=json - Returns JSON with status and content
 * GET /proxy.php?url=https://example.com&format=jsonp&callback=myCallback - Returns JSONP
 * GET /proxy.php?url=https://example.com&debug=1 - Includes detailed debug info in response
 */

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set maximum execution time to avoid timeouts
set_time_limit(60);

// Configure options
$config = [
    'allow_requests_to_localhost' => false,
    'enable_cache' => true,
    'cache_time' => 3600, // 1 hour in seconds
    'cache_dir' => __DIR__ . '/cache/',
    'timeout' => 30,
    'max_redirects' => 10,
    'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'cors' => [
        'allow_origin' => '*', // Use specific domain in production
        'allow_methods' => 'GET, POST, OPTIONS',
        'allow_headers' => 'Origin, X-Requested-With, Content-Type, Accept',
        'max_age' => 86400 // 24 hours
    ],
    'verify_ssl' => false,
    'debug_mode' => isset($_GET['debug']) && $_GET['debug'] == '1',
    // List of challenging sites that need special handling
    'challenging_sites' => [
        'martijndebie.nl',
        'imunify360'
    ]
];

// Handle preflight OPTIONS request for CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header("Access-Control-Allow-Origin: {$config['cors']['allow_origin']}");
    header("Access-Control-Allow-Methods: {$config['cors']['allow_methods']}");
    header("Access-Control-Allow-Headers: {$config['cors']['allow_headers']}");
    header("Access-Control-Max-Age: {$config['cors']['max_age']}");
    exit(0);
}

// Set CORS headers for all responses
header("Access-Control-Allow-Origin: {$config['cors']['allow_origin']}");
header("Access-Control-Allow-Methods: {$config['cors']['allow_methods']}");

// Get request parameters
$url = isset($_GET['url']) ? $_GET['url'] : null;
// Add site-specific detection
$isChallengingSite = false;
$siteSpecificHandler = null;

// Check for known challenging sites that need special handling
if (strpos($url, 'martijndebie.nl') !== false) {
    $isChallengingSite = true;
    $siteSpecificHandler = 'handleMartijnDebieNl';
    
    if ($config['debug_mode']) {
        $debugInfo['site_handling'] = "Detected challenging site: martijndebie.nl - applying special handling";
    }
}

$format = isset($_GET['format']) ? strtolower($_GET['format']) : 'raw';
$callback = isset($_GET['callback']) ? $_GET['callback'] : 'callback';
$charset = isset($_GET['charset']) ? $_GET['charset'] : null;

// Validate URL
if (!$url) {
    outputError('URL parameter is missing', 400);
}

if (!filter_var($url, FILTER_VALIDATE_URL)) {
    outputError('Invalid URL provided', 400);
}

// Check if this is a challenging site that needs special handling
$isChallengingSite = false;
foreach ($config['challenging_sites'] as $site) {
    if (strpos($url, $site) !== false) {
        $isChallengingSite = true;
        
        // Increase timeout for challenging sites
        $config['timeout'] = 40;
        $config['max_redirects'] = 15;
        
        if ($config['debug_mode']) {
            $debugInfo['site_handling'] = "Detected challenging site: $site - applying special handling";
        }
        break;
    }
}

// Parse URL to check if it's trying to access localhost/internal networks
$parsedUrl = parse_url($url);
$host = isset($parsedUrl['host']) ? $parsedUrl['host'] : '';

// Block requests to localhost or internal networks unless explicitly allowed
if (!$config['allow_requests_to_localhost'] && 
    (preg_match('/^(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/', $host) || 
     $host === '[::1]')) {
    outputError('Requests to localhost or internal networks are not allowed', 403);
}

// Create cache directory if it doesn't exist and caching is enabled
if ($config['enable_cache'] && !is_dir($config['cache_dir'])) {
    mkdir($config['cache_dir'], 0755, true);
}

// Generate cache key based on URL
$cacheKey = md5($url);
$cacheFile = $config['cache_dir'] . $cacheKey;

// Debug info container
$debugInfo = [];

// Try to serve from cache if enabled and not a challenging site
// Skip cache for challenging sites to ensure fresh attempts
if ($config['enable_cache'] && !$isChallengingSite && file_exists($cacheFile)) {
    $cacheData = json_decode(file_get_contents($cacheFile), true);
    
    // Check if cache is still valid
    if (time() - $cacheData['timestamp'] < $config['cache_time']) {
        if ($config['debug_mode']) {
            $debugInfo['cache'] = 'Serving from cache (age: ' . (time() - $cacheData['timestamp']) . ' seconds)';
            $cacheData['debug_info'] = $debugInfo;
        }
        outputResponse($cacheData['status'], $cacheData['content'], $cacheData['content_type'], $format, $callback, $charset, $config['debug_mode'] ? $debugInfo : null);
    }
    
    if ($config['debug_mode']) {
        $debugInfo['cache'] = 'Cache expired (age: ' . (time() - $cacheData['timestamp']) . ' seconds)';
    }
}

// Fetch the URL content
// $response = fetchUrl($url, $config, $debugInfo);



// Check if this is martijndebie.nl and use special handler
if (strpos($url, 'martijndebie.nl') !== false) {
    $specificResponse = handleMartijnDebieNl($url, $config, $debugInfo);
    if ($specificResponse !== null) {
        $response = $specificResponse;
    } else {
        $response = fetchUrl($url, $config, $debugInfo);
    }
} else {
    $response = fetchUrl($url, $config, $debugInfo);
}


// $response = fetchWithMultipleStrategies($url, $config, $debugInfo);

// Check if we need to handle WAF challenges
if ($isChallengingSite || $response['status'] >= 400) {
    $response = handleWafChallenges($response, $url, $config, $debugInfo);
}

// Cache the response if enabled and successful
if ($config['enable_cache'] && $response['status'] >= 200 && $response['status'] < 400) {
    $cacheData = [
        'timestamp' => time(),
        'status' => $response['status'],
        'content' => $response['content'],
        'content_type' => $response['content_type']
    ];
    
    if ($config['debug_mode']) {
        $cacheData['debug_info'] = $debugInfo;
    }
    
    file_put_contents($cacheFile, json_encode($cacheData));
}

// Output the response
outputResponse($response['status'], $response['content'], $response['content_type'], $format, $callback, $charset, $config['debug_mode'] ? $debugInfo : null);



/**
 * Special handler for martijndebie.nl
 * 
 * This site-specific function mimics how Node.js http-proxy works by
 * establishing a session-like connection first
 */
function handleMartijnDebieNl($url, $config, &$debugInfo) {
    if ($config['debug_mode']) {
        $debugInfo['special_handler'] = "Using martijndebie.nl specific handler";
    }
    
    // Cookie file for session handling
    $cookieFile = tempnam(sys_get_temp_dir(), 'martijn_cookie');
    
    // Step 1: First visit the homepage to grab cookies and establish a session
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://www.martijndebie.nl/',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_COOKIEJAR => $cookieFile,
        CURLOPT_COOKIEFILE => $cookieFile,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.9',
            'Accept-Encoding: gzip, deflate, br',
            'Connection: keep-alive',
            'Cache-Control: max-age=0',
            'Upgrade-Insecure-Requests: 1',
            'Sec-Fetch-Dest: document',
            'Sec-Fetch-Mode: navigate',
            'Sec-Fetch-Site: none',
            'Sec-Fetch-User: ?1',
        ],
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_ENCODING => '',
    ]);
    
    $homepageResponse = curl_exec($ch);
    $homepageInfo = curl_getinfo($ch);
    curl_close($ch);
    
    if ($config['debug_mode']) {
        $debugInfo['homepage_status'] = $homepageInfo['http_code'];
    }
    
    // Wait briefly to mimic human behavior
    usleep(rand(800000, 1500000));
    
    // Step 2: Now make the actual request with the established session
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_COOKIEFILE => $cookieFile,
        CURLOPT_COOKIEJAR => $cookieFile,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        CURLOPT_REFERER => 'https://www.martijndebie.nl/',
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.9',
            'Accept-Encoding: gzip, deflate, br',
            'Connection: keep-alive',
            'Cache-Control: no-cache',
            'Pragma: no-cache',
            'Upgrade-Insecure-Requests: 1',
            'Sec-Fetch-Dest: document',
            'Sec-Fetch-Mode: navigate',
            'Sec-Fetch-Site: same-origin',
            'Sec-Fetch-User: ?1',
        ],
        CURLOPT_ENCODING => '',
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    
    // Clean up
    if (file_exists($cookieFile)) {
        unlink($cookieFile);
    }
    
    if ($response === false) {
        if ($config['debug_mode']) {
            $debugInfo['martijn_handler_error'] = $error;
        }
        return null; // Return null to indicate failure
    }
    
    $headerSize = $info['header_size'];
    $header = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);
    
    if ($config['debug_mode']) {
        $debugInfo['martijn_handler_status'] = $info['http_code'];
        $debugInfo['martijn_handler_content_type'] = $info['content_type'];
    }
    
    return [
        'status' => $info['http_code'],
        'content' => $body,
        'content_type' => $info['content_type']
    ];
}

/**
 * Function to create a more realistic browser fingerprint for challenging sites
 * 
 * @param array &$curlOptions Reference to cURL options array to modify
 * @param string $url The URL being requested
 * @param array $config Configuration options
 */
function configureForChallengingSite(&$curlOptions, $url, $config) {
    // Use a modern Chrome browser user agent
    $curlOptions[CURLOPT_USERAGENT] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36';
    
    // Create a more convincing set of headers that closely match real browser behavior
    $curlOptions[CURLOPT_HTTPHEADER] = [
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language: en-US,en;q=0.9',
        'Accept-Encoding: gzip, deflate, br',
        'Connection: keep-alive',
        'Upgrade-Insecure-Requests: 1',
        'Sec-Ch-Ua: "Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
        'Sec-Ch-Ua-Mobile: ?0',
        'Sec-Ch-Ua-Platform: "Windows"',
        'Sec-Fetch-Dest: document',
        'Sec-Fetch-Mode: navigate',
        'Sec-Fetch-Site: none',
        'Sec-Fetch-User: ?1',
        'Cache-Control: max-age=0',
        'DNT: 1'
    ];
    
    // Set up cookies and keep them between redirects
    $cookieFile = tempnam(sys_get_temp_dir(), 'curl_cookie');
    $curlOptions[CURLOPT_COOKIEJAR] = $cookieFile;
    $curlOptions[CURLOPT_COOKIEFILE] = $cookieFile;
    
    // Add a Google search referer - very important for sites with bot protection
    $hostname = parse_url($url, PHP_URL_HOST);
    $curlOptions[CURLOPT_REFERER] = 'https://www.google.com/search?q=' . urlencode($hostname);
    
    // Slow down the request to appear more human-like and avoid rate-limiting/bot detection
    usleep(rand(500000, 1500000)); // 0.5-1.5 second delay
    
    // Allow compressed responses
    $curlOptions[CURLOPT_ENCODING] = '';
    
    // Extend timeouts for potentially slow sites
    $curlOptions[CURLOPT_CONNECTTIMEOUT] = 20;
    $curlOptions[CURLOPT_TIMEOUT] = 40;
    
    // Enable TCP keepalive to maintain connection
    $curlOptions[CURLOPT_TCP_KEEPALIVE] = 1;
    
    // Follow redirects to handle any multi-step challenges
    $curlOptions[CURLOPT_FOLLOWLOCATION] = true;
    $curlOptions[CURLOPT_MAXREDIRS] = 10;
    
    // Set a higher connection timeout but lower transfer timeout
    // This mimics human behavior - we connect quickly but may read slowly
    $curlOptions[CURLOPT_CONNECTTIMEOUT] = 10;
    $curlOptions[CURLOPT_TIMEOUT] = 30;
}

/**
 * Add this function to implement a multi-strategy approach for challenging sites
 */
function fetchWithMultipleStrategies($url, $config, &$debugInfo) {
    // Strategy 1: Standard fetch with browser headers
    $response = fetchUrl($url, $config, $debugInfo);
    
    // Check if we succeeded (200-299 status codes)
    if ($response['status'] >= 200 && $response['status'] < 300) {
        if ($config['debug_mode']) {
            $debugInfo['strategy_used'] = "Standard fetch succeeded";
        }
        return $response;
    }
    
    // Strategy 2: Try with a delay and different user agent
    if ($config['debug_mode']) {
        $debugInfo['retry_strategy'] = "Attempting with delay and different user agent";
    }
    
    sleep(2); // Add delay to avoid rate limiting
    
    $ch = curl_init();
    $curlOptions = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => $config['max_redirects'],
        CURLOPT_TIMEOUT => $config['timeout'],
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ];
    
    // Add different headers to mimic Safari
    $curlOptions[CURLOPT_HTTPHEADER] = [
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.9',
        'Accept-Encoding: gzip, deflate, br',
        'Connection: keep-alive'
    ];
    
    curl_setopt_array($ch, $curlOptions);
    $response2 = curl_exec($ch);
    $error = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    
    if ($response2 !== false && $info['http_code'] >= 200 && $info['http_code'] < 300) {
        $headerSize = $info['header_size'];
        $header = substr($response2, 0, $headerSize);
        $body = substr($response2, $headerSize);
        
        if ($config['debug_mode']) {
            $debugInfo['strategy_used'] = "Safari strategy succeeded";
        }
        
        return [
            'status' => $info['http_code'],
            'content' => $body,
            'content_type' => $info['content_type']
        ];
    }
    
    // Strategy 3: Try with curl_exec directly and specific flags for this site
    if ($config['debug_mode']) {
        $debugInfo['retry_strategy'] = "Attempting direct cURL with session maintaining";
    }
    
    // Create cookie file for maintaining session
    $cookieFile = tempnam(sys_get_temp_dir(), 'curl_cookie');
    
    // First make a GET request to the homepage to establish cookies
    $ch = curl_init();
    $homepageUrl = parse_url($url, PHP_URL_SCHEME) . '://' . parse_url($url, PHP_URL_HOST) . '/';
    curl_setopt_array($ch, [
        CURLOPT_URL => $homepageUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_COOKIEJAR => $cookieFile,
        CURLOPT_COOKIEFILE => $cookieFile,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    curl_exec($ch);
    curl_close($ch);
    
    // Wait briefly
    usleep(800000);
    
    // Now try the actual URL with the established cookies
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_COOKIEFILE => $cookieFile,
        CURLOPT_COOKIEJAR => $cookieFile,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        CURLOPT_REFERER => $homepageUrl,
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.9',
            'Accept-Encoding: gzip, deflate, br',
            'Cache-Control: max-age=0',
            'Upgrade-Insecure-Requests: 1',
            'Sec-Fetch-Dest: document',
            'Sec-Fetch-Mode: navigate',
            'Sec-Fetch-Site: same-origin',
            'Sec-Fetch-User: ?1',
        ],
        CURLOPT_ENCODING => '',
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    
    $response3 = curl_exec($ch);
    $error = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    
    if ($response3 !== false) {
        $headerSize = $info['header_size'];
        $header = substr($response3, 0, $headerSize);
        $body = substr($response3, $headerSize);
        
        if ($config['debug_mode']) {
            $debugInfo['strategy_used'] = "Session-based strategy";
            $debugInfo['final_http_code'] = $info['http_code'];
        }
        
        return [
            'status' => $info['http_code'],
            'content' => $body,
            'content_type' => $info['content_type']
        ];
    }
    
    // If all strategies failed, return the original response
    if ($config['debug_mode']) {
        $debugInfo['strategy_used'] = "All strategies failed, returning original response";
    }
    
    return $response;
}


/**
 * Function to detect and handle WAF challenges
 * 
 * @param array $response The original response
 * @param string $url The URL being requested
 * @param array $config Configuration options
 * @param array &$debugInfo Reference to debug info array
 * @return array The potentially updated response
 */
function handleWafChallenges($response, $url, $config, &$debugInfo) {
    // Check for common WAF response patterns
    $needsBypass = false;
    
    // Check for error status codes that might indicate WAF blocking
    if ($response['status'] == 403 || $response['status'] == 429 || $response['status'] == 503 || $response['status'] == 415) {
        $needsBypass = true;
    }
    
    // Check for WAF signatures in content
    if (
        strpos($response['content'], 'security check') !== false ||
        strpos($response['content'], 'blocked') !== false ||
        strpos($response['content'], 'captcha') !== false ||
        strpos($response['content'], 'imunify') !== false ||
        strpos($response['content'], 'cloudflare') !== false ||
        strpos($response['content'], 'firewall') !== false
    ) {
        $needsBypass = true;
    }
    
    if (!$needsBypass) {
        return $response; // No bypass needed
    }
    
    if ($config['debug_mode']) {
        $debugInfo['waf_bypass'] = "WAF detected (status code: {$response['status']}), attempting bypass";
    }
    
    // Wait a bit - WAFs often check for timing patterns
    sleep(2);
    
    // Create a new cURL handle with enhanced browser simulation
    $ch = curl_init();
    
    $curlOptions = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => $config['max_redirects'],
        CURLOPT_TIMEOUT => $config['timeout'] * 2, // Double timeout for challenge pages
        CURLOPT_HEADER => true,
        CURLOPT_SSL_VERIFYPEER => $config['verify_ssl'],
        CURLOPT_SSL_VERIFYHOST => $config['verify_ssl'] ? 2 : 0,
        CURLOPT_ENCODING => '',
        CURLOPT_VERBOSE => $config['debug_mode']
    ];
    
    // Add realistic browser behavior
    configureForChallengingSite($curlOptions, $url, $config);
    
    // If in debug mode, capture verbose output
    if ($config['debug_mode']) {
        $verbose = fopen('php://temp', 'w+');
        $curlOptions[CURLOPT_STDERR] = $verbose;
    }
    
    curl_setopt_array($ch, $curlOptions);
    
    $bypassResponse = curl_exec($ch);
    $error = curl_error($ch);
    $info = curl_getinfo($ch);
    
    // Gather debug info
    if ($config['debug_mode']) {
        rewind($verbose);
        $verboseLog = stream_get_contents($verbose);
        fclose($verbose);
        
        $debugInfo['bypass_execution_time'] = round(microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'], 3) . ' seconds';
        $debugInfo['bypass_curl_info'] = $info;
        $debugInfo['bypass_curl_error'] = $error ?: 'None';
        $debugInfo['bypass_verbose_log'] = $verboseLog;
    }
    
    curl_close($ch);
    
    // Handle cURL errors
    if ($bypassResponse === false) {
        if ($config['debug_mode']) {
            $debugInfo['bypass_result'] = 'Failed: ' . $error;
        }
        return $response; // Return original response if bypass fails
    }
    
    // Split header and body
    $headerSize = $info['header_size'];
    $header = substr($bypassResponse, 0, $headerSize);
    $body = substr($bypassResponse, $headerSize);
    
    // Success - use the bypass response
    if ($config['debug_mode']) {
        $debugInfo['bypass_result'] = 'Success: Got status code ' . $info['http_code'];
        $debugInfo['bypass_headers'] = $header;
    }
    
    return [
        'status' => $info['http_code'],
        'content' => $body,
        'content_type' => $info['content_type']
    ];
}

/**
 * Fetch content from a URL using cURL
 * 
 * @param string $url The URL to fetch
 * @param array $config Configuration options
 * @param array &$debugInfo Reference to debug info array
 * @return array The response data including status, content, and content-type
 */
function fetchUrl($url, $config, &$debugInfo = []) {
    $ch = curl_init();
    
    // Determine if this is a challenging site
    $isChallengingSite = false;
    foreach ($config['challenging_sites'] as $site) {
        if (strpos($url, $site) !== false) {
            $isChallengingSite = true;
            break;
        }
    }
    
    // Basic headers for normal sites
    $headers = [
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.5',
        'Connection: keep-alive',
        'Upgrade-Insecure-Requests: 1',
        'Cache-Control: max-age=0'
    ];
    
    $startTime = microtime(true);
    
    $curlOptions = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => $config['max_redirects'],
        CURLOPT_TIMEOUT => $config['timeout'],
        CURLOPT_USERAGENT => $config['user_agent'],
        CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => $config['verify_ssl'],
        CURLOPT_SSL_VERIFYHOST => $config['verify_ssl'] ? 2 : 0,
        CURLINFO_HEADER_OUT => true,
        CURLOPT_VERBOSE => $config['debug_mode'],
        CURLOPT_ENCODING => '' // Use empty string to enable automatic decompression
    ];
    
    // Apply special configuration for challenging sites
    if ($isChallengingSite) {
        configureForChallengingSite($curlOptions, $url, $config);
    }
    
    // If in debug mode, capture verbose output
    if ($config['debug_mode']) {
        $verbose = fopen('php://temp', 'w+');
        $curlOptions[CURLOPT_STDERR] = $verbose;
    }
    
    curl_setopt_array($ch, $curlOptions);
    
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $info = curl_getinfo($ch);
    
    $endTime = microtime(true);
    $executionTime = round($endTime - $startTime, 3);
    
    // Gather debug info
    if ($config['debug_mode']) {
        rewind($verbose);
        $verboseLog = stream_get_contents($verbose);
        fclose($verbose);
        
        $debugInfo['execution_time'] = $executionTime . ' seconds';
        $debugInfo['curl_info'] = $info;
        $debugInfo['curl_error'] = $error ?: 'None';
        $debugInfo['verbose_log'] = $verboseLog;
        $debugInfo['request_headers'] = $info['request_header'] ?? 'Not available';
        $debugInfo['challenging_site'] = $isChallengingSite ? 'Yes' : 'No';
        $debugInfo['config'] = [
            'timeout' => $config['timeout'],
            'max_redirects' => $config['max_redirects'],
            'user_agent' => $curlOptions[CURLOPT_USERAGENT],
            'verify_ssl' => $config['verify_ssl']
        ];
    }
    
    curl_close($ch);

    // Handle cURL errors
    if ($response === false) {
        // If we get an encoding error, try again without any encoding
        if (strpos($error, 'content encoding') !== false) {
            if ($config['debug_mode']) {
                $debugInfo['retry'] = 'Retrying without content encoding handling';
            }
            
            return retryWithoutEncoding($url, $config, $debugInfo);
        }
        
        if ($config['debug_mode']) {
            outputErrorWithDebug('cURL error: ' . $error, 500, $debugInfo);
        } else {
            outputError('cURL error: ' . $error, 500);
        }
    }
    
    // Split header and body
    $headerSize = $info['header_size'];
    $header = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);
    
    // Parse content type
    $contentType = $info['content_type'];
    
    // Add headers to debug info
    if ($config['debug_mode']) {
        $debugInfo['response_headers'] = $header;
    }
    
    return [
        'status' => $info['http_code'],
        'content' => $body,
        'content_type' => $contentType
    ];
}

/**
 * Retry the request without any encoding handling
 */
function retryWithoutEncoding($url, $config, &$debugInfo = []) {
    $ch = curl_init();
    
    // Modified headers without Accept-Encoding
    $headers = [
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.5',
        'Connection: keep-alive',
        'Upgrade-Insecure-Requests: 1',
        'Cache-Control: max-age=0'
    ];
    
    $curlOptions = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => $config['max_redirects'],
        CURLOPT_TIMEOUT => $config['timeout'],
        CURLOPT_USERAGENT => $config['user_agent'],
        CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => $config['verify_ssl'],
        CURLOPT_SSL_VERIFYHOST => $config['verify_ssl'] ? 2 : 0,
        // Don't set any encoding-related options
    ];
    
    curl_setopt_array($ch, $curlOptions);
    
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $info = curl_getinfo($ch);
    
    if ($config['debug_mode']) {
        $debugInfo['retry_curl_info'] = $info;
        $debugInfo['retry_curl_error'] = $error ?: 'None';
    }
    
    curl_close($ch);
    
    // Handle cURL errors on the retry
    if ($response === false) {
        if ($config['debug_mode']) {
            outputErrorWithDebug('Retry failed: ' . $error, 500, $debugInfo);
        } else {
            outputError('Retry failed: ' . $error, 500);
        }
    }
    
    // Split header and body
    $headerSize = $info['header_size'];
    $header = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);
    
    // Parse content type
    $contentType = $info['content_type'];
    
    // Add headers to debug info
    if ($config['debug_mode']) {
        $debugInfo['retry_response_headers'] = $header;
    }
    
    return [
        'status' => $info['http_code'],
        'content' => $body,
        'content_type' => $contentType
    ];
}

/**
 * Output the response in the requested format
 * 
 * @param int $status HTTP status code
 * @param string $content The content to output
 * @param string $contentType The content type of the original response
 * @param string $format The desired output format (raw, json, jsonp)
 * @param string $callback The JSONP callback function name
 * @param string|null $charset Optional character set for the response
 * @param array|null $debugInfo Optional debug information
 */
function outputResponse($status, $content, $contentType, $format, $callback, $charset = null, $debugInfo = null) {
    $originalCharset = null;
    
    // Extract charset from content-type if present
    if (preg_match('/charset=([^;]+)/i', $contentType, $matches)) {
        $originalCharset = $matches[1];
    }
    
    // Use requested charset or original charset
    $outputCharset = $charset ?: $originalCharset ?: 'UTF-8';
    
    // Convert content to requested charset if needed
    if ($originalCharset && $outputCharset && strtoupper($originalCharset) !== strtoupper($outputCharset)) {
        $content = mb_convert_encoding($content, $outputCharset, $originalCharset);
    }
    
    switch ($format) {
        case 'json':
            header('Content-Type: application/json; charset=' . $outputCharset);
            $response = [
                'status' => [
                    'http_code' => $status,
                    'content_type' => $contentType
                ],
                'contents' => $content
            ];
            
            // Add debug info if available
            if ($debugInfo) {
                $response['debug'] = $debugInfo;
            }
            
            echo json_encode($response);
            break;
            
        case 'jsonp':
            header('Content-Type: application/javascript; charset=' . $outputCharset);
            // Sanitize callback function name to prevent XSS
            $callback = preg_replace('/[^a-zA-Z0-9_]/', '', $callback);
            
            $response = [
                'status' => [
                    'http_code' => $status,
                    'content_type' => $contentType
                ],
                'contents' => $content
            ];
            
            // Add debug info if available
            if ($debugInfo) {
                $response['debug'] = $debugInfo;
            }
            
            echo $callback . '(' . json_encode($response) . ');';
            break;
            
        case 'raw':
        default:
            // For raw format with debug info, we need to switch to JSON
            if ($debugInfo) {
                header('Content-Type: application/json; charset=' . $outputCharset);
                echo json_encode([
                    'status' => [
                        'http_code' => $status,
                        'content_type' => $contentType
                    ],
                    'contents' => $content,
                    'debug' => $debugInfo
                ]);
            } else {
                header('Content-Type: ' . $contentType);
                echo $content;
            }
            break;
    }
    
    exit;
}

/**
 * Output an error message in the appropriate format and exit
 * 
 * @param string $message Error message
 * @param int $status HTTP status code
 */
function outputError($message, $status) {
    http_response_code($status);
    
    // Check if format parameter exists
    $format = isset($_GET['format']) ? strtolower($_GET['format']) : 'raw';
    $callback = isset($_GET['callback']) ? $_GET['callback'] : 'callback';
    
    switch ($format) {
        case 'json':
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode([
                'status' => [
                    'http_code' => $status,
                    'message' => $message
                ],
                'contents' => null
            ]);
            break;
            
        case 'jsonp':
            header('Content-Type: application/javascript; charset=UTF-8');
            $callback = preg_replace('/[^a-zA-Z0-9_]/', '', $callback);
            echo $callback . '(' . json_encode([
                'status' => [
                    'http_code' => $status,
                    'message' => $message
                ],
                'contents' => null
            ]) . ');';
            break;
            
        case 'raw':
        default:
            header('Content-Type: text/plain; charset=UTF-8');
            echo $message;
            break;
    }
    
    exit;
}

/**
 * Output an error message with debug information
 * 
 * @param string $message Error message
 * @param int $status HTTP status code
 * @param array $debugInfo Debug information
 */
function outputErrorWithDebug($message, $status, $debugInfo) {
    http_response_code($status);
    
    // Check if format parameter exists
    $format = isset($_GET['format']) ? strtolower($_GET['format']) : 'raw';
    $callback = isset($_GET['callback']) ? $_GET['callback'] : 'callback';
    
    $response = [
        'status' => [
            'http_code' => $status,
            'message' => $message
        ],
        'contents' => null,
        'debug' => $debugInfo
    ];
    
    switch ($format) {
        case 'json':
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode($response);
            break;
            
        case 'jsonp':
            header('Content-Type: application/javascript; charset=UTF-8');
            $callback = preg_replace('/[^a-zA-Z0-9_]/', '', $callback);
            echo $callback . '(' . json_encode($response) . ');';
            break;
            
        case 'raw':
        default:
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode($response);
            break;
    }
    
    exit;
}
?>