<?php
/**
 * Gate 门禁 - 放到目标站根目录
 * 
 * 使用方式（二选一）：
 * 
 * 方式1：php.ini 或 Docker 里设置 auto_prepend_file（推荐，不用改代码）
 *   php_value auto_prepend_file /var/www/html/gate_check.php
 * 
 * 方式2：在 index.php 最顶部加一行
 *   require_once __DIR__ . '/gate_check.php';
 */

// ===== 配置 =====
// 必须和 go_page 的 GATE_SECRET 环境变量一致！
$GATE_SECRET = getenv('GATE_SECRET') ?: 'change-me-to-a-random-string';
$GATE_TTL    = (int)(getenv('GATE_TTL') ?: 300);      // gate token 有效期（秒）
$COOKIE_TTL  = (int)(getenv('COOKIE_TTL') ?: 86400);   // cookie 有效期（秒）
$COOKIE_NAME = '_gate_pass';

// ===== 不需要验证的路径（静态资源等，按需添加）=====
$SKIP_PATHS = [
    // 探测资源路径不能拦，否则 go_page 探测不到
    '/static/',
    '/favicon.ico',
    '/robots.txt',
];

// ===== 逻辑开始 =====

// 检查是否是不需要验证的路径
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$requestPath = parse_url($requestUri, PHP_URL_PATH) ?: '/';
foreach ($SKIP_PATHS as $skip) {
    if (strpos($requestPath, $skip) === 0) {
        return; // 放行，继续执行原来的代码
    }
}

/**
 * 验证 gate token（go_page 生成的）
 */
function verify_gate_token($token, $secret, $ttl) {
    try {
        // 补齐 base64 padding
        $padding = 4 - (strlen($token) % 4);
        if ($padding !== 4) {
            $token .= str_repeat('=', $padding);
        }
        $raw = base64_decode(strtr($token, '-_', '+/'));
        if ($raw === false) return false;
        
        $parts = explode(':', $raw, 2);
        if (count($parts) !== 2) return false;
        
        $ts = (int)$parts[0];
        $sig = $parts[1];
        
        // 检查过期
        if (abs(time() - $ts) > $ttl) return false;
        
        // 检查签名
        $expected = substr(hash_hmac('sha256', (string)$ts, $secret), 0, 16);
        return hash_equals($expected, $sig);
    } catch (\Exception $e) {
        return false;
    }
}

/**
 * 生成 cookie 值（带签名）
 */
function generate_cookie_value($secret) {
    $ts = (string)time();
    $sig = substr(hash_hmac('sha256', 'cookie:' . $ts, $secret), 0, 16);
    $raw = $ts . ':' . $sig;
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

/**
 * 验证 cookie 值
 */
function verify_cookie_value($cookie, $secret, $ttl) {
    try {
        $padding = 4 - (strlen($cookie) % 4);
        if ($padding !== 4) {
            $cookie .= str_repeat('=', $padding);
        }
        $raw = base64_decode(strtr($cookie, '-_', '+/'));
        if ($raw === false) return false;
        
        $parts = explode(':', $raw, 2);
        if (count($parts) !== 2) return false;
        
        $ts = (int)$parts[0];
        $sig = $parts[1];
        
        if (abs(time() - $ts) > $ttl) return false;
        
        $expected = substr(hash_hmac('sha256', 'cookie:' . (string)$ts, $secret), 0, 16);
        return hash_equals($expected, $sig);
    } catch (\Exception $e) {
        return false;
    }
}

// 1. 检查 URL 参数 _gate
$gateToken = $_GET['_gate'] ?? '';
if ($gateToken && verify_gate_token($gateToken, $GATE_SECRET, $GATE_TTL)) {
    // 验证通过 → 种 Cookie → 302 到干净 URL
    $cookieVal = generate_cookie_value($GATE_SECRET);
    setcookie($COOKIE_NAME, $cookieVal, [
        'expires'  => time() + $COOKIE_TTL,
        'path'     => '/',
        'httponly'  => true,
        'samesite' => 'Lax',
    ]);
    
    // 去掉 _gate 参数
    $params = $_GET;
    unset($params['_gate']);
    $cleanUrl = $requestPath;
    if (!empty($params)) {
        $cleanUrl .= '?' . http_build_query($params);
    }
    
    header('Location: ' . $cleanUrl, true, 302);
    header('Cache-Control: no-cache, no-store, must-revalidate');
    exit;
}

// 2. 检查 Cookie
$cookieVal = $_COOKIE[$COOKIE_NAME] ?? '';
if ($cookieVal && verify_cookie_value($cookieVal, $GATE_SECRET, $COOKIE_TTL)) {
    return; // 放行
}

// 3. 都没有 → 505 拒绝
http_response_code(505);
echo '505';
exit;
