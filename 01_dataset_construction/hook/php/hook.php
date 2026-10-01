<?php

declare(strict_types=1);

if (!defined('FURINA_PHP_HOOK_LOADED')) {
    define('FURINA_PHP_HOOK_LOADED', true);

    final class FurinaPhpRequestContext
    {
        private static int $counter = 0;

        public static function newRequestId(): string
        {
            self::$counter++;
            return sprintf(
                '%s-%d-%d',
                (string) getmypid(),
                self::$counter,
                (int) floor(microtime(true) * 1000000)
            );
        }
    }

    function furina_php_open_marker_stream()
    {
        static $markerStream = null;

        if ($markerStream === null) {
            $markerStream = @fopen('/dev/null', 'wb');
        }

        return $markerStream;
    }

    function furina_php_detect_handler_key(): string
    {
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
        $method = (string) ($_SERVER['REQUEST_METHOD'] ?? '');
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '');

        $uriPath = (string) parse_url($uri, PHP_URL_PATH);
        $parts = array_filter([$script, $method, $uriPath], static fn ($item): bool => $item !== '');
        return implode('|', $parts);
    }

    function furina_php_emit_marker(string $action, string $requestId, string $handlerKey = ''): void
    {
        $stream = furina_php_open_marker_stream();
        if ($stream === false || $stream === null) {
            return;
        }

        $payload = sprintf('furina-php-ins %s %s', $action, $requestId);
        if ($handlerKey !== '') {
            $payload .= ' ' . $handlerKey;
        }

        @fwrite($stream, $payload);
        @fflush($stream);
    }

    $furinaPhpRequestId = FurinaPhpRequestContext::newRequestId();
    $furinaPhpHandlerKey = furina_php_detect_handler_key();

    furina_php_emit_marker('hook_loaded', $furinaPhpRequestId, $furinaPhpHandlerKey);

    try {
        furina_php_emit_marker('request_begin', $furinaPhpRequestId, $furinaPhpHandlerKey);
    } catch (\Throwable $e) {
        furina_php_emit_marker('emit_error', $furinaPhpRequestId, 'begin');
    }

    register_shutdown_function(
        static function () use ($furinaPhpRequestId, $furinaPhpHandlerKey): void {
            try {
                furina_php_emit_marker('request_end', $furinaPhpRequestId, $furinaPhpHandlerKey);
            } catch (\Throwable $e) {
                furina_php_emit_marker('emit_error', $furinaPhpRequestId, 'end');
            }
        }
    );
}