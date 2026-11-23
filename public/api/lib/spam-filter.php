<?php

declare(strict_types=1);

/**
 * Form spam detection: keyword phrases/tokens in contact messages and disposable email domains.
 * ASCII word boundaries (\b) are used for tokens; sufficient for English spam on this site.
 */

function submissionLooksLikeSpam(array $post, array $config): ?string
{
    $email = trim((string) ($post['email'] ?? ''));
    if ($email !== '') {
        $domainReason = emailUsesDisposableDomain($email, $config);
        if ($domainReason !== null) {
            return $domainReason;
        }
    }

    $formType = trim((string) ($post['form_type'] ?? ''));
    if ($formType !== 'contact') {
        return null;
    }

    $message = trim((string) ($post['message'] ?? ''));

    return messageMatchesSpamKeywords($message, $config);
}

function messageMatchesSpamKeywords(string $message, array $config): ?string
{
    if ($message === '') {
        return null;
    }

    $normalized = normalizeSpamText($message);

    foreach (loadSpamPhrases($config) as $phrase) {
        if ($phrase === '') {
            continue;
        }
        if (str_contains($normalized, $phrase)) {
            return 'keyword:phrase:' . $phrase;
        }
    }

    $tokenText = deobfuscateForTokenScan($normalized);

    foreach (loadSpamTokens($config) as $token) {
        if ($token === '') {
            continue;
        }
        $pattern = '/\b' . preg_quote($token, '/') . '\b/i';
        if (preg_match($pattern, $tokenText) === 1) {
            return 'keyword:token:' . $token;
        }
    }

    return null;
}

function emailUsesDisposableDomain(string $email, array $config): ?string
{
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return null;
    }

    $at = strrpos($email, '@');
    if ($at === false) {
        return null;
    }

    $domain = strtolower(substr($email, $at + 1));
    if ($domain === '') {
        return null;
    }

    if (isset(loadTrustedEmailDomains($config)[$domain])) {
        return null;
    }

    $blocklist = loadDisposableDomains($config);
    if (isset($blocklist[$domain])) {
        return 'disposable_domain:' . $domain;
    }

    return null;
}

function spamSubmitterName(array $post): string
{
    $name = trim((string) ($post['name'] ?? ''));
    if ($name !== '') {
        return $name;
    }

    $first = trim((string) ($post['first'] ?? $post['firstName'] ?? $post['first_name'] ?? ''));
    $last = trim((string) ($post['last'] ?? $post['lastName'] ?? $post['last_name'] ?? ''));

    return trim("$first $last");
}

function logSpamSubmission(string $reason, array $post, string $remoteIp, array $config): void
{
    $formType = trim((string) ($post['form_type'] ?? ''));
    $email = trim((string) ($post['email'] ?? ''));
    $message = trim((string) ($post['message'] ?? ''));
    if (strlen($message) > 200) {
        $message = substr($message, 0, 200) . '…';
    }

    $summary = sprintf(
        '[form-spam] reason=%s form=%s ip=%s email=%s message=%s',
        $reason,
        $formType,
        $remoteIp,
        $email,
        $message,
    );
    error_log($summary);

    $logPath = trim((string) ($config['spam_log_path'] ?? ''));
    if ($logPath === '') {
        return;
    }

    $entry = json_encode([
        'ts' => (new DateTimeImmutable('now'))->format(DateTimeInterface::ATOM),
        'reason' => $reason,
        'form_type' => $formType,
        'ip' => $remoteIp,
        'email' => $email,
        'name' => spamSubmitterName($post),
        'message_preview' => $message,
    ], JSON_UNESCAPED_UNICODE);

    if ($entry === false) {
        return;
    }

    @file_put_contents($logPath, $entry . "\n", FILE_APPEND | LOCK_EX);
}

function normalizeSpamText(string $text): string
{
    $text = strtolower($text);
    $text = preg_replace('/\s+/u', ' ', $text) ?? $text;

    return trim($text);
}

/**
 * Light de-obfuscation for token matching (e.g. v1agra, v.i.a.g.r.a).
 */
function deobfuscateForTokenScan(string $normalized): string
{
    $text = $normalized;
    $text = str_replace(['0', '1', '3', '4', '5', '@'], ['o', 'i', 'e', 'a', 's', 'a'], $text);
    $text = preg_replace('/[^a-z0-9\s]+/u', '', $text) ?? $text;
    $text = preg_replace('/\s+/u', ' ', $text) ?? $text;

    return trim($text);
}

/** @return list<string> */
function loadSpamPhrases(array $config): array
{
    static $cached = null;
    if ($cached !== null) {
        return applyPhraseConfig($cached, $config);
    }

    $cached = loadKeywordLines(dirname(__DIR__) . '/data/spam-keywords-phrases.txt');

    return applyPhraseConfig($cached, $config);
}

/** @return list<string> */
function loadSpamTokens(array $config): array
{
    static $cached = null;
    if ($cached !== null) {
        return applyTokenConfig($cached, $config);
    }

    $cached = loadKeywordLines(dirname(__DIR__) . '/data/spam-keywords-tokens.txt');

    return applyTokenConfig($cached, $config);
}

/** @return array<string, true> */
function loadTrustedEmailDomains(array $config): array
{
    static $cached = null;
    if ($cached === null) {
        $cached = [];
        $path = dirname(__DIR__) . '/data/trusted-email-domains.txt';
        if (is_readable($path)) {
            $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '' || str_starts_with($line, '#')) {
                        continue;
                    }
                    $cached[strtolower($line)] = true;
                }
            }
        }
    }

    $trusted = $cached;
    foreach ($config['trusted_email_domains_extra'] ?? [] as $domain) {
        $domain = strtolower(trim((string) $domain));
        if ($domain !== '') {
            $trusted[$domain] = true;
        }
    }

    return $trusted;
}

/** @return array<string, true> */
function loadDisposableDomains(array $config): array
{
    static $cached = null;
    if ($cached === null) {
        $cached = [];
        $path = dirname(__DIR__) . '/data/disposable-email-domains.txt';
        if (is_readable($path)) {
            $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '' || str_starts_with($line, '#')) {
                        continue;
                    }
                    $cached[strtolower($line)] = true;
                }
            }
        }
    }

    $trusted = loadTrustedEmailDomains($config);
    $domains = $cached;
    foreach (array_keys($trusted) as $domain) {
        unset($domains[$domain]);
    }

    foreach ($config['disposable_domains_extra'] ?? [] as $domain) {
        $domain = strtolower(trim((string) $domain));
        if ($domain !== '' && !isset($trusted[$domain])) {
            $domains[$domain] = true;
        }
    }

    return $domains;
}

/** @return list<string> */
function loadKeywordLines(string $path): array
{
    $keywords = [];
    if (!is_readable($path)) {
        return $keywords;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return $keywords;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $keywords[] = normalizeSpamText($line);
    }

    return $keywords;
}

/** @param list<string> $base */
function applyPhraseConfig(array $base, array $config): array
{
    $disable = [];
    foreach ($config['spam_keywords_disable'] ?? [] as $item) {
        $disable[normalizeSpamText((string) $item)] = true;
    }

    $phrases = [];
    foreach ($base as $phrase) {
        if (!isset($disable[$phrase])) {
            $phrases[] = $phrase;
        }
    }

    foreach ($config['spam_keywords_extra'] ?? [] as $item) {
        $phrase = normalizeSpamText((string) $item);
        if ($phrase !== '' && !isset($disable[$phrase])) {
            $phrases[] = $phrase;
        }
    }

    return $phrases;
}

/** @param list<string> $base */
function applyTokenConfig(array $base, array $config): array
{
    $disable = [];
    foreach ($config['spam_keywords_disable'] ?? [] as $item) {
        $disable[normalizeSpamText((string) $item)] = true;
    }

    $tokens = [];
    foreach ($base as $token) {
        if (!isset($disable[$token])) {
            $tokens[] = $token;
        }
    }

    foreach ($config['spam_keywords_extra'] ?? [] as $item) {
        $token = normalizeSpamText((string) $item);
        if ($token !== '' && !isset($disable[$token]) && !str_contains($token, ' ')) {
            $tokens[] = $token;
        }
    }

    return $tokens;
}