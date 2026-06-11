<?php
declare(strict_types=1);

function sendUpdaterEmail(string $to, string $subject, string $body, array $options = []): array
{
    $to = trim($to);
    if ($to === '') {
        return ['sent' => false, 'reason' => 'missing_email'];
    }

    loadUpdaterMailerConfig();

    $fromEmail = updaterEmailOption($options, 'from_email', 'UPDATE_FROM_EMAIL', 'wordpress-updates@hfe.co.uk');
    $fromName = updaterEmailOption($options, 'from_name', 'UPDATE_FROM_NAME', 'WordPress Update Policy');

    if (getConfiguredValue('MANDRILL_KEY') !== '') {
        return sendUpdaterEmailWithMandrill($to, $subject, $body, $fromEmail, $fromName);
    }

    return sendUpdaterEmailWithPhpMail($to, $subject, $body, $fromEmail, $fromName);
}

function loadUpdaterMailerConfig(): void
{
    static $loaded = false;
    if ($loaded) {
        return;
    }

    $settingsPath = dirname(__FILE__) . '/../public/config/settings.php';
    if (is_file($settingsPath)) {
        include_once $settingsPath;
    }

    $loaded = true;
}

function updaterEmailOption(array $options, string $key, string $constant, string $default): string
{
    if (!empty($options[$key])) {
        return (string) $options[$key];
    }

    $configured = getConfiguredValue($constant);
    return $configured !== '' ? $configured : $default;
}

function sendUpdaterEmailWithMandrill(string $to, string $subject, string $body, string $fromEmail, string $fromName): array
{
    $mandrillPath = __DIR__ . '/Mandrill.php';
    if (!is_file($mandrillPath)) {
        return ['sent' => false, 'transport' => 'mandrill', 'reason' => 'missing_mandrill_class'];
    }

    require_once $mandrillPath;

    try {
        $mandrill = new Mandrill(getConfiguredValue('MANDRILL_KEY'));
        $message = [
            'from_email' => $fromEmail,
            'from_name' => $fromName,
            'to' => [
                [
                    'email' => $to,
                    'type' => 'to',
                ],
            ],
            'headers' => [
                'Reply-To' => $fromEmail,
            ],
            'merge' => true,
            'merge_language' => 'handlebars',
            'global_merge_vars' => [
                [
                    'name' => 'content',
                    'content' => nl2br(htmlspecialchars($body, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')),
                ],
            ],
            'metadata' => [
                'source' => 'wordpress-update-policy',
            ],
        ];

        if ($subject !== '') {
            $message['subject'] = $subject;
        }

        $message['text'] = $body;

        $result = $mandrill->messages->sendTemplate('hfe-default', [], $message, false, 'Main Pool', null);
        $first = is_array($result) && isset($result[0]) && is_array($result[0]) ? $result[0] : [];
        $status = (string) ($first['status'] ?? '');
        $rejectReason = (string) ($first['reject_reason'] ?? '');

        return [
            'sent' => in_array($status, ['sent', 'queued', 'scheduled'], true),
            'transport' => 'mandrill',
            'to' => $to,
            'mandrill_id' => (string) ($first['_id'] ?? ''),
            'status' => $status,
            'reason' => $rejectReason !== '' ? $rejectReason : null,
        ];
    } catch (Exception $exception) {
        return [
            'sent' => false,
            'transport' => 'mandrill',
            'to' => $to,
            'reason' => $exception->getMessage(),
        ];
    }
}

function sendUpdaterEmailWithPhpMail(string $to, string $subject, string $body, string $fromEmail, string $fromName): array
{
    $headers = 'From: ' . $fromName . ' <' . $fromEmail . '>';
    $sent = mail($to, $subject, $body, $headers);

    return [
        'sent' => $sent,
        'transport' => 'php_mail',
        'to' => $to,
        'reason' => $sent ? null : 'mail_failed',
    ];
}
