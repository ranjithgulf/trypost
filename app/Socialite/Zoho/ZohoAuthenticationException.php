<?php

declare(strict_types=1);

namespace App\Socialite\Zoho;

use RuntimeException;

/**
 * A Zoho Directory sign-in that must not proceed. `reason` is a short,
 * non-sensitive code that is safe to log; the token itself never is.
 */
final class ZohoAuthenticationException extends RuntimeException
{
    public function __construct(public readonly string $reason, ?\Throwable $previous = null)
    {
        parent::__construct("Zoho sign-in rejected: {$reason}", 0, $previous);
    }
}
