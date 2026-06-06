<?php

declare(strict_types=1);

namespace Switon\Crypto;

function openssl_cipher_iv_length(string $cipher_algo): int|false
{
    if ($cipher_algo === 'NOT-A-CIPHER') {
        return false;
    }

    return \openssl_cipher_iv_length($cipher_algo);
}

function openssl_cipher_key_length(string $cipher_algo): int|false
{
    if ($cipher_algo === 'NOT-A-CIPHER') {
        return false;
    }

    return \openssl_cipher_key_length($cipher_algo);
}
