<?php

declare(strict_types=1);

/**
 * Сервис для работы с JWT токенами
 *
 * Class JwtTokenService
 * @package App\Service
 */
class JwtTokenService
{
    private string $jwtSecret;

    public function __construct()
    {
        $this->jwtSecret = getenv('JWT_SECRET');
    }

    /**
     * Генерация JWT токена
     * Реализовано по статье https://dev.to/robdwaller/how-to-create-a-json-web-token-using-php-3gml
     *
     * @param array $payload
     * @param int|null $lifeTime Время жизни токена в секундах
     *
     * @return string
     */
    public function generate(array $payload, ?int $lifeTime = null): string
    {
        $header = json_encode([
            "typ" => "JWT",
            "alg" => "HS256"
        ]);

        // Устанавливаем время жизни токена (по умолчанию 30 дней)
        $payload['exp'] = time() + ($lifeTime ?? 3600 * 24 * 30);

        $payload = json_encode($payload);

        $base64UrlHeader = $this->base64UrlEncode($header);
        $base64UrlPayload = $this->base64UrlEncode($payload);

        $signature = hash_hmac(
            'sha256',
            $base64UrlHeader . '.' . $base64UrlPayload,
            $this->jwtSecret,
            true
        );

        $base64UrlSignature = $this->base64UrlEncode($signature);

        return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
    }

    /**
     * Валидация токена
     *
     * @param string $jwt
     *
     * @return bool
     */
    public function validate(string $jwt): bool
    {
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];

        // Проверяем токен на истечение времени жизни
        $expiration = json_decode($payload)->exp;
        $isTokenExpired = ($expiration - time()) < 0;

        if ($isTokenExpired) {
            return false;
        }

        $base64UrlHeader = $this->base64UrlEncode($header);
        $base64UrlPayload = $this->base64UrlEncode($payload);

        $signature = hash_hmac(
            'sha256',
            $base64UrlHeader . '.' . $base64UrlPayload,
            $this->jwtSecret,
            true
        );

        $base64UrlSignature = $this->base64UrlEncode($signature);

        return ($base64UrlSignature === $signatureProvided);
    }

    /**
     * Получение payload из токена
     *
     * @param string $jwt
     *
     * @return array|null
     */
    public function getPayload(string $jwt): ?array
    {
        if ($this->validate($jwt) === false) {
            return null;
        }
        $tokenParts = explode('.', $jwt);

        $payload = base64_decode($tokenParts[1]);

        return json_decode($payload, true);
    }

    /**
     * Кодировка в формат base64Url
     *
     * @param string $str
     *
     * @return string
     */
    public function base64UrlEncode(string $str): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($str));
    }
}

