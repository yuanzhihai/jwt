<?php
/**
 * Created by PHP@大海 [三十年河东三十年河西,莫欺少年穷.!]
 * User: yuanzhihai
 * Date: 2021/8/12
 * Time: 1:44 下午
 * Author: PHP@大海 <396751927@qq.com>
 *       江城子 . 程序员之歌
 *
 *  十年生死两茫茫，写程序，到天亮。
 *      千行代码，Bug何处藏。
 *  纵使上线又怎样，朝令改，夕断肠。
 *
 *  领导每天新想法，天天改，日日忙。
 *     相顾无言，惟有泪千行。
 *  每晚灯火阑珊处，夜难寐，加班狂。
 */

namespace yzh52521\Jwt;

class Jwt
{
    private static $instance;

    private $secretKey = 'easyJwt';
    protected $prefix;

    private $alg = Jwt::ALG_METHOD_HS256; // 默认加密方式

    public const ALG_METHOD_AES = 'AES';
    public const ALG_METHOD_HMAC_SHA256 = 'HMACSHA256';
    public const ALG_METHOD_HS256 = 'HS256';
    public const ALG_METHOD_RS256 = 'RS256';

    public static function getInstance(): Jwt
    {
        if (!isset(self::$instance)) {
            self::$instance = new Jwt();
        }
        return self::$instance;
    }

    public function setSecretKey(string $key): Jwt
    {
        $this->secretKey = $key;
        return $this;
    }

    public function setAlg(string $alg): Jwt
    {
        $this->alg = $alg;
        return $this;
    }

    public function publish(): JwtObject
    {
        return new JwtObject(['secretKey' => $this->secretKey]);
    }

    /**
     * @throws Exception
     */
    public function decode(string $raw): ?JwtObject
    {
        if (strpos($raw, ' ')) {
            $prefix       = explode(' ', $raw);
            $this->prefix = $prefix[0];
            $raw          = str_replace($this->prefix . ' ', '', $raw);
        }

        $items = explode('.', $raw);

        // token格式
        if (count($items) !== 3) {
            throw new Exception('Token format error!');
        }

        // 验证header
        $header = Encryption::getInstance()->base64UrlDecode($items[0]);
        $header = json_decode($header, true);
        if (empty($header)) {
            throw new Exception('Token header is empty!');
        }

        // 验证payload
        $payload = Encryption::getInstance()->base64UrlDecode($items[1]);
        $payload = json_decode($payload, true);
        if (empty($payload)) {
            throw new Exception('Token payload is empty!');
        }

        if (empty($items[2])) {
            throw new Exception('Signature is empty!');
        }

        $jwtObjConfig = array_merge(
            $header,
            $payload,
            [
                'header' => $items[0],
                'payload' => $items[1],
                'signature' => $items[2],
                'secretKey' => $this->secretKey,
                'alg' => $this->alg
            ],
            ['prefix' => $this->prefix]
        );
        return new JwtObject($jwtObjConfig, true);
    }

}
