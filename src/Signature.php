<?php
/**
 * Created by PHP@大海 [三十年河东三十年河西,莫欺少年穷.!]
 * User: yuanzhihai
 * Date: 2021/8/12
 * Time: 1:46 下午
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

class Signature extends SplBean
{
    protected $secretKey;
    protected $header;
    protected $payload;
    protected $alg;

    /**
     * php 7.4以下不支持在__toString()抛出异常
     */
    public function __toString()
    {
        $content = $this->header . '.' . $this->payload;

        $signature = "";
        switch ($this->alg) {
            case Jwt::ALG_METHOD_HMAC_SHA256:
            case Jwt::ALG_METHOD_HS256:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    hash_hmac('sha256', $content, $this->secretKey, true)
                );
                break;
            case Jwt::ALG_METHOD_AES:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    openssl_encrypt($content, 'AES-128-ECB', $this->secretKey)
                );
                break;
            case Jwt::ALG_METHOD_RS256:
                $success = openssl_sign($content, $signature, $this->secretKey, 'SHA256');
                if (!$success) {
                    $signature = "";
                } else {
                    $signature = Encryption::getInstance()->base64UrlEncode($signature);
                }
                break;
            default:
                $signature = "";
        }
        return $signature;
    }
}
