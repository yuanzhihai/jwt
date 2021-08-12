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


class Encryption
{
    use Singleton;

    public function base64UrlEncode($content)
    {
        return str_replace('=', '', strtr(base64_encode($content), '+/', '-_'));
    }

    public function base64UrlDecode($content)
    {
        $remainder = strlen($content) % 4;
        if ($remainder) {
            $addlen  = 4 - $remainder;
            $content .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($content, '-_', '+/'));
    }
}
