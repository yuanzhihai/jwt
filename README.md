# jwt

## 安装

可以通过composer安装

~~~ 
composer require yzh52521/jwt 
~~~

## 依赖

~~~
* PHP version >= PHP 7.1
~~~

## 生成token

```php
use yzh52521\Jwt\Jwt;

$jwtObject = Jwt::getInstance()
    ->setSecretKey('easyjwt') // 秘钥
    ->publish()
    ->setAlg('HMACSHA256') // 加密方式
     ->setAud('user') // 用户
    ->setExp(time()+3600) // 过期时间
    ->setIat(time()) // 发布时间
    ->setIss('easyswoole') // 发行人
    ->setJti(md5(time())) // jwt id 用于标识该jwt
    ->setNbf(time()+60*5) // 在此之前不可用
    ->setSub('主题') // 主题
    ->setPrefix('Bearer') // token前缀(可选)
    ->setData(['uid'=>1]);// 自定义数据

// 最终生成的token
$token = $jwtObject->__toString();
// 如果设置了setPrefix将会在生成的token加入对应的前缀,decode的时候会自动截取还原token
// Bearer +token (前缀与token间有一个空格，请注意)
```

## 解析token

```php
use yzh52521\Jwt\Jwt;

$token = "eyJhbGciOiJITUFDU0hBMjU2IiwiaXNzIjoiZWFzeXN3b29sZSIsImV4cCI6MTU3MzgzNTIxMSwic3ViIjoi5Li76aKYIiwibmJmIjoxNTczODMxOTExLCJhdWQiOiJ1c2VyIiwiaWF0IjoxNTczODMxNjExLCJqdGkiOiJjYWJhZmNiMWIxZTkxNTU3YzIxMDUxYTZiYTQ0MTliMiIsInNpZ25hdHVyZSI6IjZlNTI1ZjJkOTFjZGYzMjBmODE1NmEwMzE1MDhiNmU0ZDQ0YzhkNGFhYzZjNmU1YzMzMTNjMDIyMGJjYjJhZjQiLCJzdGF0dXMiOjEsImRhdGEiOlsib3RoZXJfaW5mbyJdfQ%3D%3D";

try {
    $jwtObject = Jwt::getInstance()->decode($token);

    $status = $jwtObject->getStatus();
    
    // 如果encode设置了秘钥,decode 的时候要指定
    // $jwtObject = Jwt::getInstance()->setSecretKey('easyjwt')->decode($token);

    switch ($status)
    {
        case -1:
            echo 'token无效';
            break;
        case  1:
            echo '验证通过';
            $jwtObject->getAlg();
            $jwtObject->getAud();
            $jwtObject->getData();
            $jwtObject->getExp();
            $jwtObject->getIat();
            $jwtObject->getIss();
            $jwtObject->getNbf();
            $jwtObject->getJti();
            $jwtObject->getSub();
            $jwtObject->getSignature();
            $jwtObject->getPrefix();
            $jwtObject->getProperty('alg');
            break;
        case  2:
            echo '验证失败';
            break;
        case  -2:
            echo 'token过期';
        break;
    }
} catch (\yzh52521\Jwt\Exception $e) {

}
```
