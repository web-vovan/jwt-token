### Сервис для работы с jwt токенами

**Создание токена**

```php
$payload = [
    'name' => 'admin'
];

$token = (new JwtTokenService())->generate($payload);

// "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidm92YW4iLCJleHAiOjE3MTk3NDAxMTd9.fSgDXyjfaMoXU3Te_BFKk6nyzkU0YaeqWa5CZKOMyAE
```

**Получение данных из токена**

```php
$payload = (new JwtTokenService())->getPayload($token);

//array(2) {
//  ["name"]=>
//  string(5) "admin"
//  ["exp"]=>
//  int(1719740133)
//}

```