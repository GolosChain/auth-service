# Auth service

**Auth service** является сервисом для авторизации запросов

### Основное

Микросервис реализует два метода:

-   'auth.authorize': принимает параметр вида `{ user, sign, secret, ...data }` и возвращает данные вида `{...data, sign, user, roles: []}` либо ошибку авторизации

-   'auth.generateSecret': возвращает сгенерированный секрет

### Фейковая транзакция

```
{
    ref_block_num: 3367,
    ref_block_prefix: 879276768,
    expiration: '2018-07-06T14:52:24',
    operations: [
        [
            'vote',
            {
                voter: <user>,      // Имя пользователя
                author: 'test',
                permlink: <secret>, // Секрет, который пришел в запросе с сервера
                weight: 1,
            },
        ],
    ],
    extensions: [],
}
```
