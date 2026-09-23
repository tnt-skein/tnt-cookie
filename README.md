# tnt-cookie

Куки для Tarantool как формат: разбор заголовка `Cookie` и чужого
`Set-Cookie`, сборка `Set-Cookie` со строгими умолчаниями, подпись
значения и хранилище кук для исходящих запросов.

```lua
local cookie = require('tnt.cookie')

cookie.configure({ key = env.required('COOKIE_KEY') })

-- Со стороны сервера.
response.headers['set-cookie'] = cookie.set('sid', cookie.sign('42'), { max_age = 3600 })
-- sid=42.…; Max-Age=3600; Path=/; SameSite=Lax; Secure; HttpOnly
local sid, err = cookie.unsign(cookie.parse(request.headers['cookie']).sid)   -- '42' либо nil, причина

-- Со стороны клиента.
local jar = cookie.jar()
jar:put('https://example.org/login', login.headers['set-cookie'])
local header = jar:header_for('https://example.org/api')
```

Зависимости: `tnt-validate` (проверка настроек), `tnt-hash` (HMAC-SHA256
и сверка за постоянное время), `tnt-log` (журнал пропущенных кусков
заголовка), `tnt-clock` (стенные часы сроков) и `tnt-external` (подмена
часов и загрузки libpsl в проверках). Необязательно — системная
библиотека libpsl: из неё хранилище берёт список публичных суффиксов.

## Зачем

Кука — единственное место, куда браузер сам кладёт данные и сам их
возвращает, и ошибиться с ней легко: разбор падает на одной чужой куке,
собранный руками `Set-Cookie` забывает `HttpOnly`, значение `x; admin=1`
приезжает обратно двумя куками, подпись сверяется обычным `==`. Пакет
делает пять вещей:

- **Разбирает `Cookie` без отказов**: негодный кусок пропускается,
  остальные доезжают; из двух кук с одним именем берётся первая.
- **Собирает `Set-Cookie` строго**: `HttpOnly`, `Secure` и `SameSite=Lax`
  стоят, пока их не выключат словом; приставки `__Host-` и `__Secure-`,
  `SameSite=None` и `Partitioned` проверяются на выполнимость;
  недопустимый знак — отказ, а не молчаливая чистка.
- **Подписывает значение** HMAC-SHA256 в base64url и сверяет подпись
  за постоянное время.
- **Разбирает чужой `Set-Cookie`** по алгоритму RFC 6265 (5.2), с датами
  во всех трёх видах.
- **Хранит чужие куки** для исходящих запросов и отбирает их по домену,
  пути, сроку и `Secure` по правилам RFC 6265; куку с `Secure` из
  открытого канала не берёт и подменить защищённую ему не даёт, а куку
  с приставкой `__Host-` или `__Secure-` без обещанного не берёт вовсе
  (RFC 6265bis, 5.7); на публичный суффикс вроде `co.uk` куку не ставит,
  если на узле есть libpsl.

## Установка

```sh
tt rocks install tnt-cookie --server=https://tnt-skein.github.io/rocks
```

Или из исходников:

```sh
git clone https://github.com/tnt-skein/tnt-cookie.git
cd tnt-cookie && tt rocks make
```

## Как пользоваться

| Вызов | Что делает |
|---|---|
| `cookie.parse(text)` | разбирает заголовок `Cookie` запроса в таблицу «имя → значение» |
| `cookie.set(name, value, opts)` | собирает `Set-Cookie`; отказ — `nil, err` |
| `cookie.expire(name, opts)` | собирает `Set-Cookie`, который велит браузеру забыть куку |
| `cookie.sign(value, key)` | подписывает значение; без ключа бросает |
| `cookie.unsign(text, key)` | снимает подпись, проверив её; отказ — `nil, err` |
| `cookie.parse_set(text)` | разбирает чужой `Set-Cookie`; отказ — `nil, err` |
| `cookie.jar()` | новое пустое хранилище кук: `put`, `header_for`, `size`, `clear` |
| `cookie.configure(opts)` | настраивает общий набор; негодная настройка бросает |
| `cookie.new(opts)` | отдельный набор со своими умолчаниями |
| `cookie.default()` | общий набор |
| `cookie.status()` | действующие настройки без ключа |

Настройки: `path` (`'/'`), `domain`, `expires`, `max_age`, `secure`
(`true`), `http_only` (`true`), `same_site` (`'lax'`; ещё `'strict'`,
`'none'` и `'off'` — без атрибута), `partitioned` (`false`), а у набора
ещё `key` — ключ подписи.

```lua
cookie.set('sid', 'x; admin=1')
--> nil, 'в значении куки недопустим знак «;» на месте 2: заголовок разделяют пробел, кавычка, …'
cookie.set('__Host-sid', 'abc', { path = '/admin' })
--> nil, 'кука с приставкой __Host- видна на всём узле: путь обязан быть «/»'
cookie.expire('sid')
--> 'sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; SameSite=Lax; Secure; HttpOnly'
```

Настройка проверяется сразу и бросает: опечатка роняет запуск узла,
а не каждый его ответ. Место в отказе — строка, которая позвала
`configure`, `new`, `sign` или `unsign`. Ключ подписи не показывается
ни в отказе, ни в `status()`.

## Проверки

```sh
make deps          # luatest, luacheck, luacov с cluacov и зависимости пакета в .rocks
make check         # форматирование, линт, проверки, покрытие с порогом 100 %
make mutants-all   # мутационное тестирование утилитой tnt-mutants из PATH, порог 100 % убитых
```

Покрытие строк — 100 %, убитых мутантов — 100 % (181 проверка,
631 мутант в восьми модулях). Часы хранилища подменены двойником,
который двигает сама проверка, libpsl — двойником со своим списком
суффиксов, а объявления FFI сверяет живая проверка на системной
библиотеке. Точный вид подписи закреплён проверкой: сменить способ
подписи молча — значит разлогинить всех, у кого кука уже лежит.

## Документ

Полное описание с обоснованием решений: [docs/cookie.md](docs/cookie.md).

## Лицензия

MIT.
