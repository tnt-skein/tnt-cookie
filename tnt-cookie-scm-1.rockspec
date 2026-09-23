rockspec_format = '3.0'

package = 'tnt-cookie'
version = 'scm-1'

source = {
    url = 'git+https://github.com/tnt-skein/tnt-cookie.git',
    branch = 'main',
}

description = {
    summary = 'Куки как формат: разбор заголовков, сборка, подпись и хранилище',
    detailed = [[
        Куки нужны на обеих сторонах HTTP: сервер читает их из запроса
        и ставит в ответ, клиент хранит чужие и отправляет обратно.
        Пакет работает с ними как с форматом — со строками заголовков, —
        и в договор о запросе не лезет.

        Разбор Cookie не падает на чужом мусоре, разбор Set-Cookie идёт
        по алгоритму RFC 6265 и понимает даты во всех трёх видах. Сборка
        ставит HttpOnly, SameSite=Lax и Secure, пока их не выключат
        словом, держит обещания приставок __Host- и __Secure- и отвергает
        недопустимые знаки вместо того, чтобы молча их вырезать. Значение
        подписывается HMAC-SHA256 со сравнением за постоянное время,
        а хранилище отбирает куки по домену, пути, сроку и Secure —
        по правилам RFC 6265, а не на глаз. Куку с Secure из открытого
        канала и куку с приставкой без обещанного хранилище не берёт,
        а на публичный суффикс не ставит, если на узле есть системная
        libpsl.

        Зависит от tnt-validate (проверка настроек), tnt-hash (подпись
        и её сверка), tnt-log (журнал пропущенных кусков заголовка),
        tnt-clock (стенные часы сроков) и tnt-external (подмена часов
        и загрузки libpsl в проверках); libpsl необязательна. Покрытие
        строк и убитых мутантов — 100 %.
    ]],
    homepage = 'https://github.com/tnt-skein/tnt-cookie',
    issues_url = 'https://github.com/tnt-skein/tnt-cookie/issues',
    maintainer = 'tnt-skein',
    license = 'MIT',
    labels = { 'tarantool', 'cookie', 'http', 'rfc6265', 'hmac', 'security' },
}

dependencies = {
    'lua >= 5.1',
    'tnt-clock',
    'tnt-hash',
    'tnt-log',
    'tnt-external',
    'tnt-validate',
}

build = {
    type = 'builtin',
    modules = {
        ['tnt.cookie'] = 'tnt/cookie.lua',
        ['tnt.cookie.octet'] = 'tnt/cookie/octet.lua',
        ['tnt.cookie.date'] = 'tnt/cookie/date.lua',
        ['tnt.cookie.parse'] = 'tnt/cookie/parse.lua',
        ['tnt.cookie.build'] = 'tnt/cookie/build.lua',
        ['tnt.cookie.sign'] = 'tnt/cookie/sign.lua',
        ['tnt.cookie.suffix'] = 'tnt/cookie/suffix.lua',
        ['tnt.cookie.jar'] = 'tnt/cookie/jar.lua',
    },
}
