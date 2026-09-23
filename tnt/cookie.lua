--- Куки: разбор и сборка.
---
--- Пакет нарочно маленький и нарочно отдельный. Куки нужны троим сразу:
--- роутер читает их из запроса и ставит в ответ, HTTP-клиент хранит чужие
--- и отправляет обратно, сессия кладёт в куку свой опознаватель. Положить
--- разбор в роутер значит заставить клиента тянуть за собой роутер;
--- повторить его в каждом — получить три разбора, расходящихся на третий
--- месяц.
---
--- Пакет работает со строками заголовков и в договор о запросе не лезет:
--- разложить разобранное по полям запроса — работа роутера.
---
--- Пользоваться так:
---
---     local cookie = require('tnt.cookie')
---     local env = require('tnt.env')
---
---     cookie.configure({ key = env.required('COOKIE_KEY'), domain = 'example.org' })
---
---     local sent = cookie.parse(request.headers['cookie'])
---     local who, err = cookie.unsign(sent.sid or '')
---
---     local header = cookie.set('sid', cookie.sign('42'), { max_age = 3600 })
---     -- sid=42.zMh...; Max-Age=3600; Domain=example.org; Path=/;
---     -- SameSite=Lax; Secure; HttpOnly
---
---     local goodbye = cookie.expire('sid')
---
---     local outgoing = cookie.jar()
---     outgoing:put('https://example.org/login', response.headers['set-cookie'])
---     request.headers['cookie'] = outgoing:header_for('https://example.org/api')
---
--- Умолчания выбраны в пользу безопасности, и выключаются они словом,
--- а не забывчивостью. Что стоит каждое — сказано у `DEFAULTS`.

local build = require('tnt.cookie.build')
local date = require('tnt.cookie.date')
local jar = require('tnt.cookie.jar')
local octet = require('tnt.cookie.octet')
local parse = require('tnt.cookie.parse')
local sign = require('tnt.cookie.sign')
local validate = require('tnt.validate')

local Module = {}

--- Настройки, которые кука берёт у своего пакета, если не сказано иного
--- при её постановке.
local FIELDS = { 'path', 'domain', 'expires', 'max_age', 'secure', 'http_only', 'same_site', 'partitioned' }

--- Умолчания в пользу безопасности.
---
--- Каждое стоит того, кто его выключит, вполне определённой дыры, и каждое
--- выключается словом: `http_only = false`, `same_site = 'off'`,
--- `secure = false`.
local DEFAULTS = {
    -- Кука видна всему узлу. Иначе она не доедет до соседнего маршрута,
    -- и разработчик, не разобравшись, снимет путь совсем.
    path = '/',

    -- Домена нет: кука без Domain принадлежит ровно поставившему её узлу.
    -- С Domain она уезжает на все поддомены разом, а поддомен, отданный
    -- под чужую витрину, — обычное дело.
    domain = nil,

    -- Только по HTTPS. Кука, ушедшая по HTTP, видна всякому, кто смотрит
    -- на сеть, и переписывается им же по дороге.
    secure = true,

    -- Недоступна сценариям на странице. Кука без HttpOnly читается первым
    -- же чужим скриптом, попавшим на страницу, а опознаватель сессии,
    -- прочитанный чужим скриптом, — это уже чужая сессия.
    http_only = true,

    -- Не уезжает на чужой сайт вместе с запросом. Без SameSite кука
    -- прикладывается и к запросу, который отправила чужая страница, —
    -- это и есть CSRF. Lax, а не Strict: Strict роняет переход по ссылке
    -- из письма, и его снимают целиком, вместе с защитой.
    same_site = 'lax',

    -- Partitioned меняет смысл куки: в каждом первом-стороннем окружении
    -- она своя. Пока об этом не попросили, кука одна.
    partitioned = false,
}

--- Схема настроек пакета.
---
--- Проверяются они при `configure`, а не при первой куке: настройка
--- с опечаткой обязана обнаружиться при запуске узла, а не в ответе
--- первому пользователю.
local OPTIONS = {
    -- Путь, домен и срок здесь проверяются только на тип: что в них можно
    -- писать, знают tnt.cookie.octet и tnt.cookie.date, и знают одни — два
    -- места с этими правилами разошлись бы на первой же поправке.
    path = validate.string({ optional = true, title = 'путь куки', gender = 'm' }),
    domain = validate.string({ optional = true, title = 'домен куки', gender = 'm' }),
    expires = validate.integer({ optional = true, title = 'срок куки', gender = 'm' }),
    max_age = validate.integer({ optional = true, title = 'время жизни куки', gender = 'n' }),
    secure = validate.boolean({ optional = true, title = 'признак Secure', gender = 'm' }),
    http_only = validate.boolean({ optional = true, title = 'признак HttpOnly', gender = 'm' }),
    partitioned = validate.boolean({ optional = true, title = 'признак Partitioned', gender = 'm' }),
    same_site = validate.string({
        one_of = { 'strict', 'lax', 'none', 'off' },
        optional = true,
        title = 'признак SameSite',
        gender = 'm',
    }),
    key = validate.string({
        -- Ключ не показывается даже в отказе по настройкам: отказ уходит
        -- в журнал запуска целиком.
        secret = true,
        optional = true,
        min = 1,
        title = 'ключ подписи',
        gender = 'm',
    }),
}

--- Всё, что хранится в настройках набора: умолчания куки и ключ подписи.
local SETTINGS = { 'key' }

for _, field in ipairs(FIELDS) do
    table.insert(SETTINGS, field)
end

--- Отказ по настройке, который надо заметить при запуске, а не потом.
---
--- Место в отказе — строка того, кто позвал `configure` или `new`:
--- чинить надо его настройку, а строка внутри пакета отправила бы искать
--- ошибку в журнале запуска не там. Отсюда уровень у каждой функции
--- по дороге. Уровень — первым аргументом: следом идёт пара проверки
--- как есть, и оба её значения доходят сюда без распаковки.
---@param level integer Уровень вины, как у `error` в вызывающем
---@param ok boolean
---@param refusal string|nil
local function demand(level, ok, refusal)
    if not ok then
        error(refusal, level + 1)
    end
end

--- Содержимое пути, домена и срока — теми же правилами, что и у отдельной
--- куки.
---
--- Проверяется здесь, а не при первой куке: настройка с путём `admin`
--- или со сроком в десятитысячном году обязана уронить запуск узла,
--- а не каждый его ответ.
---@param options table
---@param level integer Уровень вины, как у `error` в вызывающем
local function check_content(options, level)
    demand(level + 1, octet.check_path(options.path))

    if options.domain ~= nil then
        demand(level + 1, octet.check_domain(options.domain))
    end

    if options.expires ~= nil then
        demand(level + 1, date.check(options.expires))
    end
end

--- Проверенные настройки поверх прежних.
---
--- Заданное значение перекрывает прежнее, даже когда это `false`: простое
--- `заданное или прежнее` здесь неверно — `secure = false` это ответ,
--- а не его отсутствие.
---@param opts table|nil
---@param base table
---@param level integer Уровень вины, как у `error` в вызывающем
---@return table
local function validated(opts, base, level)
    local given, err = validate.settings(opts or {}, OPTIONS)

    if err ~= nil then
        error(err, level + 1)
    end

    local options = {}

    for _, field in ipairs(SETTINGS) do
        options[field] = given[field]

        if options[field] == nil then
            options[field] = base[field]
        end
    end

    check_content(options, level + 1)

    return options
end

--- Заданное значение или прежнее.
---@param given any
---@param fallback any
---@return any
local function pick(given, fallback)
    if given == nil then
        return fallback
    end

    return given
end

--- Настройки этой куки поверх умолчаний экземпляра.
---@param base table
---@param opts table|nil
---@return table
local function merged(base, opts)
    local given = opts or {}
    local options = {}

    for _, field in ipairs(FIELDS) do
        options[field] = pick(given[field], base[field])
    end

    -- Слово `off` дальше не едет: оно значит «атрибута не будет».
    if options.same_site == 'off' then
        options.same_site = nil
    end

    return options
end

--- Подпись ключом набора — одна на метод набора и на функцию пакета.
---
--- Уровень вины приходит от них: у каждой свой вызывающий, и отказ без
--- ключа обязан показать на него. По той же причине подпись кладётся
--- в переменную, а не отдаётся хвостовым вызовом: хвостовой вызов
--- снимает кадр, и уровень показал бы мимо вызывающего.
---@param set TntCookie
---@param value string
---@param key string|nil Ключ; по умолчанию из настроек набора
---@param level integer Уровень вины, как у `error` в вызывающем
---@return string signed
local function signed(set, value, key, level)
    local result = sign.make(value, pick(key, set.options.key), level + 1)

    return result
end

--- Снятие подписи ключом набора; уровень вины — как у подписи.
---@param set TntCookie
---@param text any
---@param key string|nil Ключ; по умолчанию из настроек набора
---@param level integer Уровень вины, как у `error` в вызывающем
---@return string|nil value
---@return string|nil err
local function opened(set, text, key, level)
    local value, err = sign.open(text, pick(key, set.options.key), level + 1)

    return value, err
end

---@class TntCookie
---@field options table Действующие настройки
local Cookie = {}
Cookie.__index = Cookie

--- Разбирает заголовок `Cookie:` запроса.
---
--- Настройки разбору не нужны — заголовок разбирается одинаково у всех, —
--- но местом в наборе он нужен: иначе разработчику пришлось бы помнить,
--- что одна половина работы с куками зовётся через набор, а другая мимо.
---@param text any Значение заголовка
---@return table<string, string> cookies Имя → значение
function Cookie.parse(_, text)
    return parse.header(text)
end

--- Разбирает чужой заголовок `Set-Cookie:`.
---@param text any Значение одного заголовка
---@return TntCookieSet|nil
---@return string|nil err
function Cookie.parse_set(_, text)
    return parse.set_cookie(text)
end

--- Собирает значение заголовка `Set-Cookie:`.
---@param name string
---@param value string
---@param opts table|nil Настройки только этой куки
---@return string|nil header
---@return string|nil err
function Cookie:set(name, value, opts)
    return build.set(name, value, merged(self.options, opts))
end

--- Просит браузер забыть куку.
---
--- Удаление куки — та же её постановка, только с истёкшим сроком, и путь
--- с доменом обязаны совпасть с теми, с которыми её ставили: браузер
--- различает куки по тройке «имя, домен, путь», и `Path=/` не удалит куку,
--- поставленную на `/admin`.
---@param name string
---@param opts table|nil
---@return string|nil header
---@return string|nil err
function Cookie:expire(name, opts)
    local options = merged(self.options, opts)

    -- И Max-Age, и Expires: первый понимают все нынешние браузеры, второй
    -- нужен тем, кто Max-Age не знает, а такие ещё встречаются.
    options.max_age = 0
    options.expires = 0

    return build.set(name, '', options)
end

--- Подписывает значение.
---@param value string
---@param key string|nil Ключ; по умолчанию из настроек
---@return string signed
function Cookie:sign(value, key)
    local result = signed(self, value, key, 2)

    return result
end

--- Снимает подпись, проверив её.
---@param text any
---@param key string|nil Ключ; по умолчанию из настроек
---@return string|nil value
---@return string|nil err
function Cookie:unsign(text, key)
    local value, err = opened(self, text, key, 2)

    return value, err
end

--- Новое пустое хранилище кук для исходящих запросов.
---
--- Умолчания набора хранилищу не передаются: они про куки, которые ставим
--- мы, а хранилище держит чужие — переданный ему наш `Secure` менял бы
--- условия отбора, о которых чужой сервер не просил.
---@return TntCookieJar
function Cookie.jar()
    return jar.new()
end

--- Что настроено.
---
--- Ключа подписи здесь нет и не будет: состояние читают и журнал, и панель,
--- и человек через плечо. Видно лишь то, что ключ задан.
---@return table
function Cookie:status()
    local options = self.options

    return {
        path = options.path,
        domain = options.domain,
        expires = options.expires,
        max_age = options.max_age,
        secure = options.secure,
        http_only = options.http_only,
        same_site = options.same_site,
        partitioned = options.partitioned,
        signed = options.key ~= nil,
    }
end

--- Отдельный набор кук со своими умолчаниями.
---@param opts table|nil
---@return TntCookie
function Module.new(opts)
    return setmetatable({ options = validated(opts, DEFAULTS, 2) }, Cookie)
end

--- Общий на процесс набор и настройки, из которых он заводится.
---
--- Одной таблицей: заменить настройки, забыв обнулить заведённый по ним
--- набор, — самая частая ошибка в такой паре, а с одной таблицей забыть
--- нечего.
local common = { options = DEFAULTS }

--- Настраивает общий на процесс набор.
---
--- Прежний набор забывается вместе с настройками: настройка, сделанная
--- после первой куки, обязана менять поведение, а не оставаться словами.
---@param opts table|nil
function Module.configure(opts)
    common = { options = validated(opts, DEFAULTS, 2) }
end

--- Общий на процесс набор; заводится при первом обращении.
---@return TntCookie
function Module.default()
    common.set = common.set or setmetatable({ options = common.options }, Cookie)

    return common.set
end

--- Разбирает заголовок `Cookie:` запроса.
---@param text any
---@return table<string, string>
function Module.parse(text)
    return parse.header(text)
end

--- Разбирает чужой заголовок `Set-Cookie:`.
---@param text any
---@return TntCookieSet|nil
---@return string|nil err
function Module.parse_set(text)
    return parse.set_cookie(text)
end

--- Собирает значение заголовка `Set-Cookie:` общими умолчаниями.
---@param name string
---@param value string
---@param opts table|nil
---@return string|nil header
---@return string|nil err
function Module.set(name, value, opts)
    return Module.default():set(name, value, opts)
end

--- Просит браузер забыть куку.
---@param name string
---@param opts table|nil
---@return string|nil header
---@return string|nil err
function Module.expire(name, opts)
    return Module.default():expire(name, opts)
end

--- Подписывает значение общим ключом.
---@param value string
---@param key string|nil
---@return string
function Module.sign(value, key)
    local result = signed(Module.default(), value, key, 2)

    return result
end

--- Снимает подпись общим ключом.
---@param text any
---@param key string|nil
---@return string|nil value
---@return string|nil err
function Module.unsign(text, key)
    local value, err = opened(Module.default(), text, key, 2)

    return value, err
end

--- Новое пустое хранилище кук для исходящих запросов.
---@return TntCookieJar
function Module.jar()
    return jar.new()
end

--- Что настроено у общего набора.
---@return table
function Module.status()
    return Module.default():status()
end

return Module
