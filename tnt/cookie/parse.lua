--- Разбор заголовков: своего `Cookie:` и чужого `Set-Cookie:`.
---
--- Разборы разной строгости, и это нарочно.
---
--- `Cookie:` приходит от клиента — от браузера, от прокси, от того, кто
--- собрал запрос руками, — и упасть на нём нельзя: отказ разбора означал бы,
--- что одна чужая кука в заголовке отключает всё приложение. Поэтому пара,
--- которую не разобрать, пропускается, а остальные доезжают. Пропущенное
--- отмечается в журнале одной строкой — без имени и без значения: в значении
--- ездит опознаватель сессии, и журнал — последнее место, где ему стоит
--- оказаться.
---
--- `Set-Cookie:` разбирается по алгоритму RFC 6265 (5.2), который нарочно
--- мягче грамматики из раздела 4.1: серверы ставят пробелы там, где
--- грамматика их запрещает, и клиент, разбирающий по грамматике, теряет
--- куки на ровном месте.
---
--- Заголовок разбирается по одному: несколько `Set-Cookie` в ответе — это
--- несколько заголовков, а не один через запятую. Склеить их запятой
--- и разрезать обратно нельзя: запятая стоит внутри даты («Sun, 06 Nov»),
--- и разрез придётся ровно посередине срока.

local date = require('tnt.cookie.date')
local octet = require('tnt.cookie.octet')

local log = require('tnt.log').new('tnt.cookie')

local Module = {}

--- Значения SameSite, которые что-то значат (RFC 6265bis, 5.6.7).
---
--- Всё прочее браузер сводит к умолчанию, равному Lax, — поэтому чужое
--- слово здесь не запоминается: записать в разобранное то, чего сервер
--- не присылал, значит соврать тому, кто это разобранное прочтёт.
local SAME_SITE = { strict = 'strict', lax = 'lax', none = 'none' }

--- Куски заголовка, разделённые точкой с запятой.
---@param text string
---@return string[]
local function pieces_of(text)
    local found = {}

    for piece in (text .. ';'):gmatch('([^;]*);') do
        table.insert(found, piece)
    end

    return found
end

--- Имя и значение из куска «имя=значение».
---
--- Пробелы по краям снимаются, внутри — остаются: так велит RFC 6265 (5.2),
--- и это не мелочь. `a b` — законное значение, а ` a` прислал прокси,
--- добавивший пробел после точки с запятой.
---@class TntCookiePair
---@field name string
---@field value string

---@param piece string
---@return TntCookiePair|nil
local function pair_of(piece)
    local name, value = piece:match('^%s*(.-)%s*=%s*(.-)%s*$')

    if name == nil or name == '' then
        return nil
    end

    -- Образец совпал целиком или не совпал вовсе: обе его части
    -- обязательны, и значение здесь есть всегда.
    ---@cast value string
    return { name = name, value = value }
end

--- Разбирает заголовок `Cookie:` запроса.
---
--- Кука с повторённым именем берётся первая: в заголовке они идут
--- от самого точного пути к самому общему (RFC 6265, 5.4), и вторая с тем
--- же именем — либо кука соседнего пути, либо подложенная с поддомена
--- в расчёте на то, что разбор возьмёт последнюю.
---@param text any Значение заголовка Cookie
---@return table<string, string> cookies Имя → значение
function Module.header(text)
    local found = {}

    if type(text) ~= 'string' then
        return found
    end

    for _, piece in ipairs(pieces_of(text)) do
        local pair = pair_of(piece)

        if pair == nil then
            log.debug('в заголовке Cookie пропущен кусок без имени')
        elseif not octet.check_name(pair.name) then
            -- Имя, непохожее на лексему HTTP, мы не ставили: так выглядит
            -- подмешанная кука, и место ей в журнале, а не в разобранном.
            log.debug(
                'в заголовке Cookie пропущена кука с недопустимым именем'
            )
        elseif found[pair.name] == nil then
            found[pair.name] = (octet.unquote(pair.value))
        end
    end

    return found
end

---@class TntCookieSet
---@field name string
---@field value string
---@field quoted boolean Значение приехало в кавычках
---@field expires number|nil Срок по стенным часам, секунды от эпохи
---@field max_age integer|nil Сколько секунд жить с мига получения
---@field domain string|nil Домен без ведущей точки, в нижнем регистре
---@field path string|nil
---@field secure boolean
---@field http_only boolean
---@field same_site string|nil strict, lax или none
---@field partitioned boolean

--- Что делать с каждым известным атрибутом (RFC 6265, 5.2.1 — 5.2.6).
---
--- Незнакомый атрибут спецификация велит пропустить: завтра их станет
--- больше, и клиент, отвергающий куку из-за незнакомого слова, перестанет
--- работать в тот же день.
---@type table<string, fun(cookie: TntCookieSet, value: string)>
local ATTRIBUTES = {
    expires = function(cookie, value)
        local at = date.parse(value)

        -- Непонятную дату спецификация велит пропустить, а не отвергать
        -- куку: сервер с кривыми часами не должен лишать нас сессии.
        if at ~= nil then
            cookie.expires = at
        end
    end,

    ['max-age'] = function(cookie, value)
        -- Минус разрешён нарочно: Max-Age=0 и отрицательный — это «забудь
        -- куку», и именно так её удаляют все.
        if value:match('^%-?%d+$') ~= nil then
            cookie.max_age = tonumber(value)
        end
    end,

    domain = function(cookie, value)
        if value ~= '' then
            -- Ведущая точка — наследие Netscape: RFC 6265 (5.2.3) велит
            -- её снять, а куку считать поддоменной в любом случае.
            cookie.domain = value:gsub('^%.', ''):lower()
        end
    end,

    path = function(cookie, value)
        -- Путь, не начинающийся с косой, спецификация велит пропустить:
        -- вместо него хранилище возьмёт путь запроса.
        if value:match('^/') ~= nil then
            cookie.path = value
        end
    end,

    secure = function(cookie)
        cookie.secure = true
    end,

    httponly = function(cookie)
        cookie.http_only = true
    end,

    samesite = function(cookie, value)
        cookie.same_site = SAME_SITE[value:lower()]
    end,

    partitioned = function(cookie)
        cookie.partitioned = true
    end,
}

--- Один атрибут из куска после точки с запятой.
---@param cookie TntCookieSet
---@param piece string
local function attribute(cookie, piece)
    -- Атрибут без знака равенства — это признак: Secure, HttpOnly.
    local pair = pair_of(piece) or { name = (piece:gsub('^%s*(.-)%s*$', '%1')), value = '' }
    local take = ATTRIBUTES[pair.name:lower()]

    if take ~= nil then
        take(cookie, pair.value)
    end
end

--- Разбирает чужой заголовок `Set-Cookie:`.
---@param text any Значение заголовка без его имени
---@return TntCookieSet|nil
---@return string|nil err
function Module.set_cookie(text)
    if type(text) ~= 'string' then
        return nil,
            ('заголовок Set-Cookie должен быть строкой, а не %s'):format(type(text))
    end

    local pieces = pieces_of(text)
    local pair = pair_of(table.remove(pieces, 1))

    if pair == nil then
        return nil, 'в заголовке Set-Cookie нет пары «имя=значение»'
    end

    local bare, quoted = octet.unquote(pair.value)

    ---@type TntCookieSet
    local cookie = {
        name = pair.name,
        value = bare,
        quoted = quoted,
        secure = false,
        http_only = false,
        partitioned = false,
    }

    for _, piece in ipairs(pieces) do
        attribute(cookie, piece)
    end

    return cookie
end

return Module
