--- Сборка значения заголовка `Set-Cookie:`.
---
--- Порядок атрибутов здесь постоянный, хотя спецификация его не требует:
--- заголовок попадает и в проверки, и в журнал, и в отчёт об ошибке,
--- и один и тот же ответ должен выглядеть одинаково.
---
--- Собранное проверяется до отправки, а не молча чинится. Кука с точкой
--- с запятой в значении не обрезается до первой точки с запятой — она
--- отвергается: обрезанная кука уезжает клиенту целой с виду, и разбираться
--- с ней будет уже тот, кто её получил.

local date = require('tnt.cookie.date')
local octet = require('tnt.cookie.octet')

local Module = {}

--- Как SameSite пишется в заголовке.
---
--- Слово `off` в заголовок не попадает: им атрибут выключают целиком.
local SAME_SITE_WORD = { strict = 'Strict', lax = 'Lax', none = 'None' }

--- Целое число секунд либо отказ.
---@param value any
---@param subject string Подлежащее со связкой
---@return boolean ok
---@return string|nil err
local function check_seconds(value, subject)
    if value == nil then
        return true
    end

    if type(value) ~= 'number' or value % 1 ~= 0 then
        return false, ('%s задаваться целым числом секунд'):format(subject)
    end

    return true
end

--- Требования, которые берёт на себя имя с приставкой (RFC 6265bis, 4.1.3).
---
--- Приставка — обещание, вписанное в имя: `__Host-` значит «кука одного
--- узла, на весь узел и только по HTTPS», `__Secure-` — «только по HTTPS».
--- Браузер отвергнет куку, обещание не выполнившую, и сделает это молча:
--- сессия просто не заведётся, а в ответе всё будет выглядеть исправно.
--- Поэтому несостыковка ловится здесь — и у `__HOST-sid` тоже: браузер
--- узнаёт приставку без регистра (`octet.prefix_of`).
---@param name string
---@param options table
---@return boolean ok
---@return string|nil err
local function check_prefix(name, options)
    local prefix = octet.prefix_of(name)

    if prefix == nil then
        return true
    end

    if not options.secure then
        return false,
            ('кука с приставкой %s ставится только по HTTPS: нужен secure = true'):format(
                prefix
            )
    end

    if prefix == '__Secure-' then
        return true
    end

    if options.domain ~= nil then
        return false,
            'кука с приставкой __Host- принадлежит одному узлу: домен задавать нельзя'
    end

    if options.path ~= '/' then
        return false,
            'кука с приставкой __Host- видна на всём узле: путь обязан быть «/»'
    end

    return true
end

--- Знакомо ли слово, которым задали SameSite.
---@param value any
---@return boolean ok
---@return string|nil err
local function check_same_site(value)
    if value == nil or value == 'off' or SAME_SITE_WORD[value] ~= nil then
        return true
    end

    return false,
        ('признак SameSite бывает strict, lax, none или off, а не «%s»'):format(tostring(value))
end

--- Согласованы ли признаки между собой.
---@param options table
---@return boolean ok
---@return string|nil err
local function check_flags(options)
    if options.same_site == 'none' and not options.secure then
        -- SameSite=None значит «прикладывать к запросам с чужих сайтов».
        -- Браузеры отвергают такую куку без Secure, и правильно делают:
        -- иначе она уезжает на чужой сайт ещё и открытым текстом.
        return false,
            'кука с SameSite=none ходит на чужие сайты и потому обязана быть secure = true'
    end

    if options.partitioned and not options.secure then
        -- Partitioned заводит куке отдельную ячейку в каждом окружении,
        -- и вне HTTPS такая ячейка ничего не разделяет.
        return false, 'кука с признаком partitioned обязана быть secure = true'
    end

    return true
end

--- Проверяет всё, что уедет в заголовок.
---@param name any
---@param value any
---@param options table
---@return boolean ok
---@return string|nil err
local function check(name, value, options)
    local checks = {
        function()
            return octet.check_name(name)
        end,
        function()
            return octet.check_value(value)
        end,
        function()
            if options.path == nil then
                return true
            end

            return octet.check_path(options.path)
        end,
        function()
            if options.domain == nil then
                return true
            end

            return octet.check_domain(options.domain)
        end,
        function()
            return check_seconds(options.expires, 'срок куки expires должен')
        end,
        function()
            -- Пределы — после рода: сравнивать с ними можно только число.
            if options.expires == nil then
                return true
            end

            return date.check(options.expires)
        end,
        function()
            return check_seconds(options.max_age, 'время жизни куки max_age должно')
        end,
        function()
            return check_same_site(options.same_site)
        end,
        function()
            return check_flags(options)
        end,
        function()
            return check_prefix(name, options)
        end,
    }

    for _, one in ipairs(checks) do
        local ok, err = one()

        if not ok then
            return false, err
        end
    end

    return true
end

--- Собирает значение заголовка `Set-Cookie:`.
---@param name string Имя куки
---@param value string Значение куки
---@param options table Настройки, уже дополненные умолчаниями
---@return string|nil header Значение заголовка без его имени
---@return string|nil err
function Module.set(name, value, options)
    local ok, err = check(name, value, options)

    if not ok then
        return nil, err
    end

    local pieces = { ('%s=%s'):format(name, value) }

    if options.expires ~= nil then
        table.insert(pieces, ('Expires=%s'):format(date.format(options.expires)))
    end

    if options.max_age ~= nil then
        table.insert(pieces, ('Max-Age=%d'):format(options.max_age))
    end

    if options.domain ~= nil then
        table.insert(pieces, ('Domain=%s'):format(options.domain))
    end

    if options.path ~= nil then
        table.insert(pieces, ('Path=%s'):format(options.path))
    end

    if SAME_SITE_WORD[options.same_site] ~= nil then
        table.insert(pieces, ('SameSite=%s'):format(SAME_SITE_WORD[options.same_site]))
    end

    if options.secure then
        table.insert(pieces, 'Secure')
    end

    if options.http_only then
        table.insert(pieces, 'HttpOnly')
    end

    if options.partitioned then
        table.insert(pieces, 'Partitioned')
    end

    return table.concat(pieces, '; ')
end

return Module
