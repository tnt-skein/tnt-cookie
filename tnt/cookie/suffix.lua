--- Список публичных суффиксов: зона это или домен одного владельца.
---
--- Домен куки сверяется с узлом по RFC 6265 (5.1.3): узел обязан в него
--- входить. Узел `evil.co.uk` с `Domain=co.uk` это правило выполняет,
--- а кука уехала бы на все узлы зоны `co.uk` — к владельцам, которые
--- друг другу чужие. По одному имени зону от домена не отличить: `co.uk`
--- и `example.org` устроены одинаково. Отличает их только список
--- публичных суффиксов (publicsuffix.org), и спрашивать его велит
--- RFC 6265 (5.3, шаг 5).
---
--- Список берётся у системной библиотеки libpsl, а своей копии у пакета
--- нет. В списке около десяти тысяч записей, и меняется он много раз
--- в год: копия внутри пакета устаревала бы молча, а системная
--- обновляется вместе с системой. libpsl лежит почти в любой поставке
--- Linux — её тянет libcurl, — но не во всякой, поэтому она
--- необязательна: без неё ответа нет, и хранилище остаётся при своём
--- правиле «в домене хотя бы одна точка».
---
--- Имена объявлений свои (`tnt_cookie_psl_*`), а на символы библиотеки
--- они ведут через `__asm__`: функция `psl_is_public_suffix` с чужой
--- подписью, объявленная другим модулем раньше нас, уронила бы
--- `ffi.cdef` «attempt to redefine».

local ffi = require('ffi')

local external = require('tnt.external')

---@class TntCookieSuffixSource Внешние зависимости списка
---@field load fun(name: string): any Загрузка библиотеки, как `ffi.load`

local Module = {}

--- Загрузка библиотеки — внешняя зависимость: проверка подменяет её,
--- чтобы увидеть узел без libpsl и список, составленный ею самой.
---@type fun(): TntCookieSuffixSource
local source = external.install(Module, { load = ffi.load })

--- Имена библиотеки в порядке поиска: общее имя ставит только пакет
--- разработчика, а soname лежит в любой поставке с libpsl.
Module.NAMES = { 'psl', 'libpsl.so.5' }

--- Объявления FFI; повторная загрузка модуля (проверки грузят исходники
--- заново) объявляет их один раз.
---
--- Строками списка, а не одной длинной строкой: внутри `[[ ]]` генератор
--- мутантов принимает объявление за мёртвый код, и его порча осталась бы
--- непроверенной.
if not pcall(ffi.typeof, 'tnt_cookie_psl') then
    ffi.cdef(table.concat({
        'typedef struct tnt_cookie_psl tnt_cookie_psl;',
        'const tnt_cookie_psl *tnt_cookie_psl_latest(const char *file) __asm__("psl_latest");',
        'int tnt_cookie_psl_is_public(const tnt_cookie_psl *list, const char *domain) __asm__("psl_is_public_suffix");',
    }, '\n'))
end

--- Список по загрузчику; `false` — списка нет.
---
--- Запоминается и отсутствие: иначе на узле без libpsl каждая кука
--- с Domain стоила бы двух неудачных поисков библиотеки на диске.
--- Библиотеку, поставленную после запуска, узел увидит после
--- перезапуска. Ключ — сам загрузчик: проверка, подменившая его,
--- получает свой ответ, а вернувшая настоящий — прежний.
---@type table<function, table|false>
local lists = setmetatable({}, { __mode = 'k' })

--- Ищет библиотеку по именам и берёт у неё список.
---
--- Путь к файлу списка не передаётся: libpsl сама выбирает свежее
--- из встроенного списка и системного файла, который обновляется
--- отдельно от неё.
---@param load fun(name: string): any
---@return table|false
local function discover(load)
    for _, name in ipairs(Module.NAMES) do
        local ok, library = pcall(load, name)

        if ok then
            local list = library.tnt_cookie_psl_latest(nil)

            -- Библиотека, собранная без встроенного списка, на машине без
            -- файла списка отдаёт NULL: она есть, а ответить ей нечем.
            if list == nil then
                return false
            end

            return { library = library, list = list }
        end
    end

    return false
end

--- Публичный ли суффикс домен (RFC 6265, 5.3, шаг 5).
---@param domain string Домен куки: без ведущей точки, в нижнем регистре
---@return boolean|nil public `nil` — списка на узле нет, и ответить нечем
function Module.is_public(domain)
    local load = source().load

    if lists[load] == nil then
        lists[load] = discover(load)
    end

    local found = lists[load]

    if not found then
        return nil
    end

    -- Точка в конце имени законна и значит тот же узел, а libpsl её
    -- не снимает: `co.uk.` для неё не суффикс, и узел `evil.co.uk.`
    -- поставил бы куку на всю зону.
    local bare = (domain:gsub('%.+$', ''))

    return found.library.tnt_cookie_psl_is_public(found.list, bare) == 1
end

return Module
