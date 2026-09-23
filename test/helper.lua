--- Общие средства тестов пакета кук.
---
--- Исходники читаются с диска, а не через `require`: у Tarantool свой
--- загрузчик `.rocks`, он идёт раньше `package.path` и подсунул бы
--- установленную копию пакета, если она есть. Проверки тогда шли бы
--- против вчерашнего кода, а покрытие считалось бы по нему. Зависимости
--- пакета — `tnt.validate`, `tnt.hash`, `tnt.log`, `tnt.clock`,
--- `tnt.external` — берутся из `.rocks` обычным `require`: проверяется этот
--- пакет, а не они.
---
--- Оснастка в `test/testing/` — загрузчик исходников и часы, которые
--- двигает проверка, — грузится так же и один раз на процесс: второй
--- экземпляр загрузчика не знал бы, что вытеснил первый, и не вернул бы
--- вытесненное на место.
---
--- Проверки берут всё через помощник, а не из оснастки напрямую: помощник —
--- единственное, чем файл проверок отличается от того же файла в наборе,
--- где пакет живёт рядом со своими зависимостями.

local fio = require('fio')
local t = require('luatest')

--- Модули оснастки в порядке зависимостей.
local TESTING = {
    { name = 'tnt.testing.sources', path = 'test/testing/sources.lua' },
    { name = 'tnt.testing.clock', path = 'test/testing/clock.lua' },
}

for _, module in ipairs(TESTING) do
    if package.loaded[module.name] == nil then
        local chunk, failure = loadfile(fio.abspath(module.path))

        if chunk == nil then
            error(('оснастка %s не читается: %s'):format(module.name, tostring(failure)))
        end

        package.loaded[module.name] = chunk()
    end
end

--- Оснастка проверок под теми именами, что зовёт помощник.
local testing = {
    load_sources = package.loaded['tnt.testing.sources'].load,
    unload_sources = package.loaded['tnt.testing.sources'].unload,
    module = package.loaded['tnt.testing.sources'].module,
    clock = package.loaded['tnt.testing.clock'].new,
}

local helper = {}

--- Модули пакета в порядке зависимостей.
helper.MODULES = {
    { name = 'tnt.cookie.octet', path = 'tnt/cookie/octet.lua' },
    { name = 'tnt.cookie.date', path = 'tnt/cookie/date.lua' },
    { name = 'tnt.cookie.parse', path = 'tnt/cookie/parse.lua' },
    { name = 'tnt.cookie.build', path = 'tnt/cookie/build.lua' },
    { name = 'tnt.cookie.sign', path = 'tnt/cookie/sign.lua' },
    { name = 'tnt.cookie.suffix', path = 'tnt/cookie/suffix.lua' },
    { name = 'tnt.cookie.jar', path = 'tnt/cookie/jar.lua' },
    { name = 'tnt.cookie', path = 'tnt/cookie.lua' },
}

--- Имя, под которым двойник libpsl находится по умолчанию: soname.
helper.PSL_SONAME = 'libpsl.so.5'

--- Загрузчик, который помнит спрошенные имена и находит библиотеку
--- только под одним.
---@param library table|nil Что отдать; nil — библиотеки нет вовсе
---@param found string|nil Под каким именем она лежит; по умолчанию soname
---@return fun(name: string): table load
---@return string[] asked Спрошенные имена по порядку
function helper.loader(library, found)
    local asked = {}
    local place = found or helper.PSL_SONAME

    return function(name)
        table.insert(asked, name)

        if library == nil or name ~= place then
            error(('%s: cannot open shared object file'):format(name), 0)
        end

        return library
    end,
        asked
end

--- Двойник libpsl со своим списком суффиксов.
---
--- Список свой, а не системный: проверка, полагающаяся на настоящий,
--- зависела бы от того, стоит ли libpsl на машине и насколько свеж
--- её список. Настоящую библиотеку проверяет `suffix_live_test.lua`.
---@param suffixes string[]|nil Публичные суффиксы; nil — библиотека без списка
---@return table library
function helper.psl(suffixes)
    local list = { suffixes = suffixes }
    local public = {}

    for _, domain in ipairs(suffixes or {}) do
        public[domain] = true
    end

    return {
        tnt_cookie_psl_latest = function(file)
            t.assert_equals(file, nil)

            if suffixes == nil then
                return nil
            end

            return list
        end,

        tnt_cookie_psl_is_public = function(asked_list, domain)
            t.assert_is(asked_list, list)

            return public[domain] and 1 or 0
        end,
    }
end

--- Даёт узлу список публичных суффиксов двойником libpsl.
---@param suffixes string[]
function helper.suffixes(suffixes)
    testing.module('tnt.cookie.suffix')._set_source({ load = (helper.loader(helper.psl(suffixes))) })
end

--- Заводит группу проверок с заново загруженными исходниками.
---
--- Исходники грузятся перед каждой проверкой: и подменённые часы,
--- и настройки общего набора живут в модулях, и оставленные одной
--- проверкой достались бы следующей. Часы — двойник из оснастки:
--- настоящие сделали бы проверку часовой куки часовой, а стенные часы
--- двойника стоят на 1700000000, пока их не подвинет проверка.
---
--- libpsl по умолчанию нет: проверки хранилища не должны зависеть
--- от того, стоит ли она на машине. Кому нужен список суффиксов, тот
--- даёт его сам — `helper.suffixes`.
---@param name string Имя группы
---@param module_name string Какой модуль пакета проверяется
---@return table g Группа luatest
---@return table ctx Поля module и clock, обновляемые перед проверкой
function helper.group(name, module_name)
    local g = t.group(name)
    local ctx = {}

    g.before_each(function()
        ctx.module = testing.load_sources(helper.MODULES, module_name)
        ctx.clock = testing.clock()
        testing.module('tnt.cookie.jar')._set_source({ clock = ctx.clock })
        testing.module('tnt.cookie.suffix')._set_source({ load = (helper.loader(nil)) })
    end)

    g.after_each(function()
        testing.unload_sources(helper.MODULES)
    end)

    return g, ctx
end

--- Уже загруженный соседний модуль пакета.
helper.part = testing.module

--- Атрибуты собранного заголовка без пары «имя=значение».
---
--- Порядок атрибутов постоянный, и проверять его надо целиком: набор
--- из тех же слов в другом порядке — это другой заголовок.
---@param header string|nil
---@return string[]
function helper.attributes(header)
    local found = {}

    for piece in ((header or '') .. ';'):gmatch('([^;]*);') do
        table.insert(found, (piece:gsub('^ ', '')))
    end

    table.remove(found, 1)

    return found
end

return helper
