--- Живая проверка списка публичных суффиксов на системной libpsl.
---
--- Двойник показывает, что модуль правильно спрашивает список. Верны ли
--- сами объявления FFI — имена символов, подписи, NULL вместо пути
--- к файлу, — видно только на настоящей библиотеке. Нет её на машине —
--- проверки пропускаются: libpsl необязательна.

local ffi = require('ffi')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_suffix_live', 'tnt.cookie.suffix')

--- Стоит ли libpsl на машине.
---
--- Имена свои, а не модуля: поломка списка имён в модуле обязана ронять
--- проверку, а не пропускать её.
---@return boolean
local function installed()
    for _, name in ipairs({ 'psl', 'libpsl.so.5' }) do
        if pcall(ffi.load, name) then
            return true
        end
    end

    return false
end

--- Настоящая загрузка вместо двойника; библиотеки нет — пропуск.
local function real()
    t.skip_if(
        not installed(),
        'libpsl на машине нет: список суффиксов проверять не на чем'
    )
    ctx.module._set_source(nil)
end

g.test_the_real_list_knows_a_country_zone_and_a_hosting_zone = function()
    real()

    t.assert_equals(ctx.module.is_public('co.uk'), true)
    t.assert_equals(ctx.module.is_public('github.io'), true)
    t.assert_equals(ctx.module.is_public('example.org'), false)
    t.assert_equals(ctx.module.is_public('example.co.uk'), false)
end

g.test_the_real_list_sees_a_suffix_behind_a_dot_at_the_end = function()
    real()

    t.assert_equals(ctx.module.is_public('co.uk.'), true)
end

g.test_the_real_list_keeps_a_cookie_off_a_whole_zone = function()
    real()

    local ok, err = helper.part('tnt.cookie.jar').new():put('https://evil.co.uk/', 'sid=x; Domain=co.uk')

    t.assert_equals(ok, false)
    t.assert_equals(
        err,
        'домен «co.uk» — публичный суффикс: под ним живут чужие друг другу узлы, и кука ушла бы ко всем'
    )
end
