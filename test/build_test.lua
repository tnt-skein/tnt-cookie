--- Проверки сборки заголовка Set-Cookie.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_build', 'tnt.cookie.build')

--- Настройки без единого умолчания: сборщик их не придумывает.
local BARE = { path = nil, secure = false, http_only = false, partitioned = false }

--- Настройки поверх голых.
---@param overrides table
---@return table
local function with(overrides)
    local options = {}

    for key, value in pairs(BARE) do
        options[key] = value
    end

    for key, value in pairs(overrides) do
        options[key] = value
    end

    return options
end

--- Собранный заголовок; отказ на этом месте — ошибка самой проверки.
---@param name string
---@param value string
---@param overrides table|nil
---@return string
local function built(name, value, overrides)
    local header, err = ctx.module.set(name, value, with(overrides or {}))

    t.assert_equals(err, nil)

    return (assert(header, 'заголовок не собрался'))
end

--- Причина отказа сборки.
---@param name any
---@param value any
---@param overrides table|nil
---@return string
local function refusal(name, value, overrides)
    local header, err = ctx.module.set(name, value, with(overrides or {}))

    t.assert_equals(header, nil)

    return (assert(err, 'отказ есть, а причины нет'))
end

g.test_a_bare_cookie_is_a_pair_and_nothing_else = function()
    t.assert_equals(built('sid', 'abc'), 'sid=abc')
    t.assert_equals(built('sid', ''), 'sid=')
end

g.test_attributes_go_in_one_and_the_same_order = function()
    local header = built('sid', 'abc', {
        expires = 784111777,
        max_age = 60,
        domain = 'example.org',
        path = '/admin',
        same_site = 'lax',
        secure = true,
        http_only = true,
        partitioned = true,
    })

    t.assert_equals(helper.attributes(header), {
        'Expires=Sun, 06 Nov 1994 08:49:37 GMT',
        'Max-Age=60',
        'Domain=example.org',
        'Path=/admin',
        'SameSite=Lax',
        'Secure',
        'HttpOnly',
        'Partitioned',
    })
end

g.test_every_same_site_word_has_its_own_spelling = function()
    t.assert_equals(helper.attributes(built('a', 'b', { same_site = 'strict' })), { 'SameSite=Strict' })
    t.assert_equals(helper.attributes(built('a', 'b', { same_site = 'lax' })), { 'SameSite=Lax' })
    t.assert_equals(
        helper.attributes(built('a', 'b', { same_site = 'none', secure = true })),
        { 'SameSite=None', 'Secure' }
    )
end

g.test_a_dead_cookie_carries_a_zero_and_a_date_from_the_past = function()
    t.assert_equals(
        helper.attributes(built('sid', '', { expires = 0, max_age = 0 })),
        { 'Expires=Thu, 01 Jan 1970 00:00:00 GMT', 'Max-Age=0' }
    )
end

g.test_a_lifetime_may_be_an_odd_number_of_seconds = function()
    t.assert_equals(helper.attributes(built('a', 'b', { max_age = 15 })), { 'Max-Age=15' })
end

g.test_a_name_or_a_value_with_a_separator_in_it_is_refused = function()
    t.assert_str_contains(
        refusal('a b', 'x'),
        'в имени куки недопустим знак « » на месте 2'
    )
    t.assert_str_contains(
        refusal('sid', 'a;b'),
        'в значении куки недопустим знак «;» на месте 2'
    )
end

g.test_a_path_or_a_domain_that_is_not_one_is_refused = function()
    t.assert_str_contains(refusal('sid', 'x', { path = 'admin' }), 'должен начинаться с «/»')
    t.assert_str_contains(refusal('sid', 'x', { domain = 'com' }), 'должен содержать точку')
end

g.test_seconds_are_whole_seconds = function()
    t.assert_equals(
        refusal('sid', 'x', { expires = 1.5 }),
        'срок куки expires должен задаваться целым числом секунд'
    )
    t.assert_equals(
        refusal('sid', 'x', { max_age = '60' }),
        'время жизни куки max_age должно задаваться целым числом секунд'
    )
end

g.test_a_same_site_word_nobody_knows_is_refused = function()
    t.assert_equals(
        refusal('sid', 'x', { same_site = 'maybe' }),
        'признак SameSite бывает strict, lax, none или off, а не «maybe»'
    )
end

g.test_a_cookie_that_goes_to_other_sites_must_go_over_tls = function()
    t.assert_equals(
        refusal('sid', 'x', { same_site = 'none' }),
        'кука с SameSite=none ходит на чужие сайты и потому обязана быть secure = true'
    )
end

g.test_a_partitioned_cookie_must_go_over_tls = function()
    t.assert_equals(
        refusal('sid', 'x', { partitioned = true }),
        'кука с признаком partitioned обязана быть secure = true'
    )
end

g.test_the_host_prefix_demands_tls_the_root_path_and_no_domain = function()
    t.assert_equals(
        refusal('__Host-sid', 'x', { path = '/' }),
        'кука с приставкой __Host- ставится только по HTTPS: нужен secure = true'
    )
    t.assert_equals(
        refusal('__Host-sid', 'x', { path = '/', secure = true, domain = 'example.org' }),
        'кука с приставкой __Host- принадлежит одному узлу: домен задавать нельзя'
    )
    t.assert_equals(
        refusal('__Host-sid', 'x', { path = '/a', secure = true }),
        'кука с приставкой __Host- видна на всём узле: путь обязан быть «/»'
    )
    t.assert_equals(built('__Host-sid', 'x', { path = '/', secure = true }), '__Host-sid=x; Path=/; Secure')
end

g.test_the_secure_prefix_demands_tls_and_nothing_more = function()
    t.assert_equals(
        refusal('__Secure-sid', 'x'),
        'кука с приставкой __Secure- ставится только по HTTPS: нужен secure = true'
    )
    t.assert_equals(
        built('__Secure-sid', 'x', { secure = true, domain = 'example.org', path = '/a' }),
        '__Secure-sid=x; Domain=example.org; Path=/a; Secure'
    )
end

g.test_a_name_that_only_looks_like_a_prefix_carries_no_promise = function()
    t.assert_equals(built('__Hostile', 'x'), '__Hostile=x')
end

g.test_a_prefix_in_another_case_makes_the_same_promise = function()
    -- Браузер узнаёт приставку без регистра и такую куку выбросит молча.
    t.assert_equals(
        refusal('__HOST-sid', 'x', { path = '/', secure = true, domain = 'example.org' }),
        'кука с приставкой __Host- принадлежит одному узлу: домен задавать нельзя'
    )
    t.assert_equals(
        refusal('__secure-sid', 'x'),
        'кука с приставкой __Secure- ставится только по HTTPS: нужен secure = true'
    )
    t.assert_equals(built('__host-sid', 'x', { path = '/', secure = true }), '__host-sid=x; Path=/; Secure')
end

g.test_a_date_no_browser_reads_is_refused_and_not_thrown = function()
    -- Год за пределами datetime бросил бы посреди сборки, а пятизначный
    -- браузер пропустил бы молча: и то и другое — отказ.
    t.assert_equals(
        refusal('sid', 'x', { expires = 253402300800 }),
        'срок куки expires должен лежать между -11644473600 и 253402300799 — в 1601—9999 годах, '
            .. 'а не 253402300800: другой год не записать датой, которую прочтёт браузер'
    )
    t.assert_str_contains(refusal('sid', 'x', { expires = 1e18 }), 'а не 1e+18')
    t.assert_equals(
        helper.attributes(built('sid', 'x', { expires = 253402300799 })),
        { 'Expires=Fri, 31 Dec 9999 23:59:59 GMT' }
    )
end

g.test_a_date_that_is_not_a_number_is_refused_before_its_years = function()
    t.assert_equals(
        refusal('sid', 'x', { expires = '60' }),
        'срок куки expires должен задаваться целым числом секунд'
    )
end
