--- Проверки фасада пакета кук.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie', 'tnt.cookie')

--- Отказ настройки; согласие на этом месте — ошибка самой проверки.
---@param opts table
---@return string
local function refusal(opts)
    local ok, err = pcall(ctx.module.configure, opts)

    t.assert_equals(ok, false)

    return tostring(err)
end

g.test_a_cookie_out_of_the_box_hides_from_scripts_and_from_other_sites = function()
    t.assert_equals(ctx.module.set('sid', 'abc'), 'sid=abc; Path=/; SameSite=Lax; Secure; HttpOnly')
end

g.test_every_safe_default_goes_off_by_a_word = function()
    local header = ctx.module.set('sid', 'abc', {
        secure = false,
        http_only = false,
        same_site = 'off',
        path = '/admin',
    })

    t.assert_equals(header, 'sid=abc; Path=/admin')
end

g.test_settings_of_the_package_become_defaults_of_every_cookie = function()
    ctx.module.configure({ domain = 'example.org', max_age = 60, same_site = 'strict' })

    t.assert_equals(
        helper.attributes(ctx.module.set('sid', 'abc')),
        { 'Max-Age=60', 'Domain=example.org', 'Path=/', 'SameSite=Strict', 'Secure', 'HttpOnly' }
    )
end

g.test_the_settings_of_one_cookie_beat_the_settings_of_the_package = function()
    ctx.module.configure({ domain = 'example.org', secure = true })

    t.assert_equals(
        helper.attributes(ctx.module.set('sid', 'abc', { domain = 'other.org', secure = false })),
        { 'Domain=other.org', 'Path=/', 'SameSite=Lax', 'HttpOnly' }
    )
end

g.test_a_separate_set_of_cookies_keeps_its_own_settings = function()
    local own = ctx.module.new({ path = '/admin', http_only = false })

    ctx.module.configure({ path = '/' })

    t.assert_equals(own:set('sid', 'abc'), 'sid=abc; Path=/admin; SameSite=Lax; Secure')
    t.assert_equals(ctx.module.set('sid', 'abc'), 'sid=abc; Path=/; SameSite=Lax; Secure; HttpOnly')
end

g.test_the_shared_set_is_made_anew_after_every_setting = function()
    t.assert_equals(ctx.module.default(), ctx.module.default())

    local before = ctx.module.default()

    ctx.module.configure({ path = '/admin' })

    t.assert_not_equals(ctx.module.default(), before)
    t.assert_equals(ctx.module.status().path, '/admin')
end

g.test_a_path_or_a_domain_that_is_not_one_falls_at_startup = function()
    -- Правила те же, что и у отдельной куки, и отказ тот же: узел с такой
    -- настройкой не должен подняться и отвечать испорченными куками.
    t.assert_str_contains(refusal({ path = 'admin' }), 'путь куки должен начинаться с «/»')
    t.assert_str_contains(refusal({ path = '' }), 'путь куки должен начинаться с «/»')
    t.assert_str_contains(refusal({ domain = 'com' }), 'домен куки должен содержать точку')
    t.assert_str_contains(refusal({ path = 42 }), 'путь куки должен быть строкой, а не 42')
end

g.test_a_key_of_one_sign_is_a_key_and_an_empty_one_is_not = function()
    ctx.module.configure({ key = 'x' })

    t.assert_equals(ctx.module.status().signed, true)
    t.assert_str_contains(
        refusal({ key = '' }),
        'ключ подписи должен быть строкой длиной не меньше 1 знака'
    )
end

g.test_the_key_does_not_show_up_even_in_the_refusal = function()
    -- Отказ по настройкам уходит в журнал запуска целиком, и значение
    -- ключа в нём осталось бы навсегда.
    t.assert_str_contains(
        refusal({ key = 42 }),
        'ключ подписи должен быть строкой длиной не меньше 1 знака, а не присланным значением'
    )
end

g.test_a_setting_with_a_typo_falls_at_startup = function()
    t.assert_str_contains(refusal({ same_site = 'maybe' }), 'признак SameSite')
    t.assert_str_contains(refusal({ htpp_only = true }), 'неизвестная настройка')
    t.assert_str_contains(refusal({ max_age = 'много' }), 'время жизни куки')
end

g.test_the_state_tells_everything_but_the_key = function()
    ctx.module.configure({ key = 'секрет', domain = 'example.org', partitioned = false })

    local state = ctx.module.status()

    t.assert_equals(state, {
        path = '/',
        domain = 'example.org',
        expires = nil,
        max_age = nil,
        secure = true,
        http_only = true,
        same_site = 'lax',
        partitioned = false,
        signed = true,
    })
end

g.test_the_state_says_when_nothing_is_signed = function()
    t.assert_equals(ctx.module.status().signed, false)
end

g.test_forgetting_a_cookie_needs_the_same_path_as_setting_it = function()
    ctx.module.configure({ path = '/admin', secure = false, same_site = 'off', http_only = false })

    t.assert_equals(ctx.module.expire('sid'), 'sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/admin')
end

g.test_the_configured_key_signs_and_opens_the_value = function()
    ctx.module.configure({ key = 'секрет' })

    local signed = ctx.module.sign('42')

    t.assert_equals(ctx.module.unsign(signed), '42')
    t.assert_equals(ctx.module.set('sid', signed), ('sid=%s; Path=/; SameSite=Lax; Secure; HttpOnly'):format(signed))
end

g.test_a_key_given_on_the_spot_beats_the_configured_one = function()
    ctx.module.configure({ key = 'секрет' })

    local signed = ctx.module.sign('42', 'другой')

    t.assert_equals(ctx.module.unsign(signed), nil)
    t.assert_equals(ctx.module.unsign(signed, 'другой'), '42')
end

g.test_signing_without_any_key_at_all_is_refused_out_loud = function()
    local ok, err = pcall(ctx.module.sign, '42')

    t.assert_equals(ok, false)
    t.assert_str_contains(tostring(err), 'задайте ключ настройкой key')
end

g.test_reading_a_request_and_a_response_goes_through_the_facade = function()
    t.assert_equals(ctx.module.parse('sid=abc; theme=dark'), { sid = 'abc', theme = 'dark' })
    t.assert_equals(ctx.module.parse_set('sid=abc; Secure').secure, true)
    t.assert_equals(ctx.module.new():parse('sid=abc'), { sid = 'abc' })
    t.assert_equals(ctx.module.new():parse_set('sid=abc').value, 'abc')
end

g.test_every_jar_is_its_own = function()
    local first = ctx.module.jar()
    local second = ctx.module.new():jar()

    t.assert_equals(first:put('https://example.org/', 'sid=abc'), true)
    t.assert_equals(first:header_for('https://example.org/'), 'sid=abc')
    t.assert_equals(second:header_for('https://example.org/'), nil)
end

g.test_a_date_no_browser_reads_falls_at_startup_and_not_at_every_cookie = function()
    t.assert_str_contains(refusal({ expires = 1e18 }), 'срок куки expires должен лежать между')

    -- Упавшая настройка не действует: общий набор остался прежним.
    t.assert_equals(ctx.module.set('sid', 'abc'), 'sid=abc; Path=/; SameSite=Lax; Secure; HttpOnly')
end

g.test_a_date_of_the_package_goes_into_every_cookie = function()
    ctx.module.configure({ expires = 784111777, secure = false, http_only = false, same_site = 'off' })

    t.assert_equals(ctx.module.set('sid', 'abc'), 'sid=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT; Path=/')
end

--- Где стоит отказ, брошенный из чанка с выдуманным именем файла.
---
--- Отказ обязан показывать на вызывающего — имя чанка и его строку,
--- а не строку внутри пакета: чинить надо настройку там.
---@param code string Тело чанка; пакет в нём зовётся `cookie`
---@return string|nil place Имя и строка перед текстом отказа
---@return string err Отказ целиком
local function thrown_from(code)
    local chunk = assert(load('local cookie = ...\n' .. code, '=caller.lua'))
    local ok, err = pcall(chunk, ctx.module)

    t.assert_equals(ok, false)

    return tostring(err):match('^(caller%.lua:%d+): '), tostring(err)
end

g.test_a_setting_refusal_points_at_the_line_that_configured = function()
    local place, err = thrown_from("cookie.configure({ path = 'admin' })")

    t.assert_equals(place, 'caller.lua:2')
    t.assert_str_contains(err, 'путь куки должен начинаться с «/»')

    place, err = thrown_from("\ncookie.configure({ domain = 'com' })")
    t.assert_equals(place, 'caller.lua:3')
    t.assert_str_contains(err, 'домен куки должен содержать точку')

    place, err = thrown_from('cookie.configure({ expires = 1e18 })')
    t.assert_equals(place, 'caller.lua:2')
    t.assert_str_contains(err, 'срок куки expires должен лежать между')

    place, err = thrown_from('cookie.configure({ htpp_only = true })')
    t.assert_equals(place, 'caller.lua:2')
    t.assert_str_contains(err, 'неизвестная настройка')
end

g.test_a_refusal_of_a_separate_set_points_at_the_line_that_made_it = function()
    local place, err = thrown_from("cookie.new({ path = 'admin' })")

    t.assert_equals(place, 'caller.lua:2')
    t.assert_str_contains(err, 'путь куки должен начинаться с «/»')

    place, err = thrown_from("cookie.new({ same_site = 'maybe' })")
    t.assert_equals(place, 'caller.lua:2')
    t.assert_str_contains(err, 'признак SameSite')
end

g.test_signing_without_a_key_points_at_the_line_that_signed = function()
    local expected =
        'caller.lua:2: подписать куку нечем: задайте ключ настройкой key'

    t.assert_equals(select(2, thrown_from("cookie.sign('42')")), expected)
    t.assert_equals(select(2, thrown_from("cookie.new():sign('42')")), expected)
    t.assert_equals(select(2, thrown_from("cookie.unsign('42.x')")), expected)
    t.assert_equals(select(2, thrown_from("cookie.new():unsign('42.x')")), expected)
end

g.test_signing_what_is_not_a_string_points_at_the_line_that_signed = function()
    ctx.module.configure({ key = 'секрет' })

    local expected = 'caller.lua:2: подписать можно строку, а не number'

    t.assert_equals(select(2, thrown_from('cookie.sign(42)')), expected)
    t.assert_equals(select(2, thrown_from("cookie.new({ key = 'k' }):sign(42)")), expected)
end

g.test_a_separate_set_signs_with_its_own_key = function()
    local own = ctx.module.new({ key = 'свой' })

    ctx.module.configure({ key = 'общий' })

    local signed = own:sign('42')
    local unsigned =
        { nil, 'в значении нет подписи: она отделяется точкой в конце' }

    t.assert_equals(signed, helper.part('tnt.cookie.sign').make('42', 'свой'))
    t.assert_equals(own:unsign(signed), '42')
    t.assert_equals(ctx.module.unsign(signed), nil)
    t.assert_equals({ own:unsign('42') }, unsigned)
    t.assert_equals({ ctx.module.unsign('42') }, unsigned)
end
