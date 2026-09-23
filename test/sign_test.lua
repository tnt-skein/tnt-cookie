--- Проверки подписи значения куки.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_sign', 'tnt.cookie.sign')

--- Ключ подписи в проверках.
local KEY = 'секрет'

--- Подпись, в которой подменён один знак.
---@param signed string Значение с подписью
---@param at integer Место знака в подписи, от начала или от конца
---@return string
local function twisted(signed, at)
    local border = assert(signed:find('%.[^.]*$'), 'подписи нет')
    local signature = signed:sub(border + 1)
    local place = at

    if place < 0 then
        place = #signature + place + 1
    end

    local char = signature:sub(place, place) == 'a' and 'b' or 'a'

    return ('%s%s%s'):format(signed:sub(1, border + place - 1), char, signature:sub(place + 1))
end

g.test_a_signed_value_opens_back_into_itself = function()
    local signed = ctx.module.make('42', KEY)

    t.assert_equals(signed:match('^42%.'), '42.')
    t.assert_equals(ctx.module.open(signed, KEY), '42')
end

g.test_the_signature_is_the_same_one_every_time = function()
    -- Значение подписи закреплено нарочно: сменить способ подписи молча
    -- значит разом разлогинить всех, у кого кука уже лежит.
    t.assert_equals(ctx.module.make('42', 'ключ'), '42.vm8lAAuedhyXp_48ZRDjDbQ0NLlF_LsoyVEl0FCjTio')
end

g.test_the_signature_holds_only_the_signs_a_cookie_allows = function()
    t.assert_equals(ctx.module.make('42', KEY):match('^42%.[%w%-_]+$') ~= nil, true)
end

g.test_a_value_with_dots_of_its_own_still_opens = function()
    t.assert_equals(ctx.module.open(ctx.module.make('a.b.c', KEY), KEY), 'a.b.c')
end

g.test_a_rewritten_value_does_not_open = function()
    local signed = ctx.module.make('42', KEY)
    local value, err = ctx.module.open(signed:gsub('^42', '43'), KEY)

    t.assert_equals(value, nil)
    t.assert_equals(
        err,
        'подпись значения не сошлась: значение переписано или ключ не тот'
    )
end

g.test_another_key_does_not_open_the_value = function()
    t.assert_equals(ctx.module.open(ctx.module.make('42', KEY), 'другой'), nil)
end

g.test_a_signature_off_by_one_sign_does_not_open_wherever_that_sign_is = function()
    -- И первый знак, и последний: сравнение, бросающее работу на первом
    -- несовпадении, отвечает не «сошлось ли», а «сколько сошлось».
    local signed = ctx.module.make('42', KEY)

    t.assert_equals(ctx.module.open(twisted(signed, 1), KEY), nil)
    t.assert_equals(ctx.module.open(twisted(signed, -1), KEY), nil)
end

g.test_a_signature_of_another_length_does_not_open = function()
    local signed = ctx.module.make('42', KEY)

    t.assert_equals(ctx.module.open(signed .. 'x', KEY), nil)
    t.assert_equals(ctx.module.open(signed:sub(1, -2), KEY), nil)
end

g.test_a_value_without_a_signature_does_not_open = function()
    local value, err = ctx.module.open('42', KEY)

    t.assert_equals(value, nil)
    t.assert_equals(
        err,
        'в значении нет подписи: она отделяется точкой в конце'
    )
end

g.test_an_empty_signature_is_a_signature_that_did_not_match = function()
    -- Точка есть, подписи за ней нет: это переписанная кука, а не кука
    -- без подписи, и сказать об этом надо именно так.
    local value, err = ctx.module.open('42.', KEY)

    t.assert_equals(value, nil)
    t.assert_equals(
        err,
        'подпись значения не сошлась: значение переписано или ключ не тот'
    )
end

g.test_an_empty_value_is_signed_and_opened_like_any_other = function()
    t.assert_equals(ctx.module.open(ctx.module.make('', KEY), KEY), '')
end

g.test_only_a_string_carries_a_signature = function()
    local value, err = ctx.module.open(42, KEY)

    t.assert_equals(value, nil)
    t.assert_equals(err, 'подписанное значение должно быть строкой, а не number')
end

g.test_signing_without_a_key_is_refused_out_loud = function()
    local ok, err = pcall(ctx.module.make, '42', nil)

    t.assert_equals(ok, false)
    t.assert_str_contains(
        tostring(err),
        'подписать куку нечем: задайте ключ настройкой key'
    )

    t.assert_equals((pcall(ctx.module.make, '42', '')), false)
    t.assert_equals((pcall(ctx.module.open, '42.x', nil)), false)
end

g.test_only_a_string_can_be_signed = function()
    local ok, err = pcall(ctx.module.make, 42, KEY)

    t.assert_equals(ok, false)
    t.assert_str_contains(tostring(err), 'подписать можно строку, а не number')
end

--- Отказ, брошенный из чанка с выдуманным именем файла.
---@param code string Тело чанка; модуль подписи в нём зовётся `sign`
---@return string
local function thrown_from(code)
    local chunk = assert(load('local sign = ...\n' .. code, '=caller.lua'))
    local ok, err = pcall(chunk, ctx.module)

    t.assert_equals(ok, false)

    return tostring(err)
end

g.test_a_refusal_points_at_the_line_that_asked_for_a_signature = function()
    -- Место — строка вызывающего: чинить надо его ключ или его вызов,
    -- а не строку внутри пакета.
    local no_key = 'подписать куку нечем: задайте ключ настройкой key'

    t.assert_equals(thrown_from("sign.make('42', nil)"), 'caller.lua:2: ' .. no_key)
    t.assert_equals(thrown_from("\nsign.open('42.x', '')"), 'caller.lua:3: ' .. no_key)
    t.assert_equals(
        thrown_from("sign.make(42, 'k')"),
        'caller.lua:2: подписать можно строку, а не number'
    )
end

g.test_a_level_given_points_further_up = function()
    -- Фасад зовёт подпись через свои кадры и называет уровень сам: виноват
    -- тот, кто позвал обёртку, а не строка в ней.
    local wrapped = table.concat({
        'local function signed(value, key)',
        '    sign.make(value, key, 2)',
        'end',
        '',
        'local function opened(text, key)',
        '    sign.open(text, key, 2)',
        'end',
        '',
        '%s',
    }, '\n')
    local no_key = 'подписать куку нечем: задайте ключ настройкой key'

    t.assert_equals(thrown_from(wrapped:format("signed('42', nil)")), 'caller.lua:10: ' .. no_key)
    t.assert_equals(
        thrown_from(wrapped:format("signed(42, 'k')")),
        'caller.lua:10: подписать можно строку, а не number'
    )
    t.assert_equals(thrown_from(wrapped:format("opened('42.x', nil)")), 'caller.lua:10: ' .. no_key)
end
