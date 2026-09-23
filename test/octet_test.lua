--- Проверки допустимых знаков в частях куки.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_octet', 'tnt.cookie.octet')

--- Отказ названной проверки; успех на этом месте — ошибка самой проверки.
---@param check fun(value: any): boolean, string|nil
---@param value any
---@return string
local function refusal(check, value)
    local ok, err = check(value)

    t.assert_equals(ok, false)

    return (assert(err, 'отказ есть, а причины нет'))
end

g.test_name_takes_letters_digits_and_token_signs = function()
    t.assert_equals(ctx.module.check_name('sid'), true)
    t.assert_equals(ctx.module.check_name('__Host-Session_1'), true)
    t.assert_equals(ctx.module.check_name("!#$%&'*+-.^_`|~"), true)
end

g.test_empty_name_is_refused_by_name = function()
    t.assert_equals(
        refusal(ctx.module.check_name, ''),
        'имя куки пустое: кука без имени не доедет обратно'
    )
end

g.test_name_refusal_points_at_the_very_first_sign = function()
    t.assert_str_contains(
        refusal(ctx.module.check_name, ' sid'),
        'недопустим знак « » на месте 1'
    )
end

g.test_name_refuses_the_signs_that_split_the_header = function()
    t.assert_str_contains(refusal(ctx.module.check_name, 'a=b'), 'знак «=» на месте 2')
    t.assert_str_contains(refusal(ctx.module.check_name, 'a;b'), 'знак «;» на месте 2')
    t.assert_str_contains(refusal(ctx.module.check_name, 'a,b'), 'знак «,» на месте 2')
end

g.test_name_refusal_names_the_byte_when_the_sign_is_not_printable = function()
    t.assert_str_contains(refusal(ctx.module.check_name, 'a\tb'), 'недопустим байт 9 на месте 2')
    t.assert_str_contains(
        refusal(ctx.module.check_name, 'a\127b'),
        'недопустим байт 127 на месте 2'
    )
    t.assert_str_contains(refusal(ctx.module.check_name, 'aж'), 'недопустим байт 208 на месте 2')
end

g.test_name_must_be_a_string = function()
    t.assert_equals(
        refusal(ctx.module.check_name, 42),
        'имя куки должно быть строкой, а не number'
    )
end

g.test_empty_value_is_a_legal_value = function()
    t.assert_equals(ctx.module.check_value(''), true)
end

g.test_value_takes_everything_printable_but_the_separators = function()
    t.assert_equals(ctx.module.check_value('!#$%&()*+-./:<=>?@[]^_`{|}~'), true)
    t.assert_equals(ctx.module.check_value('eyJhbGciOiJIUzI1NiJ9.abc-_'), true)
end

g.test_value_refuses_each_separator_of_the_header = function()
    t.assert_str_contains(refusal(ctx.module.check_value, 'a b'), 'знак « » на месте 2')
    t.assert_str_contains(refusal(ctx.module.check_value, 'a"b'), 'знак «"» на месте 2')
    t.assert_str_contains(refusal(ctx.module.check_value, 'a,b'), 'знак «,» на месте 2')
    t.assert_str_contains(refusal(ctx.module.check_value, 'a;b'), 'знак «;» на месте 2')
    t.assert_str_contains(refusal(ctx.module.check_value, 'a\\b'), 'знак «\\» на месте 2')
end

g.test_value_refusal_tells_what_the_separators_are = function()
    t.assert_str_contains(refusal(ctx.module.check_value, 'a;b'), 'в значении куки недопустим')
    t.assert_str_contains(
        refusal(ctx.module.check_value, 'a;b'),
        'внутри значения их быть не может'
    )
end

g.test_path_starts_at_the_root = function()
    t.assert_equals(ctx.module.check_path('/'), true)
    t.assert_equals(ctx.module.check_path('/admin/panel'), true)
    t.assert_str_contains(refusal(ctx.module.check_path, 'admin'), 'должен начинаться с «/»')
end

g.test_path_refuses_the_sign_that_starts_the_next_attribute = function()
    t.assert_str_contains(
        refusal(ctx.module.check_path, '/a;b'),
        'в пути куки недопустим знак «;» на месте 3'
    )
    t.assert_str_contains(refusal(ctx.module.check_path, '/a\nb'), 'недопустим байт 10 на месте 3')
end

g.test_path_must_be_a_string = function()
    t.assert_equals(
        refusal(ctx.module.check_path, true),
        'путь куки должен быть строкой, а не boolean'
    )
end

g.test_domain_is_a_host_name_with_a_dot_in_it = function()
    t.assert_equals(ctx.module.check_domain('example.org'), true)
    t.assert_equals(ctx.module.check_domain('a-b.example.org'), true)
    t.assert_str_contains(refusal(ctx.module.check_domain, 'com'), 'должен содержать точку')
end

g.test_domain_refuses_what_a_host_name_never_has = function()
    t.assert_str_contains(
        refusal(ctx.module.check_domain, 'a_b.org'),
        'в домене куки недопустим знак «_» на месте 2'
    )
    t.assert_equals(
        refusal(ctx.module.check_domain, nil),
        'домен куки должен быть строкой, а не nil'
    )
end

g.test_quotes_come_off_the_value_and_leave_a_mark = function()
    local bare, quoted = ctx.module.unquote('"dark"')

    t.assert_equals(bare, 'dark')
    t.assert_equals(quoted, true)
end

g.test_value_without_quotes_stays_as_it_is = function()
    local bare, quoted = ctx.module.unquote('dark')

    t.assert_equals(bare, 'dark')
    t.assert_equals(quoted, false)
end

g.test_a_single_quote_is_not_a_pair_of_them = function()
    t.assert_equals((ctx.module.unquote('"')), '"')
    t.assert_equals((ctx.module.unquote('""')), '')
end

g.test_a_prefix_is_found_at_the_start_of_the_name = function()
    t.assert_equals(ctx.module.prefix_of('__Host-sid'), '__Host-')
    t.assert_equals(ctx.module.prefix_of('__Secure-sid'), '__Secure-')
    t.assert_equals(ctx.module.prefix_of('__Host-'), '__Host-')
end

g.test_a_prefix_is_found_regardless_of_its_case = function()
    -- Отдаётся приставка так, как она пишется, а не как в имени.
    t.assert_equals(ctx.module.prefix_of('__HOST-sid'), '__Host-')
    t.assert_equals(ctx.module.prefix_of('__sEcUrE-sid'), '__Secure-')
end

g.test_a_name_only_like_a_prefix_has_none = function()
    t.assert_equals(ctx.module.prefix_of('sid'), nil)
    t.assert_equals(ctx.module.prefix_of('__Hostile'), nil)
    t.assert_equals(ctx.module.prefix_of('__Hostile-sid'), nil)
    t.assert_equals(ctx.module.prefix_of('x__Host-sid'), nil)
    t.assert_equals(ctx.module.prefix_of('_Host-sid'), nil)
    t.assert_equals(ctx.module.prefix_of('__Host_sid'), nil)
end
