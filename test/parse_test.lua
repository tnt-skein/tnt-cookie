--- Проверки разбора заголовков куки.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_parse', 'tnt.cookie.parse')

--- Разобранный `Set-Cookie:`; отказ на этом месте — ошибка самой проверки.
---@param text string
---@return TntCookieSet
local function taken(text)
    local cookie, err = ctx.module.set_cookie(text)

    t.assert_equals(err, nil)

    return (assert(cookie, 'кука не разобралась'))
end

--- Причина отказа разбора `Set-Cookie:`.
---@param text any
---@return string
local function refusal(text)
    local cookie, err = ctx.module.set_cookie(text)

    t.assert_equals(cookie, nil)

    return (assert(err, 'отказ есть, а причины нет'))
end

g.test_a_request_header_becomes_a_table_of_names_and_values = function()
    t.assert_equals(ctx.module.header('sid=abc; theme=dark'), { sid = 'abc', theme = 'dark' })
end

g.test_spaces_around_the_pair_go_and_spaces_inside_the_value_stay = function()
    t.assert_equals(ctx.module.header('  sid = a b  '), { sid = 'a b' })
end

g.test_a_value_may_hold_the_padding_of_base_sixty_four = function()
    t.assert_equals(ctx.module.header('sid=YWJj=='), { sid = 'YWJj==' })
end

g.test_a_quoted_value_arrives_without_its_quotes = function()
    t.assert_equals(ctx.module.header('theme="dark"'), { theme = 'dark' })
end

g.test_the_first_of_the_cookies_with_one_name_wins = function()
    -- Впереди идёт кука самого точного пути; вторая с тем же именем —
    -- либо кука соседнего пути, либо подложенная с поддомена.
    t.assert_equals(ctx.module.header('sid=свой; sid=чужой'), { sid = 'свой' })
end

g.test_junk_beside_a_cookie_does_not_take_the_cookie_down = function()
    t.assert_equals(ctx.module.header('junk; =empty; bad name=1; sid=abc; ;'), { sid = 'abc' })
end

g.test_a_header_that_is_not_a_string_gives_nothing = function()
    t.assert_equals(ctx.module.header(nil), {})
    t.assert_equals(ctx.module.header(42), {})
    t.assert_equals(ctx.module.header(''), {})
end

g.test_a_response_header_gives_the_pair_and_every_attribute = function()
    local cookie = taken(
        'sid=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT; Max-Age=60; '
            .. 'Domain=example.org; Path=/admin; Secure; HttpOnly; SameSite=Strict; Partitioned'
    )

    t.assert_equals(cookie.name, 'sid')
    t.assert_equals(cookie.value, 'abc')
    t.assert_equals(cookie.expires, 784111777)
    t.assert_equals(cookie.max_age, 60)
    t.assert_equals(cookie.domain, 'example.org')
    t.assert_equals(cookie.path, '/admin')
    t.assert_equals(cookie.secure, true)
    t.assert_equals(cookie.http_only, true)
    t.assert_equals(cookie.same_site, 'strict')
    t.assert_equals(cookie.partitioned, true)
end

g.test_a_bare_pair_has_no_attributes_at_all = function()
    local cookie = taken('sid=abc')

    t.assert_equals(cookie.secure, false)
    t.assert_equals(cookie.http_only, false)
    t.assert_equals(cookie.partitioned, false)
    t.assert_equals(cookie.same_site, nil)
    t.assert_equals(cookie.domain, nil)
    t.assert_equals(cookie.path, nil)
    t.assert_equals(cookie.expires, nil)
    t.assert_equals(cookie.max_age, nil)
end

g.test_attribute_names_are_read_regardless_of_their_case = function()
    local cookie = taken('sid=abc; PATH=/a; secure; HTTPONLY; samesite=LAX')

    t.assert_equals(cookie.path, '/a')
    t.assert_equals(cookie.secure, true)
    t.assert_equals(cookie.http_only, true)
    t.assert_equals(cookie.same_site, 'lax')
end

g.test_an_unknown_attribute_is_stepped_over = function()
    local cookie = taken('sid=abc; Priority=High; Path=/a; =nameless')

    t.assert_equals(cookie.path, '/a')
end

g.test_the_leading_dot_of_a_domain_goes_and_the_case_goes_down = function()
    t.assert_equals(taken('sid=abc; Domain=.Example.ORG').domain, 'example.org')
end

g.test_an_empty_domain_is_the_same_as_no_domain = function()
    t.assert_equals(taken('sid=abc; Domain=').domain, nil)
end

g.test_a_path_not_starting_at_the_root_is_dropped = function()
    t.assert_equals(taken('sid=abc; Path=admin').path, nil)
    t.assert_equals(taken('sid=abc; Path=').path, nil)
end

g.test_max_age_may_be_zero_or_negative_because_that_is_how_a_cookie_dies = function()
    t.assert_equals(taken('sid=abc; Max-Age=0').max_age, 0)
    t.assert_equals(taken('sid=abc; Max-Age=-1').max_age, -1)
end

g.test_max_age_that_is_not_a_number_is_dropped = function()
    t.assert_equals(taken('sid=abc; Max-Age=скоро').max_age, nil)
    t.assert_equals(taken('sid=abc; Max-Age=60s').max_age, nil)
    t.assert_equals(taken('sid=abc; Max-Age=').max_age, nil)
end

g.test_a_broken_max_age_does_not_wipe_the_one_before_it = function()
    -- Пропустить атрибут — значит оставить всё как было, а не обнулить:
    -- последним считается последний понятый (RFC 6265, 5.3, шаг 3).
    t.assert_equals(taken('sid=abc; Max-Age=60; Max-Age=').max_age, 60)
    t.assert_equals(taken('sid=abc; Max-Age=60; Max-Age=-').max_age, 60)
end

g.test_an_attribute_is_read_with_spaces_on_either_side_of_it = function()
    local cookie = taken('sid=abc;Secure ; HttpOnly; Path = /a ')

    t.assert_equals(cookie.secure, true)
    t.assert_equals(cookie.http_only, true)
    t.assert_equals(cookie.path, '/a')
end

g.test_a_date_that_cannot_be_read_leaves_the_cookie_alive = function()
    local cookie = taken('sid=abc; Expires=позавчера; Path=/a')

    t.assert_equals(cookie.expires, nil)
    t.assert_equals(cookie.path, '/a')
end

g.test_a_same_site_word_nobody_knows_is_not_remembered = function()
    t.assert_equals(taken('sid=abc; SameSite=Maybe').same_site, nil)
    t.assert_equals(taken('sid=abc; SameSite=None').same_site, 'none')
end

g.test_a_response_value_in_quotes_is_remembered_as_such = function()
    local cookie = taken('sid="a b"')

    t.assert_equals(cookie.value, 'a b')
    t.assert_equals(cookie.quoted, true)
end

g.test_a_response_without_a_pair_is_refused = function()
    t.assert_equals(
        refusal('Secure; HttpOnly'),
        'в заголовке Set-Cookie нет пары «имя=значение»'
    )
    t.assert_equals(refusal('=abc'), 'в заголовке Set-Cookie нет пары «имя=значение»')
    t.assert_equals(refusal(''), 'в заголовке Set-Cookie нет пары «имя=значение»')
end

g.test_the_first_pair_is_the_cookie_and_never_an_attribute = function()
    -- Кука с именем Path — законная кука: атрибуты начинаются со второго
    -- куска, каким бы словом ни звался первый.
    local cookie = taken('Path=/a; Path=/b')

    t.assert_equals(cookie.name, 'Path')
    t.assert_equals(cookie.value, '/a')
    t.assert_equals(cookie.path, '/b')
end

g.test_a_response_header_that_is_not_a_string_is_refused = function()
    t.assert_equals(refusal(nil), 'заголовок Set-Cookie должен быть строкой, а не nil')
end
