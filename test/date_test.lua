--- Проверки дат в куках.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_date', 'tnt.cookie.date')

--- Шестое ноября 1994 года, 08:49:37 UTC — дата из примеров RFC 9110.
local SAMPLE = 784111777

--- Разобранная дата: пишется в каждой второй проверке.
---@param text string
---@return number|nil
local function parsed(text)
    return ctx.module.parse(text)
end

g.test_all_three_ways_of_writing_a_date_give_one_moment = function()
    t.assert_equals(parsed('Sun, 06 Nov 1994 08:49:37 GMT'), SAMPLE)
    t.assert_equals(parsed('Sunday, 06-Nov-94 08:49:37 GMT'), SAMPLE)
    t.assert_equals(parsed('Sun Nov  6 08:49:37 1994'), SAMPLE)
end

g.test_the_year_is_found_wherever_it_stands = function()
    t.assert_equals(parsed('Sun, 06 Nov 08:49:37 1994'), SAMPLE)
end

g.test_four_digits_are_a_year_and_not_a_day_of_month = function()
    -- Без разбора «день кончился» число 1994 сошло бы за девятнадцатое.
    t.assert_equals(parsed('Nov 1994 06 08:49:37'), SAMPLE)
end

g.test_three_digits_are_no_day_of_month_either = function()
    -- День месяца — одна цифра или две, и на этом число обязано кончиться:
    -- иначе 123 стало бы двенадцатым числом, а хвост потерялся бы молча.
    t.assert_equals(parsed('123 Jan 1994 00:00:00 GMT'), nil)
end

g.test_every_month_is_known_by_its_first_three_letters = function()
    local months = {
        'January',
        'February',
        'March',
        'April',
        'May',
        'June',
        'July',
        'August',
        'September',
        'October',
        'November',
        'December',
    }
    local starts = {}

    for _, month in ipairs(months) do
        table.insert(starts, parsed(('01 %s 2021 00:00:00 GMT'):format(month)))
    end

    t.assert_equals(starts, {
        1609459200,
        1612137600,
        1614556800,
        1617235200,
        1619827200,
        1622505600,
        1625097600,
        1627776000,
        1630454400,
        1633046400,
        1635724800,
        1638316800,
    })
end

g.test_two_digit_years_split_at_seventy = function()
    t.assert_equals(parsed('01 Jan 69 00:00:00 GMT'), 3124224000)
    t.assert_equals(parsed('01 Jan 70 00:00:00 GMT'), 0)
    t.assert_equals(parsed('01 Jan 99 00:00:00 GMT'), 915148800)
    t.assert_equals(parsed('01 Jan 00 00:00:00 GMT'), 946684800)
end

g.test_a_three_digit_year_is_taken_as_it_is_written = function()
    -- 100 — это сотый год, а не двухтысячный, и в куке его быть не может.
    t.assert_equals(parsed('01 Jan 100 00:00:00 GMT'), nil)
end

g.test_the_count_of_years_starts_at_sixteen_hundred_and_one = function()
    t.assert_equals(parsed('01 Jan 1600 00:00:00 GMT'), nil)
    t.assert_equals(parsed('01 Jan 1601 00:00:00 GMT'), -11644473600)
end

g.test_a_leap_second_is_not_a_time_a_cookie_can_expire_at = function()
    t.assert_equals(parsed('06 Nov 1994 08:49:59 GMT'), SAMPLE + 22)
    t.assert_equals(parsed('06 Nov 1994 08:49:60 GMT'), nil)
end

g.test_a_date_without_all_four_parts_is_not_a_date = function()
    t.assert_equals(parsed('Nov 1994 08:49:37 GMT'), nil)
    t.assert_equals(parsed('06 1994 08:49:37 GMT'), nil)
    t.assert_equals(parsed('06 Nov 1994 GMT'), nil)
    t.assert_equals(parsed('06 Nov 08:49:37 GMT'), nil)
end

g.test_a_day_that_never_happened_is_not_a_date = function()
    t.assert_equals(parsed('30 Feb 1994 08:49:37 GMT'), nil)
    t.assert_equals(parsed('32 Jan 1994 08:49:37 GMT'), nil)
    t.assert_equals(parsed('00 Jan 1994 08:49:37 GMT'), nil)
    t.assert_equals(parsed('01 Jan 1994 24:00:00 GMT'), nil)
    t.assert_equals(parsed('01 Jan 1994 00:60:00 GMT'), nil)
end

g.test_nothing_but_a_string_is_a_date = function()
    t.assert_equals(ctx.module.parse(SAMPLE), nil)
    t.assert_equals(ctx.module.parse(nil), nil)
    t.assert_equals(parsed('позавчера'), nil)
    t.assert_equals(parsed(''), nil)
end

g.test_a_written_date_is_read_back_the_same = function()
    t.assert_equals(ctx.module.format(SAMPLE), 'Sun, 06 Nov 1994 08:49:37 GMT')
    t.assert_equals(ctx.module.format(0), 'Thu, 01 Jan 1970 00:00:00 GMT')
    t.assert_equals(parsed(ctx.module.format(SAMPLE)), SAMPLE)
end

g.test_a_date_is_written_only_within_the_years_a_browser_reads = function()
    -- Раньше 1601 года дат нет по RFC 6265, позже 9999-го год пятизначный:
    -- такую дату браузер пропустит молча, и кука станет сеансовой.
    t.assert_equals(ctx.module.check(-11644473600), true)
    t.assert_equals(ctx.module.check(253402300799), true)
    t.assert_equals({ ctx.module.check(-11644473601) }, {
        false,
        'срок куки expires должен лежать между -11644473600 и 253402300799 — в 1601—9999 годах, '
            .. 'а не -11644473601: другой год не записать датой, которую прочтёт браузер',
    })
    t.assert_equals({ ctx.module.check(253402300800) }, {
        false,
        'срок куки expires должен лежать между -11644473600 и 253402300799 — в 1601—9999 годах, '
            .. 'а не 253402300800: другой год не записать датой, которую прочтёт браузер',
    })
end

g.test_the_edges_of_the_written_years_are_read_back = function()
    t.assert_equals(ctx.module.format(-11644473600), 'Mon, 01 Jan 1601 00:00:00 GMT')
    t.assert_equals(ctx.module.format(253402300799), 'Fri, 31 Dec 9999 23:59:59 GMT')
    t.assert_equals(parsed(ctx.module.format(-11644473600)), -11644473600)
    t.assert_equals(parsed(ctx.module.format(253402300799)), 253402300799)
end
