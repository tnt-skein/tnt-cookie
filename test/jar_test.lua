--- Проверки хранилища кук для исходящих запросов.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_jar', 'tnt.cookie.jar')

--- Хранилище с уже положенными куками.
---@param url string Откуда пришли куки
---@param ... string Заголовки Set-Cookie
---@return TntCookieJar
local function filled(url, ...)
    local jar = ctx.module.new()

    for _, header in ipairs({ ... }) do
        local ok, err = jar:put(url, header)

        t.assert_equals(err, nil)
        t.assert_equals(ok, true)
    end

    return jar
end

--- Причина отказа положить куку.
---@param url any
---@param header any
---@return string
local function refusal(url, header)
    local ok, err = ctx.module.new():put(url, header)

    t.assert_equals(ok, false)

    return (assert(err, 'отказ есть, а причины нет'))
end

g.test_a_cookie_comes_back_to_the_host_that_set_it = function()
    local jar = filled('https://example.org/', 'sid=abc')

    t.assert_equals(jar:header_for('https://example.org/'), 'sid=abc')
end

g.test_a_host_only_cookie_never_leaves_for_a_subdomain = function()
    -- Без атрибута Domain кука принадлежит ровно поставившему её узлу.
    local jar = filled('https://example.org/', 'sid=abc')

    t.assert_equals(jar:header_for('https://sub.example.org/'), nil)
    t.assert_equals(jar:header_for('https://other.org/'), nil)
end

g.test_a_domain_cookie_reaches_the_subdomains_and_nobody_else = function()
    local jar = filled('https://example.org/', 'sid=abc; Domain=example.org')

    t.assert_equals(jar:header_for('https://example.org/'), 'sid=abc')
    t.assert_equals(jar:header_for('https://deep.sub.example.org/'), 'sid=abc')
    t.assert_equals(jar:header_for('https://notexample.org/'), nil)
end

g.test_a_host_cannot_set_a_cookie_on_a_domain_it_is_not_in = function()
    t.assert_str_contains(
        refusal('https://evil.org/', 'sid=abc; Domain=example.org'),
        'узел «evil.org» не входит в домен «example.org»'
    )
end

g.test_a_whole_zone_is_not_a_domain_for_a_cookie = function()
    t.assert_str_contains(refusal('https://example.org/', 'sid=abc; Domain=org'), 'это зона целиком')
end

g.test_an_address_keeps_its_cookies_to_itself = function()
    -- У адреса 10.0.0.1 суффикс 0.0.1 — не домен, а обрезок числа.
    t.assert_str_contains(refusal('https://10.0.0.1/', 'sid=abc; Domain=0.0.1'), 'не входит в домен')

    local jar = filled('https://10.0.0.1/', 'sid=abc; Domain=10.0.0.1')

    t.assert_equals(jar:header_for('https://10.0.0.1/'), 'sid=abc')
end

g.test_an_address_with_letters_in_it_is_still_an_address = function()
    -- В записи IPv6 ::ffff:1.2.3.4 есть и буквы, и точки, и по одним
    -- только точкам она сошла бы за поддомен зоны 2.3.4.
    t.assert_str_contains(
        refusal('https://[::ffff:1.2.3.4]/', 'sid=abc; Domain=2.3.4'),
        'не входит в домен'
    )
end

g.test_the_host_is_matched_regardless_of_its_case = function()
    local jar = filled('https://Example.ORG/', 'sid=abc; Domain=Example.ORG')

    t.assert_equals(jar:header_for('https://EXAMPLE.org/'), 'sid=abc')
end

g.test_a_cookie_takes_the_folder_of_the_request_as_its_path = function()
    local jar = filled('https://example.org/a/b/c', 'sid=abc')

    t.assert_equals(jar:header_for('https://example.org/a/b/other'), 'sid=abc')
    t.assert_equals(jar:header_for('https://example.org/a/'), nil)
end

g.test_a_request_without_a_folder_puts_the_cookie_at_the_root = function()
    t.assert_equals(filled('https://example.org/a', 'sid=abc'):header_for('https://example.org/z'), 'sid=abc')
    t.assert_equals(filled('https://example.org', 'sid=abc'):header_for('https://example.org/z'), 'sid=abc')
end

g.test_a_path_matches_by_folders_and_not_by_letters = function()
    local jar = filled('https://example.org/', 'sid=abc; Path=/foo')

    t.assert_equals(jar:header_for('https://example.org/foo'), 'sid=abc')
    t.assert_equals(jar:header_for('https://example.org/foo/bar'), 'sid=abc')
    t.assert_equals(jar:header_for('https://example.org/foobar'), nil)
end

g.test_a_path_that_already_ends_in_a_slash_is_not_given_another = function()
    local jar = filled('https://example.org/', 'sid=abc; Path=/foo/')

    t.assert_equals(jar:header_for('https://example.org/foo/bar'), 'sid=abc')
end

g.test_a_request_ending_in_a_slash_is_already_a_folder = function()
    -- Каталог запроса /a/b/ — это /a/b, а не /a: последняя косая тут
    -- не отделяет имя ресурса, потому что имени за ней нет.
    local jar = filled('https://example.org/a/b/', 'sid=abc')

    t.assert_equals(jar:header_for('https://example.org/a/b'), 'sid=abc')
    t.assert_equals(jar:header_for('https://example.org/a/b/x'), 'sid=abc')
    t.assert_equals(jar:header_for('https://example.org/a/x'), nil)
end

g.test_the_signs_of_a_path_are_letters_and_not_a_pattern = function()
    local jar = filled('https://example.org/', 'sid=abc; Path=/a+b')

    t.assert_equals(jar:header_for('https://example.org/a+b/c'), 'sid=abc')
    t.assert_equals(jar:header_for('https://example.org/aab/c'), nil)
end

g.test_a_secure_cookie_does_not_travel_in_the_open = function()
    local jar = filled('https://example.org/', 'sid=abc; Secure', 'theme=dark')

    t.assert_equals(jar:header_for('https://example.org/'), 'sid=abc; theme=dark')
    t.assert_equals(jar:header_for('http://example.org/'), 'theme=dark')
end

g.test_a_websocket_over_tls_counts_as_a_safe_way_too = function()
    -- Рукопожатие WebSocket — обычный запрос HTTP, и куки к нему
    -- прикладываются так же.
    local jar = filled('https://example.org/', 'sid=abc; Secure')

    t.assert_equals(jar:header_for('wss://example.org/'), 'sid=abc')
    t.assert_equals(jar:header_for('ws://example.org/'), nil)
end

g.test_a_cookie_dies_exactly_at_its_hour = function()
    local jar = filled('https://example.org/', 'sid=abc; Max-Age=60')

    ctx.clock.advance(59)
    t.assert_equals(jar:header_for('https://example.org/'), 'sid=abc')

    ctx.clock.advance(1)
    t.assert_equals(jar:header_for('https://example.org/'), nil)
end

g.test_an_expired_cookie_is_thrown_out_and_not_just_passed_over = function()
    local jar = filled('https://example.org/', 'sid=abc; Max-Age=60')

    ctx.clock.advance(61)
    t.assert_equals(jar:header_for('https://example.org/'), nil)
    t.assert_equals(jar:size(), 0)
end

g.test_a_cookie_told_to_die_at_once_never_travels = function()
    local jar = filled('https://example.org/', 'sid=abc; Max-Age=0')

    t.assert_equals(jar:header_for('https://example.org/'), nil)
end

g.test_a_date_from_the_past_kills_a_cookie_just_as_well = function()
    local jar = filled('https://example.org/', 'sid=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT')

    t.assert_equals(jar:header_for('https://example.org/'), nil)
end

g.test_a_lifetime_beats_a_date_because_our_clocks_may_differ = function()
    local jar = filled('https://example.org/', 'sid=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT; Max-Age=60')

    t.assert_equals(jar:header_for('https://example.org/'), 'sid=abc')
end

g.test_a_session_cookie_lives_as_long_as_the_jar_does = function()
    local jar = filled('https://example.org/', 'sid=abc')

    ctx.clock.advance(100000000)
    t.assert_equals(jar:header_for('https://example.org/'), 'sid=abc')

    jar:clear()
    t.assert_equals(jar:header_for('https://example.org/'), nil)
    t.assert_equals(jar:size(), 0)
end

g.test_a_new_value_replaces_the_old_one_and_keeps_its_place = function()
    local jar = filled('https://example.org/', 'sid=one', 'theme=dark', 'sid=two')

    t.assert_equals(jar:size(), 2)
    t.assert_equals(jar:header_for('https://example.org/'), 'sid=two; theme=dark')
end

g.test_cookies_of_one_name_on_different_paths_live_side_by_side = function()
    local jar = filled('https://example.org/', 'sid=deep; Path=/a/b', 'sid=shallow; Path=/a')

    t.assert_equals(jar:size(), 2)
    -- Длинный путь впереди: так велит RFC 6265, и есть серверы, которые
    -- на этот порядок полагаются.
    t.assert_equals(jar:header_for('https://example.org/a/b/c'), 'sid=deep; sid=shallow')
end

g.test_the_longest_path_goes_first_wherever_it_was_put = function()
    local jar = filled(
        'https://example.org/',
        'first=1; Path=/a',
        'second=2; Path=/a/b/c',
        'third=3; Path=/a',
        'fourth=4; Path=/a/b'
    )

    t.assert_equals(jar:header_for('https://example.org/a/b/c/d'), 'second=2; fourth=4; first=1; third=3')
end

g.test_cookies_of_one_path_length_keep_the_order_they_came_in = function()
    local jar = filled('https://example.org/', 'a=1', 'b=2', 'c=3')

    t.assert_equals(jar:header_for('https://example.org/'), 'a=1; b=2; c=3')
end

g.test_a_value_in_quotes_goes_back_in_quotes = function()
    local jar = filled('https://example.org/', 'theme="a b"')

    t.assert_equals(jar:header_for('https://example.org/'), 'theme="a b"')
end

g.test_a_header_that_is_not_a_cookie_is_refused = function()
    t.assert_str_contains(refusal('https://example.org/', 'Secure'), 'нет пары «имя=значение»')
end

g.test_an_address_that_is_not_a_full_one_is_refused_on_both_ways = function()
    t.assert_equals(
        refusal('/just/a/path', 'sid=abc'),
        'адрес «/just/a/path» не годится: кука знает, кому принадлежать, только по полному '
            .. 'адресу со схемой и узлом — вроде https://example.org/path'
    )
    t.assert_str_contains(
        refusal('не адрес', 'sid=abc'),
        'по полному адресу со схемой и узлом'
    )
    t.assert_equals(
        refusal(42, 'sid=abc'),
        'адрес запроса должен быть строкой, а не number'
    )

    local header, err = ctx.module.new():header_for('/just/a/path')

    t.assert_equals(header, nil)
    t.assert_str_contains(assert(err), 'по полному адресу со схемой и узлом')
end

g.test_a_scheme_is_read_regardless_of_its_case = function()
    -- Схема в адресе нечувствительна к регистру, и HTTPS большими буквами —
    -- такой же защищённый канал.
    local jar = filled('HTTPS://example.org/', 'sid=abc; Secure')

    t.assert_equals(jar:header_for('HTTPS://example.org/'), 'sid=abc')
    t.assert_equals(jar:header_for('Wss://example.org/'), 'sid=abc')
    t.assert_equals(jar:header_for('HTTP://example.org/'), nil)
end

g.test_a_secure_cookie_that_came_in_the_open_is_refused = function()
    -- Такую мог подложить посредник, а по защищённому каналу хранилище
    -- отдало бы её настоящему серверу.
    local jar = ctx.module.new()
    local ok, err = jar:put('http://example.org/', 'sid=planted; Secure')

    t.assert_equals(ok, false)
    t.assert_equals(
        err,
        'кука «sid» с признаком Secure пришла по открытому каналу: '
            .. 'её мог подложить посредник, и хранилище её не берёт'
    )
    t.assert_equals(jar:size(), 0)
    t.assert_equals(jar:header_for('https://example.org/'), nil)

    t.assert_str_contains(
        refusal('ws://example.org/', 'sid=planted; Secure'),
        'пришла по открытому каналу'
    )
end

g.test_an_open_answer_does_not_replace_a_secure_cookie = function()
    local jar = filled('https://example.org/', 'sid=real; Secure')
    local ok, err = jar:put('http://example.org/', 'sid=planted')

    t.assert_equals(ok, false)
    t.assert_equals(
        err,
        'кука «sid» пришла по открытому каналу, а защищённая с тем же именем уже лежит: '
            .. 'открытый ответ не вправе ни заменить её, ни заслонить'
    )
    t.assert_equals(jar:header_for('https://example.org/'), 'sid=real')
end

g.test_a_safe_answer_replaces_a_secure_cookie_as_before = function()
    local jar = filled('https://example.org/', 'sid=real; Secure', 'sid=next')

    t.assert_equals(jar:header_for('http://example.org/'), 'sid=next')
end

g.test_an_open_answer_does_not_shadow_a_secure_cookie_from_a_deeper_path = function()
    -- Кука на пути длиннее едет впереди, и сервер прочёл бы подложенную.
    local jar = filled('https://example.org/', 'sid=real; Secure; Path=/login')

    t.assert_equals(jar:put('http://example.org/', 'sid=planted; Path=/login/en'), false)
    t.assert_equals(jar:put('http://example.org/', 'sid=planted; Path=/login'), false)

    -- Путь короче законен: там, где едет защищённая, эта едет после неё.
    t.assert_equals(jar:put('http://example.org/', 'sid=open; Path=/'), true)
    t.assert_equals(jar:header_for('https://example.org/login/en'), 'sid=real; sid=open')
    t.assert_equals(jar:header_for('http://example.org/other'), 'sid=open')
end

g.test_an_open_answer_does_not_shadow_a_secure_cookie_of_a_wider_domain = function()
    -- Узел поддомена ставит свою куку, а защищённая лежит на весь домен.
    local jar = filled('https://example.org/', 'sid=real; Secure; Domain=example.org')

    t.assert_equals(jar:put('http://sub.example.org/', 'sid=planted'), false)
    t.assert_equals(jar:header_for('https://sub.example.org/'), 'sid=real')
end

g.test_an_open_answer_does_not_shadow_a_secure_cookie_with_a_wider_domain = function()
    -- Защищённая принадлежит поддомену, а подложенная легла бы на весь домен.
    local jar = filled('https://sub.example.org/', 'sid=real; Secure')

    t.assert_equals(jar:put('http://sub.example.org/', 'sid=planted; Domain=example.org'), false)
    t.assert_equals(jar:header_for('https://sub.example.org/'), 'sid=real')
end

g.test_an_open_answer_still_sets_what_no_secure_cookie_guards = function()
    local jar = filled('https://example.org/', 'sid=real; Secure', 'theme=light')

    t.assert_equals(jar:put('http://example.org/', 'theme=dark'), true)
    t.assert_equals(jar:put('http://example.org/', 'lang=ru'), true)
    t.assert_equals(jar:put('http://other.org/', 'sid=theirs'), true)
    t.assert_equals(jar:put('http://notexample.org/', 'sid=theirs'), true)

    t.assert_equals(jar:header_for('https://example.org/'), 'sid=real; theme=dark; lang=ru')
    t.assert_equals(jar:header_for('http://other.org/'), 'sid=theirs')
end

g.test_a_secure_cookie_guards_its_name_only_while_it_lives = function()
    local jar = filled('https://example.org/', 'sid=real; Secure; Max-Age=60')

    ctx.clock.advance(59)
    t.assert_equals(jar:put('http://example.org/', 'sid=planted'), false)

    ctx.clock.advance(1)
    t.assert_equals(jar:put('http://example.org/', 'sid=fresh'), true)
    t.assert_equals(jar:header_for('https://example.org/'), 'sid=fresh')
end

g.test_a_cookie_on_a_public_suffix_is_refused = function()
    helper.suffixes({ 'co.uk' })

    t.assert_equals(
        refusal('https://evil.co.uk/', 'sid=x; Domain=co.uk'),
        'домен «co.uk» — публичный суффикс: под ним живут чужие друг другу узлы, и кука ушла бы ко всем'
    )
    -- Точка в конце — тот же узел и тот же суффикс.
    t.assert_str_contains(refusal('https://evil.co.uk./', 'sid=x; Domain=co.uk.'), 'публичный суффикс')
end

g.test_a_host_named_like_a_suffix_keeps_its_cookie_to_itself = function()
    -- Такой узел свою куку ставить вправе (RFC 6265, 5.3, шаг 5), но его
    -- поддомены принадлежат чужим владельцам и её не получают.
    helper.suffixes({ 'github.io' })

    local jar = filled('https://github.io/', 'sid=abc; Domain=github.io')

    t.assert_equals(jar:header_for('https://github.io/'), 'sid=abc')
    t.assert_equals(jar:header_for('https://evil.github.io/'), nil)
end

g.test_a_domain_under_a_suffix_is_an_ordinary_domain = function()
    helper.suffixes({ 'co.uk' })

    local jar = filled('https://www.example.co.uk/', 'sid=abc; Domain=example.co.uk')

    t.assert_equals(jar:header_for('https://shop.example.co.uk/'), 'sid=abc')
    t.assert_str_contains(
        refusal('https://evil.co.uk/', 'sid=x; Domain=example.co.uk'),
        'узел «evil.co.uk» не входит в домен «example.co.uk»'
    )
end

g.test_without_the_list_a_domain_needs_only_a_dot = function()
    -- libpsl на узле нет: зону из двух слов отличить нечем, и остаётся
    -- правило точки.
    local jar = filled('https://evil.co.uk/', 'sid=abc; Domain=co.uk')

    t.assert_equals(jar:header_for('https://other.co.uk/'), 'sid=abc')
end

--- Отказ куке, не сдержавшей обещания приставки, — полным текстом.
---@param name string Имя куки
---@param broken string Чего у куки нет или что лишнее
---@param prefix string Приставка, как она пишется
---@param promise string Что приставка обещает
---@return string
local function broken_promise(name, broken, prefix, promise)
    return ('кука «%s» пришла %s, а приставка %s обещает %s: '):format(
        name,
        broken,
        prefix,
        promise
    ) .. 'хранилище такую куку не берёт'
end

g.test_a_secure_prefix_without_secure_is_refused = function()
    -- Текст целиком, а не шаблоном: шаблон проверки повторял бы шаблон
    -- кода и ошибку в нём не заметил бы.
    local expected = 'кука «__Secure-sid» пришла без признака Secure, а приставка __Secure- обещает его: '
        .. 'хранилище такую куку не берёт'
    local jar = ctx.module.new()
    local ok, err = jar:put('https://example.org/', '__Secure-sid=x')

    t.assert_equals(ok, false)
    t.assert_equals(err, expected)
    t.assert_equals(jar:size(), 0)

    -- По открытому каналу — тот же отказ: признака Secure нет, и правилу
    -- канала сказать нечего, а приставку такая кука всё равно обманывает.
    t.assert_equals(refusal('http://example.org/', '__Secure-sid=x'), expected)
end

g.test_a_secure_prefix_asks_for_secure_and_nothing_more = function()
    -- Домен и путь приставка __Secure- не трогает: обещан только канал.
    local jar = filled('https://www.example.org/', '__Secure-sid=x; Secure; Domain=example.org; Path=/a')

    t.assert_equals(jar:header_for('https://example.org/a'), '__Secure-sid=x')
    t.assert_equals(jar:header_for('http://example.org/a'), nil)
end

g.test_a_prefixed_cookie_from_the_open_channel_is_refused_for_the_channel = function()
    -- Правило канала стоит в черновике раньше правил приставок, и отказ
    -- называет его, в чём бы ещё кука ни провинилась.
    t.assert_equals(
        refusal('http://example.org/', '__Secure-sid=x; Secure'),
        'кука «__Secure-sid» с признаком Secure пришла по открытому каналу: '
            .. 'её мог подложить посредник, и хранилище её не берёт'
    )
    t.assert_str_contains(
        refusal('http://example.org/', '__Host-sid=x; Secure; Domain=example.org'),
        'пришла по открытому каналу'
    )
end

g.test_a_host_prefix_without_secure_is_refused = function()
    t.assert_equals(
        refusal('https://example.org/', '__Host-sid=x; Path=/'),
        broken_promise('__Host-sid', 'без признака Secure', '__Host-', 'его')
    )
end

g.test_a_neighbour_cannot_spread_a_host_cookie_over_the_domain = function()
    -- Соседний поддомен ставит куку с приставкой одного узла на весь домен:
    -- сервер доверился бы ей как своей.
    local expected =
        broken_promise('__Host-sid', 'с атрибутом Domain', '__Host-', 'куку одного узла')
    local jar = ctx.module.new()
    local ok, err = jar:put('https://evil.example.org/', '__Host-sid=x; Secure; Path=/; Domain=example.org')

    t.assert_equals(ok, false)
    t.assert_equals(err, expected)
    t.assert_equals(jar:header_for('https://example.org/'), nil)

    -- Атрибут Domain делает куку доменной, даже когда его назвал сам узел.
    t.assert_equals(refusal('https://example.org/', '__Host-sid=x; Secure; Path=/; Domain=example.org'), expected)
end

g.test_a_host_prefix_needs_the_root_path_named_by_the_server = function()
    local expected = broken_promise('__Host-sid', 'без Path=/', '__Host-', 'куку на весь узел')

    t.assert_equals(refusal('https://example.org/', '__Host-sid=x; Secure; Path=/admin'), expected)

    -- Путь по умолчанию не в счёт, даже когда он «/»: обещан атрибут.
    t.assert_equals(refusal('https://example.org/', '__Host-sid=x; Secure'), expected)

    -- Путь не с косой разбор пропускает, и Path=/ сервер не назвал.
    t.assert_equals(refusal('https://example.org/', '__Host-sid=x; Secure; Path=admin'), expected)
end

g.test_a_host_prefix_that_keeps_its_promise_stays_with_its_host = function()
    local jar = filled('https://example.org/login/form', '__Host-sid=x; Secure; Path=/')

    t.assert_equals(jar:header_for('https://example.org/any/where'), '__Host-sid=x')
    t.assert_equals(jar:header_for('https://sub.example.org/'), nil)
    t.assert_equals(jar:header_for('http://example.org/'), nil)
end

g.test_a_host_named_like_a_suffix_may_name_itself_in_a_host_cookie = function()
    -- Domain на самого себя у такого узла даёт куку одного узла
    -- (RFC 6265, 5.3, шаг 5), и обещание приставки она держит.
    helper.suffixes({ 'github.io' })

    local jar = filled('https://github.io/', '__Host-sid=x; Secure; Path=/; Domain=github.io')

    t.assert_equals(jar:header_for('https://github.io/'), '__Host-sid=x')
    t.assert_equals(jar:header_for('https://evil.github.io/'), nil)
end

g.test_a_prefix_is_read_regardless_of_its_case = function()
    -- Сервер, сравнивающий имена без регистра, прочёл бы __HOST-sid как
    -- свою __Host-sid, поэтому и обещания с неё спрашиваются те же.
    t.assert_equals(
        refusal('https://evil.example.org/', '__HOST-sid=x; Secure; Path=/; Domain=example.org'),
        broken_promise('__HOST-sid', 'с атрибутом Domain', '__Host-', 'куку одного узла')
    )
    t.assert_equals(
        refusal('https://example.org/', '__secure-sid=x'),
        broken_promise('__secure-sid', 'без признака Secure', '__Secure-', 'его')
    )

    local jar = filled('https://example.org/', '__host-sid=x; Secure; Path=/', '__SeCuRe-id=y; Secure')

    t.assert_equals(jar:header_for('https://example.org/'), '__host-sid=x; __SeCuRe-id=y')
end

g.test_a_name_that_only_looks_like_a_prefix_promises_nothing = function()
    local jar = filled(
        'http://www.example.org/',
        '__Hostile=1; Domain=example.org',
        '__Secure=2',
        'x__Host-sid=3; Domain=example.org',
        '_Host-sid=4; Path=/a',
        '__Host_sid=5'
    )

    t.assert_equals(jar:size(), 5)
end
