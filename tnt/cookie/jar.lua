--- Хранилище кук для исходящих запросов.
---
--- Клиент, ходящий к чужому серверу, обязан вести себя как браузер: взять
--- куки из ответа, запомнить и приложить их к следующему запросу — но
--- только к тому, которому они предназначены. Отбор идёт по домену, пути,
--- сроку и признаку Secure, и правила отбора взяты из RFC 6265 (5.1.3,
--- 5.1.4, 5.3 и 5.4) дословно, а не придуманы.
---
--- Соврать здесь дороже всего: кука — это пропуск, и уехавшая не на тот
--- узел кука отдаёт чужому серверу нашу сессию. Поэтому кука без атрибута
--- Domain принадлежит ровно тому узлу, который её поставил, и никакому
--- поддомену; кука с Domain доедет до поддоменов, но только если узел,
--- приславший её, сам входит в этот домен, а домен — не публичный
--- суффикс вроде `co.uk` (`tnt.cookie.suffix`). Без списка суффиксов
--- на узле остаётся одно правило: домен без единой точки отвергается —
--- это отсекает `Domain=com`, но не `Domain=co.uk`.
---
--- Открытый канал куку с Secure не ставит и не подменяет: это два
--- правила черновика RFC 6265bis (5.7) поверх RFC 6265. Куку, пришедшую
--- по HTTP, мог подложить любой посредник, и признак Secure на ней —
--- уловка: хранилище отдало бы её настоящему серверу по защищённому
--- каналу, и клиенту досталась бы чужая сессия. По той же причине
--- открытый ответ не вправе заменить или заслонить защищённую куку,
--- которая уже лежит.
---
--- Приставки `__Host-` и `__Secure-` хранилище сверяет с атрибутами
--- по тому же черновику: сервер читает приставку как обещание, и кука,
--- пришедшая без обещанного, сделала бы его ложью.
---
--- Признак HttpOnly хранится, но на отбор не влияет: он запрещает отдавать
--- куку не-HTTP средствам (сценарию на странице), а здесь всё происходящее
--- и есть HTTP-запрос.

local uri = require('uri')

local clock = require('tnt.clock')
local octet = require('tnt.cookie.octet')
local parse = require('tnt.cookie.parse')
local suffix = require('tnt.cookie.suffix')
local external = require('tnt.external')

local Module = {}

--- Часы берутся как внешняя зависимость: срок куки истекает в проверке мгновенно, но ровно
--- там, где истёк бы на самом деле.
---
--- Часы стенные, а не монотонные: срок куки сервер называет датой, и мерять
--- его нечем, кроме такой же даты. Отсюда и цена: перевод стенных часов
--- назад продлевает жизнь уже сохранённым кукам.
local source = external.install(Module, { clock = clock })

--- Схемы, которые считаются защищёнными (RFC 6265, 5.4, шаг 1).
local SECURE_SCHEMES = { https = true, wss = true }

--- Адрес это или имя узла.
---
--- Правило RFC 6265 (5.1.3) отрезает суффикс домена только у имён: у адреса
--- `10.0.0.1` суффикс `0.0.1` — не домен, а обрезок числа, и кука от него
--- уехала бы куда угодно.
---
--- Признаков два, и обоих по отдельности мало. Двоеточий в имени узла
--- не бывает — а в записи IPv6 `::ffff:1.2.3.4` есть и буквы, и точки,
--- и без этой проверки она сошла бы за поддомен зоны `2.3.4`. Буква же
--- отличает имя от четвёрки чисел IPv4, где её нет вовсе.
---@param host string
---@return boolean
local function is_address(host)
    if host:match(':') ~= nil then
        return true
    end

    return host:match('%a') == nil
end

--- Входит ли узел в домен куки (RFC 6265, 5.1.3).
---@param host string Узел запроса, в нижнем регистре
---@param domain string Домен куки, в нижнем регистре
---@return boolean
local function domain_matches(host, domain)
    -- Суффикс отрезается ровно по точке: `foo.example.org` входит
    -- в `example.org`, а `notexample.org` — нет, хотя кончается так же.
    -- Одним выражением, а не ветками с `return false`: зовущий читает ответ
    -- как истину или ложь, и `nil` вместо `false` в ветке никто бы не отличил.
    return host == domain or (not is_address(host) and host:sub(-#domain - 1) == '.' .. domain)
end

--- Совпадает ли начало строки с образцом-текстом.
---
--- Знаки образца экранируются: путь `/a+b` — это путь, а не образец
--- «a и сколько-нибудь плюсов».
---@param text string
---@param prefix string
---@return boolean
local function starts_with(text, prefix)
    return text:match('^' .. prefix:gsub('%W', '%%%0')) ~= nil
end

--- Доходит ли путь запроса до пути куки (RFC 6265, 5.1.4).
---@param request string
---@param cookie_path string
---@return boolean
local function path_matches(request, cookie_path)
    if request == cookie_path then
        return true
    end

    -- Косая в конце делает путь куки каталогом; без неё каталогом его
    -- делаем мы сами. Иначе `/foobar` сошёл бы за `/foo`: по началу они
    -- совпадают, а каталогом `/foo` он не является.
    local folder = cookie_path

    if folder:sub(-1) ~= '/' then
        folder = folder .. '/'
    end

    return starts_with(request, folder)
end

--- Путь запроса: с ним сверяется путь куки при отборе.
---@param path string|nil Путь из адреса
---@return string
local function request_path(path)
    if path == nil or path:match('^/') == nil then
        return '/'
    end

    return path
end

--- Путь куки по умолчанию (RFC 6265, 5.1.4).
---
--- Каталог запроса, а не сам запрос: ответ на `/a/b/c` ставит куку на
--- `/a/b`, иначе она не доехала бы до соседнего `/a/b/d`.
---@param path string Путь запроса
---@return string
local function default_path(path)
    local folder = (path:gsub('/[^/]*$', ''))

    if folder == '' then
        return '/'
    end

    return folder
end

--- Что нужно знать об адресе запроса.
---
--- Схема обязательна наравне с узлом. Без неё нечем ответить на вопрос,
--- защищено ли соединение, а `uri.parse` вдобавок читает голый путь как
--- адрес сокета Unix и выдаёт узел `unix/`, которому кука досталась бы
--- ни за что.
---@param url any
---@return table|nil where Узел, путь, каталог и защищено ли соединение
---@return string|nil err
local function place_of(url)
    if type(url) ~= 'string' then
        return nil, ('адрес запроса должен быть строкой, а не %s'):format(type(url))
    end

    local parts = uri.parse(url)

    if parts == nil or parts.host == nil or parts.scheme == nil then
        return nil,
            ('адрес «%s» не годится: кука знает, кому принадлежать, только по полному '):format(
                url
            )
                .. 'адресу со схемой и узлом — вроде https://example.org/path'
    end

    local path = request_path(parts.path)

    -- Схема сверяется без регистра, как и узел (RFC 3986, 3.1): `uri.parse`
    -- отдаёт её как написано, и `HTTPS://` иначе считался бы открытым
    -- каналом, а куки с Secure молча не уезжали бы.
    return {
        host = parts.host:lower(),
        path = path,
        folder = default_path(path),
        secure = SECURE_SCHEMES[parts.scheme:lower()] == true,
    }
end

--- Кому будет принадлежать кука (RFC 6265, 5.3, шаги 4—6).
---@param cookie TntCookieSet
---@param where table
---@return string|nil domain
---@return boolean|nil host_only Принадлежит ли кука одному узлу
---@return string|nil err
local function domain_for(cookie, where)
    if cookie.domain == nil then
        -- Без атрибута Domain кука принадлежит ровно этому узлу: ни один
        -- поддомен её не получит и не перепишет.
        return where.host, true
    end

    if cookie.domain:match('%.') == nil then
        return nil,
            nil,
            ('домен «%s» — это зона целиком: куку на неё не ставят'):format(
                cookie.domain
            )
    end

    if suffix.is_public(cookie.domain) then
        -- Узел, чьё имя само стоит в списке суффиксов, свою куку ставить
        -- вправе, но она остаётся его и только его (RFC 6265, 5.3, шаг 5):
        -- поддомены такого имени принадлежат чужим друг другу владельцам.
        if cookie.domain == where.host then
            return where.host, true
        end

        return nil,
            nil,
            ('домен «%s» — публичный суффикс: под ним живут чужие друг другу узлы, '):format(
                cookie.domain
            ) .. 'и кука ушла бы ко всем'
    end

    if not domain_matches(where.host, cookie.domain) then
        return nil,
            nil,
            ('узел «%s» не входит в домен «%s»: такую куку он ставить не вправе'):format(
                where.host,
                cookie.domain
            )
    end

    return cookie.domain, false
end

--- Когда кука перестанет годиться (RFC 6265, 5.3, шаг 3).
---
--- Max-Age старше Expires: он задан длительностью и не зависит от того,
--- насколько разошлись часы сервера и наши. Ни того ни другого — кука
--- сеансовая и живёт, пока живёт хранилище.
---@param cookie TntCookieSet
---@param now number
---@return number|nil
local function expiry_of(cookie, now)
    if cookie.max_age ~= nil then
        return now + cookie.max_age
    end

    return cookie.expires
end

--- Жива ли кука: сеансовая живёт, пока живёт хранилище.
---
--- Одно правило на отбор и на сверку с защищёнными: протухшая кука
--- считается выброшенной, даже если отбор её ещё не выбросил, и путь
--- новой куке не закрывает.
---@param entry table
---@param now number
---@return boolean
local function lives(entry, now)
    return entry.expires_at == nil or entry.expires_at > now
end

--- Значение так, как его прислал сервер.
---
--- Кавычки, если они были, возвращаются на место: для сервера, приславшего
--- значение в кавычках, они — часть значения.
---@param entry table
---@return string
local function shown_value(entry)
    if entry.quoted then
        return ('"%s"'):format(entry.value)
    end

    return entry.value
end

--- Порядок в заголовке (RFC 6265, 5.4, шаг 2): впереди куки с более длинным
--- путём, среди равных — появившиеся раньше. Серверы, полагающиеся на этот
--- порядок, существуют, и спорить с ними дороже, чем его соблюсти.
---
--- Вставками, а не `table.sort`: сортировка в Lua неустойчива и куки
--- с путями одной длины переставила бы как придётся, а порядок появления
--- у них уже есть — тот, в котором они лежат. Хранить его отдельным
--- счётчиком пришлось бы только ради неустойчивой сортировки.
---
--- Место ищется проходом `for` по уже разложенным, а не сдвигом `while`
--- с конца: у прохода есть конец, и ошибка в счёте места даёт неверный
--- порядок, а не цикл, который не кончается.
---@param chosen table[] Куки в порядке появления
---@return table[]
local function by_path_length(chosen)
    local sorted = {}

    for _, entry in ipairs(chosen) do
        local at = #sorted + 1

        for index, placed in ipairs(sorted) do
            if #placed.path < #entry.path then
                at = index

                break
            end
        end

        table.insert(sorted, at, entry)
    end

    return sorted
end

---@class TntCookieJar
---@field entries table[] Сохранённые куки в порядке появления
local Jar = {}
Jar.__index = Jar

--- Одна ли это кука (RFC 6265, 5.3, шаг 11).
---
--- Куку опознаёт тройка «имя, домен, путь», а не одно имя: `sid` на `/a`
--- и `sid` на `/a/b` — две разные куки, и вторая не заменяет первую.
---@param entry table
---@param other table
---@return boolean
local function same_cookie(entry, other)
    return entry.name == other.name and entry.domain == other.domain and entry.path == other.path
end

--- Кладёт куку, заменяя прежнюю такую же.
---
--- Заменённая остаётся на своём месте (RFC 6265, 5.3, шаг 11): по порядку
--- в хранилище идёт и порядок в заголовке, и обновление значения не должно
--- перекидывать куку в конец.
---@param entry table
function Jar:store(entry)
    for at, stored in ipairs(self.entries) do
        if same_cookie(entry, stored) then
            self.entries[at] = entry

            return
        end
    end

    table.insert(self.entries, entry)
end

--- Защищённая кука, которую новая заменила бы или заслонила (RFC 6265bis, 5.7).
---
--- Заслоняет не только та же самая кука. Новая `sid` на `/login/en`
--- поехала бы впереди защищённой `sid` на `/login` — путь у неё длиннее,
--- — и сервер, читающий первую, прочёл бы подложенную. Поэтому домены
--- сверяются в обе стороны, а путь новой — вглубь пути защищённой. Путь
--- короче (`/` при защищённой на `/login`) законен: там, куда едет
--- защищённая, такая кука едет после неё.
---
--- Отдаётся сама кука, а не признак: ответ «нет» у признака пишется
--- и `false`, и `nil`, и зовущий, читающий его как истину или ложь,
--- этой разницы не различил бы.
---@param entries table[] Сохранённые куки
---@param entry table Новая кука
---@param now number
---@return table|nil stored Лежащая защищённая кука; nil — такой нет
local function hidden_secure(entries, entry, now)
    for _, stored in ipairs(entries) do
        if
            stored.secure
            and stored.name == entry.name
            and lives(stored, now)
            and (domain_matches(stored.domain, entry.domain) or domain_matches(entry.domain, stored.domain))
            and path_matches(entry.path, stored.path)
        then
            return stored
        end
    end

    return nil
end

--- Почему открытый канал не вправе положить эту куку (RFC 6265bis, 5.7).
---
--- Куку из ответа по HTTP мог подложить любой посредник. С признаком
--- Secure хранилище отдало бы её настоящему серверу по защищённому
--- каналу, а заменив или заслонив защищённую, она подсунула бы серверу
--- чужую сессию вместо нашей.
---@param entries table[] Сохранённые куки
---@param entry table Новая кука
---@param where table
---@param now number
---@return string|nil refusal
local function open_channel_refusal(entries, entry, where, now)
    if where.secure then
        return nil
    end

    if entry.secure then
        return ('кука «%s» с признаком Secure пришла по открытому каналу: '):format(
            entry.name
        ) .. 'её мог подложить посредник, и хранилище её не берёт'
    end

    if hidden_secure(entries, entry, now) ~= nil then
        return ('кука «%s» пришла по открытому каналу, а защищённая с тем же именем уже лежит: '):format(
            entry.name
        ) .. 'открытый ответ не вправе ни заменить её, ни заслонить'
    end

    return nil
end

--- Отказ куке, которая не держит обещания своей приставки.
---@param name string Имя куки
---@param broken string Чего у куки нет или что лишнее
---@param prefix string Приставка
---@param promise string Что приставка обещает
---@return string
local function broken_promise(name, broken, prefix, promise)
    return ('кука «%s» пришла %s, а приставка %s обещает %s: хранилище такую куку не берёт'):format(
        name,
        broken,
        prefix,
        promise
    )
end

--- Почему кука не держит обещания своей приставки (RFC 6265bis, 5.7).
---
--- Сервер, читающий `__Host-sid`, верит имени на слово: эту куку поставил
--- сам узел, на весь узел и по защищённому каналу. Возьми хранилище
--- `__Host-sid; Secure; Path=/; Domain=example.org` от соседнего
--- поддомена, и кука уехала бы на `example.org`, где сервер принял бы
--- подложенную сессию за свою. `__Secure-` без признака Secure мог
--- поставить открытый ответ, то есть любой посредник.
---
--- Путь сверяется с атрибутом Path, а не с путём по умолчанию: приставка
--- обещает, что `Path=/` назвал сам сервер (RFC 6265bis, 4.1.3.2), а ответ
--- на `/` без атрибута его не называл. Атрибут, не начинающийся с косой,
--- разбор пропускает, и такая кука тоже получает отказ. Здесь хранилище
--- строже черновика — тот подставил бы путь по умолчанию, — но и такой
--- сервер `Path=/` не называл.
---@param cookie TntCookieSet Разобранная кука
---@param host_only boolean Принадлежит ли она одному узлу
---@return string|nil refusal
local function prefix_refusal(cookie, host_only)
    local prefix = octet.prefix_of(cookie.name)

    if prefix == nil then
        return nil
    end

    if not cookie.secure then
        return broken_promise(cookie.name, 'без признака Secure', prefix, 'его')
    end

    if prefix == '__Secure-' then
        return nil
    end

    -- Узел, чьё имя само стоит в списке суффиксов, с Domain на себя
    -- получает куку одного узла (`domain_for`), и обещания она не нарушает.
    if not host_only then
        return broken_promise(cookie.name, 'с атрибутом Domain', prefix, 'куку одного узла')
    end

    if cookie.path ~= '/' then
        return broken_promise(cookie.name, 'без Path=/', prefix, 'куку на весь узел')
    end

    return nil
end

--- Запоминает куку из ответа.
---@param url string Адрес, с которого пришёл ответ
---@param header string Значение одного заголовка Set-Cookie
---@return boolean ok
---@return string|nil err
function Jar:put(url, header)
    local where, err = place_of(url)

    if where == nil then
        return false, err
    end

    local cookie, refusal = parse.set_cookie(header)

    if cookie == nil then
        return false, refusal
    end

    local domain, host_only, problem = domain_for(cookie, where)

    if domain == nil then
        return false, problem
    end

    -- Домен и признак одного узла `domain_for` отдаёт вместе: есть домен —
    -- есть и признак.
    ---@cast host_only boolean

    local now = source().clock.realtime()
    local entry = {
        name = cookie.name,
        value = cookie.value,
        quoted = cookie.quoted,
        domain = domain,
        host_only = host_only,
        path = cookie.path or where.folder,
        secure = cookie.secure,
        http_only = cookie.http_only,
        same_site = cookie.same_site,
        partitioned = cookie.partitioned,
        expires_at = expiry_of(cookie, now),
    }

    -- Приставка сверяется после открытого канала — в порядке шагов
    -- черновика: подложенная по HTTP кука получает отказ за канал,
    -- в чём бы ещё она ни провинилась.
    local denial = open_channel_refusal(self.entries, entry, where, now) or prefix_refusal(cookie, host_only)

    if denial ~= nil then
        return false, denial
    end

    self:store(entry)

    return true
end

--- Доходит ли кука до узла запроса (RFC 6265, 5.4, шаг 1).
---@param entry table
---@param where table
---@return boolean
local function reaches_host(entry, where)
    if entry.host_only then
        return entry.domain == where.host
    end

    return domain_matches(where.host, entry.domain)
end

--- Годится ли кука этому запросу (RFC 6265, 5.4, шаг 1).
---
--- Одним выражением по той же причине, что и сверка домена: зовущий
--- читает ответ как истину или ложь.
---@param entry table
---@param where table
---@return boolean
local function suits(entry, where)
    -- Кука с Secure не уходит по незащищённому соединению: ради этого
    -- её и помечали.
    return reaches_host(entry, where) and path_matches(where.path, entry.path) and (not entry.secure or where.secure)
end

--- Куки, которые поедут по этому адресу, в порядке заголовка.
---@param where table
---@return table[]
function Jar:matching(where)
    local now = source().clock.realtime()
    local chosen = {}
    local alive = {}

    for _, entry in ipairs(self.entries) do
        -- Протухшая кука выбрасывается, а не просто пропускается: иначе
        -- хранилище растёт, пока живёт клиент.
        if lives(entry, now) then
            table.insert(alive, entry)

            if suits(entry, where) then
                table.insert(chosen, entry)
            end
        end
    end

    self.entries = alive

    return by_path_length(chosen)
end

--- Заголовок `Cookie:` для запроса по этому адресу.
---@param url string
---@return string|nil header Значение заголовка; nil, если слать нечего
---@return string|nil err
function Jar:header_for(url)
    local where, err = place_of(url)

    if where == nil then
        return nil, err
    end

    local pieces = {}

    for _, entry in ipairs(self:matching(where)) do
        table.insert(pieces, ('%s=%s'):format(entry.name, shown_value(entry)))
    end

    if #pieces == 0 then
        return nil
    end

    return table.concat(pieces, '; ')
end

--- Сколько кук лежит в хранилище, вместе с уже протухшими.
---@return integer
function Jar:size()
    return #self.entries
end

--- Забывает всё.
---
--- Сеансовые куки живут, пока живёт хранилище, и другого способа выйти
--- из чужой сессии у клиента нет.
function Jar:clear()
    self.entries = {}
end

--- Новое пустое хранилище.
---@return TntCookieJar
function Module.new()
    return setmetatable({ entries = {} }, Jar)
end

return Module
