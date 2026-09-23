--- Что можно писать в имени, значении, пути и домене куки.
---
--- Заголовок куки — разметка, а не текст: имя от значения отделяет знак
--- равенства, куку от куки и атрибут от атрибута — точка с запятой. Знак
--- разметки, попавший внутрь значения, портит не свою куку, а соседние:
--- значение `x; admin=1` приезжает обратно двумя куками, и вторая
--- неотличима от поставленной сервером.
---
--- Поэтому недопустимый знак отвергается, а не вырезается. Урезанное молча
--- значение уходит клиенту целым с виду, и разбирается с ним уже тот, кто
--- его получил: подпись не сойдётся, опознаватель сессии окажется чужим,
--- а причину придётся искать в чужом браузере.
---
--- Наборы знаков собраны таблицами, а не образцами вида `%w`: классы Lua
--- смотрят на локаль, и в чужой локали `%w` прихватывает буквы, которых
--- в лексеме HTTP не бывает.

local Module = {}

--- Множество знаков из строки.
---@param chars string
---@return table<string, boolean>
function Module.set_of(chars)
    local set = {}

    for char in chars:gmatch('.') do
        set[char] = true
    end

    return set
end

--- Печатные знаки US-ASCII: только их можно показать в отказе как есть.
---
--- Управляющий знак, вставленный в сообщение, разорвал бы запись журнала
--- переводом строки, а байт вне ASCII превратил бы её в нечитаемую кашу.
local PRINTABLE = ' !"#$%&\'()*+,-./0123456789:;<=>?@'
    .. 'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`'
    .. 'abcdefghijklmnopqrstuvwxyz{|}~'

local SHOWN = Module.set_of(PRINTABLE)

--- Буквы и цифры: основа всех остальных наборов.
local ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

--- Имя куки — лексема HTTP (RFC 9110, 5.6.2).
local NAME_ALLOWED = Module.set_of(ALNUM .. "!#$%&'*+-.^_`|~")

--- Значение куки (RFC 6265, 4.1.1): печатные знаки US-ASCII, кроме
--- пробела, кавычки, запятой, точки с запятой и обратной косой.
local VALUE_ALLOWED = Module.set_of((PRINTABLE:gsub('[ ",;\\]', '')))

--- Путь куки (RFC 6265, 4.1.1): всё печатное, кроме точки с запятой.
--- Пробел здесь разрешён самой грамматикой, хотя в пути ему делать нечего.
local PATH_ALLOWED = Module.set_of((PRINTABLE:gsub(';', '')))

--- Домен куки: имя узла по RFC 1034 с поправкой RFC 1123.
local DOMAIN_ALLOWED = Module.set_of(ALNUM .. '-.')

--- Знак так, чтобы отказ остался читаемым.
---@param char string
---@return string
local function shown(char)
    if SHOWN[char] then
        return ('знак «%s»'):format(char)
    end

    return ('байт %d'):format(char:byte())
end

--- Первый знак, которого в строке быть не должно.
---@param text string
---@param allowed table<string, boolean>
---@return string|nil char
---@return integer|nil at
local function first_forbidden(text, allowed)
    for at = 1, #text do
        local char = text:sub(at, at)

        if not allowed[char] then
            return char, at
        end
    end
end

--- Описание одного набора: чем он ограничен и как об этом сказать.
---@class TntCookieKind
---@field allowed table<string, boolean>
---@field subject string Подлежащее со связкой: «имя куки должно»
---@field place string Где искать знак: «имени куки»
---@field tail string Чем кончить отказ

---@type table<string, TntCookieKind>
local KINDS = {
    name = {
        allowed = NAME_ALLOWED,
        subject = 'имя куки должно',
        place = 'имени куки',
        tail = "имя — это лексема HTTP: буквы, цифры и знаки !#$%&'*+-.^_`|~",
    },
    value = {
        allowed = VALUE_ALLOWED,
        subject = 'значение куки должно',
        place = 'значении куки',
        tail = 'заголовок разделяют пробел, кавычка, запятая, точка с запятой '
            .. 'и обратная косая, и внутри значения их быть не может',
    },
    path = {
        allowed = PATH_ALLOWED,
        subject = 'путь куки должен',
        place = 'пути куки',
        tail = 'точка с запятой начинает следующий атрибут, а управляющий знак обрывает заголовок',
    },
    domain = {
        allowed = DOMAIN_ALLOWED,
        subject = 'домен куки должен',
        place = 'домене куки',
        tail = 'имя узла складывается из букв, цифр, дефисов и точек',
    },
}

--- Годится ли строка для своего места в заголовке.
---@param text any
---@param kind TntCookieKind
---@return boolean ok
---@return string|nil err
local function checked(text, kind)
    if type(text) ~= 'string' then
        return false, ('%s быть строкой, а не %s'):format(kind.subject, type(text))
    end

    local char, at = first_forbidden(text, kind.allowed)

    if char ~= nil then
        return false,
            ('в %s недопустим %s на месте %d: %s'):format(kind.place, shown(char), at, kind.tail)
    end

    return true
end

--- Годится ли имя куки.
---@param name any
---@return boolean ok
---@return string|nil err
function Module.check_name(name)
    local ok, err = checked(name, KINDS.name)

    if not ok then
        return false, err
    end

    if name == '' then
        return false, 'имя куки пустое: кука без имени не доедет обратно'
    end

    return true
end

--- Годится ли значение куки. Пустое значение — законное значение.
---@param value any
---@return boolean ok
---@return string|nil err
function Module.check_value(value)
    return checked(value, KINDS.value)
end

--- Годится ли путь куки.
---@param path any
---@return boolean ok
---@return string|nil err
function Module.check_path(path)
    local ok, err = checked(path, KINDS.path)

    if not ok then
        return false, err
    end

    if path:match('^/') == nil then
        return false,
            'путь куки должен начинаться с «/»: иначе браузер подставит путь запроса, '
                .. 'и кука уедет не туда, куда её ставили'
    end

    return true
end

--- Годится ли домен куки.
---@param domain any
---@return boolean ok
---@return string|nil err
function Module.check_domain(domain)
    local ok, err = checked(domain, KINDS.domain)

    if not ok then
        return false, err
    end

    if domain:match('%.') == nil then
        return false,
            'домен куки должен содержать точку: домен из одного слова — это зона целиком, '
                .. 'и куку на неё не поставит ни один браузер'
    end

    return true
end

--- Приставки имени, которые несут обещание (RFC 6265bis, 4.1.3): как
--- приставка пишется и образец, по которому она узнаётся в имени,
--- приведённом к нижнему регистру.
---
--- Образец у каждой свой и написан целиком, без повторов вида `[a-z]+`:
--- приставок две, и общий образец с поиском по таблице только прятал бы,
--- какие имена узнаются.
local PREFIXES = {
    { name = '__Host-', pattern = '^__host%-' },
    { name = '__Secure-', pattern = '^__secure%-' },
}

--- Какую приставку несёт имя куки.
---
--- Без регистра, как велит браузеру черновик RFC 6265bis (5.4 и 5.7):
--- сервер, который сравнивает имена кук без регистра, прочтёт
--- `__HOST-sid` как свою `__Host-sid`. Проверка, узнающая приставку
--- в одном написании, пропустила бы подложенную куку в другом.
--- Распознавание одно на сборку и на хранилище: собранную куку без
--- обещанного браузер выбросит молча, а хранилище её не возьмёт.
---@param name string
---@return string|nil prefix `__Host-` или `__Secure-`; nil — приставки нет
function Module.prefix_of(name)
    local lowered = name:lower()

    for _, prefix in ipairs(PREFIXES) do
        if lowered:match(prefix.pattern) ~= nil then
            return prefix.name
        end
    end

    return nil
end

--- Снимает кавычки со значения.
---
--- RFC 6265 (4.1.1) разрешает значение в кавычках, и серверы на Java его
--- шлют. RFC 6265bis велит кавычки не снимать, считая их частью значения,
--- — но тогда подпись, посчитанная по значению, не сойдётся ни у кого, кто
--- прислал его в кавычках. Здесь кавычки снимаются, а то, что они были,
--- запоминается отдельно: собрать заголовок обратно можно точно таким же.
---@param value string
---@return string bare Значение без кавычек
---@return boolean quoted Были ли кавычки
function Module.unquote(value)
    local inner = value:match('^"(.*)"$')

    if inner == nil then
        return value, false
    end

    return inner, true
end

return Module
