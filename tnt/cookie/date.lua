--- Даты в куках: три вида на чтение, один на запись.
---
--- Сервер вправе написать срок куки тремя способами, и все три встречаются
--- в природе: нынешний IMF-fixdate («Sun, 06 Nov 1994 08:49:37 GMT»),
--- устаревший вид RFC 850 («Sunday, 06-Nov-94 08:49:37 GMT») и то, что
--- печатает asctime языка C («Sun Nov  6 08:49:37 1994»). Разбирать их
--- тремя образцами незачем: RFC 6265 (5.1.1) велит другое — разбить строку
--- на лексемы по разделителям и разобрать лексемы по одной, чем бы они
--- ни были разделены. Один разбор покрывает все три вида и ещё десяток
--- кривых, которые шлют живые серверы.
---
--- Порядок проб в разборе лексемы — из спецификации, и он важен: «08:49:37»
--- подходит и под время, и под день месяца, а «11» — и под день, и под год.
--- Первым пробуется время, последним год.
---
--- Пишем только IMF-fixdate: остальные два вида устарели, и посылать их
--- некому.

local datetime = require('datetime')

local octet = require('tnt.cookie.octet')

local Module = {}

--- Разделители лексем в дате (RFC 6265, 5.1.1).
---
--- Перечислены знаками, а не диапазонами байтов: диапазон разъезжается
--- на единицу незаметно, а знаки видно глазами. Всё, чего здесь нет, —
--- часть лексемы, включая управляющие байты: так велит спецификация,
--- и это не придирка. Разбор, считающий управляющий байт разделителем,
--- разрежет «199☒4» на два числа и примет год, которого сервер не писал.
local DELIMITER = octet.set_of('\t !"#$%&\'()*+,-./;<=>?@[\\]^_`{|}~')

--- Месяцы: в дате куки они всегда по-английски и всегда тремя буквами.
local MONTHS = {
    jan = 1,
    feb = 2,
    mar = 3,
    apr = 4,
    may = 5,
    jun = 6,
    jul = 7,
    aug = 8,
    sep = 9,
    oct = 10,
    nov = 11,
    dec = 12,
}

--- Самый ранний срок, который пишется датой куки: начало 1601 года.
---
--- Более ранних дат RFC 6265 (5.1.1) не признаёт, а непонятую дату браузер
--- молча пропускает — и кука, которой назначили срок, живёт до закрытия
--- браузера.
local EARLIEST = -11644473600

--- Самый поздний: последняя секунда 9999 года. Дальше год перестаёт быть
--- четырёхзначным, и такую дату не прочтёт ни браузер, ни разбор выше.
local LATEST = 253402300799

--- Отказ сроку вне этих лет: пределы в нём названы и секундами, и годами —
--- задают срок секундами, а думают о нём годами.
local OUT_OF_YEARS = 'срок куки expires должен лежать между %d и %d — в 1601—9999 годах, а не %s: '
    .. 'другой год не записать датой, которую прочтёт браузер'

--- Лексемы даты.
---
--- Разделитель в конце подставлен нарочно: без него последняя лексема
--- осталась бы недособранной, и из «Sun, 06 Nov 08:49:37 1994» пропал бы
--- год.
---@param text string
---@return string[]
local function tokens_of(text)
    local found = {}
    local current = ''

    for char in (text .. ' '):gmatch('.') do
        if DELIMITER[char] then
            if current ~= '' then
                table.insert(found, current)
                current = ''
            end
        else
            current = current .. char
        end
    end

    return found
end

--- Совпадение в начале лексемы, за которым нет цифры.
---
--- Все числовые продукции RFC 6265 (5.1.1) кончаются оборотом
--- `( non-digit *OCTET )`: число обязано на этом месте кончиться. Без этой
--- проверки «1994» сошло бы за день месяца — две первые цифры подходят, —
--- и года в дате не нашлось бы вовсе.
---@param token string
---@param pattern string
---@return string[]|nil found Совпадение целиком и его части
local function leading(token, pattern)
    local found = { token:match('^(' .. pattern .. ')') }

    if found[1] == nil then
        return nil
    end

    if token:sub(#found[1] + 1):match('^%d') ~= nil then
        return nil
    end

    return found
end

--- Кладёт лексему в первую подходящую ещё не занятую ячейку.
---@param found table
---@param token string
local function take(found, token)
    if found.hour == nil then
        local time = leading(token, '(%d%d?):(%d%d?):(%d%d?)')

        if time ~= nil then
            found.hour = tonumber(time[2])
            found.min = tonumber(time[3])
            found.sec = tonumber(time[4])

            return
        end
    end

    if found.day == nil then
        local day = leading(token, '%d%d?')

        if day ~= nil then
            found.day = tonumber(day[1])

            return
        end
    end

    if found.month == nil then
        -- Пустая строка вместо несовпадения: в таблице месяцев её нет,
        -- и лишняя проверка на nil здесь была бы только шумом.
        local month = MONTHS[token:lower():match('^%a%a%a') or '']

        if month ~= nil then
            found.month = month

            return
        end
    end

    if found.year == nil then
        local year = leading(token, '%d%d%d?%d?')

        if year ~= nil then
            found.year = tonumber(year[1])
        end
    end
end

--- Двузначный год в четырёхзначный (RFC 6265, 5.1.1, шаги 3 и 4).
---
--- 70..99 читаются как 1970..1999, 00..69 — как 2000..2069. Эта развилка
--- и есть причина, по которой в куках до сих пор попадается вид RFC 850
--- с двузначным годом: он не умер, потому что его научились читать.
---@param year integer
---@return integer
local function full_year(year)
    if year <= 69 then
        return year + 2000
    end

    if year <= 99 then
        return year + 1900
    end

    return year
end

--- Сошлись ли поля даты в дату, которая бывает (RFC 6265, 5.1.1, шаг 5).
---
--- Пределы дня, месяца, часа и минуты здесь не проверяются: их проверит
--- сам `datetime`, и проверять дважды значит однажды разойтись во мнениях.
--- Двух проверок он не делает, и обе остались тут. Год до 1601 он принимает,
--- а спецификация — нет. Секунду 60 он считает високосной и переводит
--- в следующую минуту; спецификация велит такую дату не принимать вовсе,
--- и молча сдвинутый на минуту срок куки — ровно то, чего здесь не надо.
---
--- Одним выражением, а не ветками с `return false`: зовущий читает ответ
--- как истину или ложь, и `nil` вместо `false` в ветке никто бы не отличил.
--- Секунды сверяются последними: их нет без часа.
---@param found table
---@param year integer
---@return boolean
local function sound(found, year)
    return found.day ~= nil and found.month ~= nil and found.hour ~= nil and year >= 1601 and found.sec <= 59
end

--- Разбирает дату куки (RFC 6265, 5.1.1).
---@param text any Значение атрибута Expires
---@return number|nil epoch Секунды от начала эпохи; nil, если это не дата
function Module.parse(text)
    if type(text) ~= 'string' then
        return nil
    end

    local found = {}

    for _, token in ipairs(tokens_of(text)) do
        take(found, token)
    end

    if found.year == nil then
        return nil
    end

    local year = full_year(found.year)

    if not sound(found, year) then
        return nil
    end

    -- Даты, которой не бывает (31 февраля), разбор не выдумывает: datetime
    -- отказывает исключением, а наружу пакет исключений не выпускает.
    local ok, stamp = pcall(datetime.new, {
        year = year,
        month = found.month,
        day = found.day,
        hour = found.hour,
        min = found.min,
        sec = found.sec,
    })

    if not ok then
        return nil
    end

    -- Поле timestamp, а не epoch: оно то же самое для целых секунд,
    -- а epoch нет в описании типов, и проверка типов о нём не знает.
    return stamp.timestamp
end

--- Годится ли срок для записи датой куки.
---
--- Срок вне 1601—9999 годов отвергается, а не пишется как есть: дату
--- с пятизначным годом браузер пропустит молча, а год за пределами
--- `datetime` уронил бы запись исключением посреди сборки заголовка.
---@param epoch number Секунды от начала эпохи, целое число
---@return boolean ok
---@return string|nil err
function Module.check(epoch)
    if epoch < EARLIEST or epoch > LATEST then
        return false, OUT_OF_YEARS:format(EARLIEST, LATEST, tostring(epoch))
    end

    return true
end

--- Пишет срок в нынешнем виде IMF-fixdate (RFC 9110, 5.6.7).
---
--- Название дня и месяца всегда по-английски: это не текст для человека,
--- а часть протокола, и локаль на него влиять не должна.
---@param epoch number Секунды от начала эпохи, целое число
---@return string
function Module.format(epoch)
    return datetime.new({ timestamp = epoch }):format('%a, %d %b %Y %H:%M:%S GMT')
end

return Module
