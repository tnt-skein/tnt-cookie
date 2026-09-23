--- Проверки списка публичных суффиксов на двойнике libpsl.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g, ctx = helper.group('cookie_suffix', 'tnt.cookie.suffix')

--- Подменяет загрузку библиотеки.
---@param load fun(name: string): table
local function use(load)
    ctx.module._set_source({ load = load })
end

g.test_the_library_is_looked_for_by_name_then_by_soname = function()
    t.assert_equals(ctx.module.NAMES, { 'psl', 'libpsl.so.5' })

    -- Под Linux без пакета разработчика `libpsl.so` нет, а soname есть.
    local load, asked = helper.loader(helper.psl({ 'co.uk' }))

    use(load)

    t.assert_equals(ctx.module.is_public('co.uk'), true)
    t.assert_equals(asked, { 'psl', 'libpsl.so.5' })
end

g.test_the_first_name_found_is_taken = function()
    local load, asked = helper.loader(helper.psl({ 'co.uk' }), 'psl')

    use(load)

    t.assert_equals(ctx.module.is_public('co.uk'), true)
    t.assert_equals(asked, { 'psl' })
end

g.test_the_found_list_is_remembered = function()
    local load, asked = helper.loader(helper.psl({ 'co.uk' }))

    use(load)

    t.assert_equals(ctx.module.is_public('co.uk'), true)
    t.assert_equals(ctx.module.is_public('example.org'), false)
    t.assert_equals(asked, { 'psl', 'libpsl.so.5' })
end

g.test_without_the_library_there_is_no_answer_and_no_second_search = function()
    -- Отсутствие запоминается тоже: иначе на узле без libpsl каждая кука
    -- с Domain стоила бы двух поисков библиотеки на диске.
    local load, asked = helper.loader(nil)

    use(load)

    t.assert_equals(ctx.module.is_public('co.uk'), nil)
    t.assert_equals(ctx.module.is_public('co.uk'), nil)
    t.assert_equals(asked, { 'psl', 'libpsl.so.5' })
end

g.test_a_library_without_a_list_gives_no_answer_either = function()
    local load, asked = helper.loader(helper.psl(nil))

    use(load)

    t.assert_equals(ctx.module.is_public('co.uk'), nil)
    t.assert_equals(ctx.module.is_public('co.uk'), nil)
    t.assert_equals(asked, { 'psl', 'libpsl.so.5' })
end

g.test_a_suffix_and_a_domain_of_one_owner_are_told_apart = function()
    helper.suffixes({ 'co.uk', 'github.io' })

    t.assert_equals(ctx.module.is_public('co.uk'), true)
    t.assert_equals(ctx.module.is_public('github.io'), true)
    t.assert_equals(ctx.module.is_public('example.co.uk'), false)
    t.assert_equals(ctx.module.is_public('example.org'), false)
end

g.test_a_dot_at_the_end_does_not_hide_a_suffix = function()
    -- Точка в конце значит тот же узел, а сама libpsl её не снимает.
    helper.suffixes({ 'co.uk' })

    t.assert_equals(ctx.module.is_public('co.uk.'), true)
    t.assert_equals(ctx.module.is_public('co.uk..'), true)
    t.assert_equals(ctx.module.is_public('example.co.uk.'), false)
end

g.test_another_loader_gets_its_own_answer = function()
    helper.suffixes({ 'co.uk' })
    t.assert_equals(ctx.module.is_public('co.uk'), true)

    use((helper.loader(nil)))
    t.assert_equals(ctx.module.is_public('co.uk'), nil)
end
