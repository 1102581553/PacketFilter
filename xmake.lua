set_project("PacketFilter")
set_version("1.0.0")

add_repositories("levimc-repo https://github.com/LiteLDev/xmake-repo.git")

add_requires("levilamina 1.9.5", {configs = {target_type = "server"}})
add_requires("levibuildscript")

if not has_config("vs_runtime") then
    set_runtimes("MD")
end

add_cxflags("/EHa", "/utf-8", "/W4")
add_defines("NOMINMAX", "UNICODE")
set_languages("c++20")
set_optimize("fast")
set_symbols("none")
set_exceptions("none")
add_includedirs("src")

target("PacketFilter")
    add_rules("@levibuildscript/linkrule")
    add_rules("@levibuildscript/modpacker")
    set_kind("shared")
    add_headerfiles("src/*.h")
    add_files("src/*.cpp")
    add_packages("levilamina")
    add_syslinks("shlwapi", "advapi32")
    set_targetdir("bin")
    set_runtimes("MD")
