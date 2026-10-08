#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

class RBAC {
public:
    RBAC();

    bool isAuthorized(const std::string& role,
                      const std::string& command) const;

    void addRole(const std::string& role);

    void addPermission(const std::string& role,
                       const std::string& command);

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> permissions;
};