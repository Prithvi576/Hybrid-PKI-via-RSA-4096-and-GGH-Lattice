#include "RBAC.h"

RBAC::RBAC() {

    // Viewer permissions
    addPermission("viewer", "READ_STATUS");

    // Operator permissions
    addPermission("operator", "READ_STATUS");
    addPermission("operator", "START_PUMP");
    addPermission("operator", "STOP_PUMP");

    // Engineer permissions
    addPermission("engineer", "READ_STATUS");
    addPermission("engineer", "START_PUMP");
    addPermission("engineer", "STOP_PUMP");
    addPermission("engineer", "RESET_ALARM");
    addPermission("engineer", "CONFIGURE_SYSTEM");

    // Admin has access to everything.
    addPermission("admin", "*");
}

bool RBAC::isAuthorized(const std::string& role,
                        const std::string& command) const {

    auto roleIt = permissions.find(role);

    if (roleIt == permissions.end()) {
        return false;
    }

    const auto& allowedCommands = roleIt->second;

    // Admin wildcard permission
    if (allowedCommands.find("*") != allowedCommands.end()) {
        return true;
    }

    return allowedCommands.find(command) != allowedCommands.end();
}

void RBAC::addRole(const std::string& role) {
    permissions.emplace(role, std::unordered_set<std::string>{});
}

void RBAC::addPermission(const std::string& role,
                         const std::string& command) {

    permissions[role].insert(command);
}