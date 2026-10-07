#include <iostream>
#include "../scada/RBAC.h"

int main() {

    RBAC rbac;

    std::cout << "SCADA RBAC Test\n";
    std::cout << "================\n\n";

    std::cout << "viewer -> READ_STATUS: "
              << (rbac.isAuthorized("viewer", "READ_STATUS") ? "ALLOW" : "DENY")
              << '\n';

    std::cout << "viewer -> START_PUMP: "
              << (rbac.isAuthorized("viewer", "START_PUMP") ? "ALLOW" : "DENY")
              << '\n';

    std::cout << "operator -> START_PUMP: "
              << (rbac.isAuthorized("operator", "START_PUMP") ? "ALLOW" : "DENY")
              << '\n';

    std::cout << "engineer -> CONFIGURE_SYSTEM: "
              << (rbac.isAuthorized("engineer", "CONFIGURE_SYSTEM") ? "ALLOW" : "DENY")
              << '\n';

    std::cout << "unknown -> START_PUMP: "
              << (rbac.isAuthorized("unknown", "START_PUMP") ? "ALLOW" : "DENY")
              << '\n';

    return 0;
}