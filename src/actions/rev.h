/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <string>

#include "modsecurity/actions/action.h"

#ifndef SRC_ACTIONS_REV_H_
#define SRC_ACTIONS_REV_H_

class Transaction;

namespace modsecurity {
class Transaction;
namespace actions {


class Rev : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Meta-data

    \verbatim
    Specifies rule revision. It is useful in combination with the id action to
    provide an indication that a rule has been changed.

    Note: This action is used in combination with the id action to allow the
    same rule ID to be used after changes take place but to still provide some
    indication the rule changed
    \endverbatim


    Example

    \verbatim
    = SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))" \
	                "phase:2,rev:'2.1.3',capture,t:none,t:normalizePath,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'950907',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%{tx.0},skipAfter:END_COMMAND_INJECTION1"

    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Rev(std::string action) : Action(action, ConfigurationKind) { }

    bool evaluate(Rule *rule, Transaction *transaction) override;
    bool init(std::string *error) override;

 private:
    std::string m_rev;
};


}  // namespace actions
}  // namespace modsecurity

#endif  // SRC_ACTIONS_REV_H_
