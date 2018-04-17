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
#include <memory>

#include "modsecurity/actions/action.h"

#ifndef SRC_ACTIONS_NO_AUDIT_LOG_H_
#define SRC_ACTIONS_NO_AUDIT_LOG_H_

#ifdef __cplusplus
class Transaction;

namespace modsecurity {
class Transaction;

namespace actions {


class NoAuditLog : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Non-disruptive

    \verbatim
    Indicates that a successful match of the rule should not be used as
    criteria to determine whether the transaction should be logged to the
    audit log.

    If the SecAuditEngine is set to On, all of the transactions will be logged.
    If it is set to RelevantOnly, then you can control the logging with the
    noauditlog action.

    The noauditlog action affects only the current rule. If you prevent audit
    logging in one rule only, a match in another rule will still cause audit
    logging to take place. If you want to prevent audit logging from taking
    place, regardless of whether any rule matches, use ctl:auditEngine=Off.
    \endverbatim


    Example

    \verbatim
    = SecRule REQUEST_HEADERS:User-Agent "Test" allow,noauditlog,id:120
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit NoAuditLog(std::string action)
        : Action(action, RunTimeOnlyIfMatchKind) { }

    bool evaluate(Rule *rule, Transaction *transaction,
        std::shared_ptr<RuleMessage> rm) override;
};

}  // namespace actions
}  // namespace modsecurity
#endif

#endif  // SRC_ACTIONS_NO_AUDIT_LOG_H_
