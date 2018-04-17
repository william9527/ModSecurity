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

#ifndef SRC_ACTIONS_NO_LOG_H_
#define SRC_ACTIONS_NO_LOG_H_

class Transaction;

namespace modsecurity {
class Transaction;
namespace actions {


class NoLog : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Non-disruptive

    \verbatim
    Prevents rule matches from appearing in both the error and audit logs.

    Although nolog implies noauditlog, you can override the former by using
    nolog,auditlog.
    \endverbatim


    Example

    \verbatim
    = SecRule REQUEST_HEADERS:User-Agent "Test" allow,nolog,id:121
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit NoLog(std::string action)
        : Action(action, RunTimeOnlyIfMatchKind) { }

    bool evaluate(Rule *rule, Transaction *transaction,
        std::shared_ptr<RuleMessage> rm) override;
};

}  // namespace actions
}  // namespace modsecurity


#endif  // SRC_ACTIONS_NO_LOG_H_
