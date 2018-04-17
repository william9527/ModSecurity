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
#include <utility>

#include "modsecurity/actions/action.h"
#include "src/run_time_string.h"

#ifndef SRC_ACTIONS_LOG_DATA_H_
#define SRC_ACTIONS_LOG_DATA_H_

class Transaction;

namespace modsecurity {
class Transaction;
namespace actions {


class LogData : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Non-disruptive

    \verbatim
    Logs a data fragment as part of the alert message.

    The logdata information appears in the error and/or audit log files. Macro
    expansion is performed, so you may use variable names such as %{TX.0} or
    %{MATCHED_VAR}. The information is properly escaped for use with logging
    of binary data.
    \endverbatim


    Example

    \verbatim
    = SecRule ARGS:p "@rx <script>" "phase:2,id:118,log,pass,logdata:%{MATCHED_VAR}"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit LogData(std::string action)
        : Action(action, RunTimeOnlyIfMatchKind) { }

    explicit LogData(std::unique_ptr<RunTimeString> z)
        : Action("logdata", RunTimeOnlyIfMatchKind),
            m_string(std::move(z)) { }

    bool evaluate(Rule *rule, Transaction *transaction,
       std::shared_ptr<RuleMessage> rm) override;

    std::string data(Transaction *Transaction);

    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace actions
}  // namespace modsecurity

#endif  // SRC_ACTIONS_LOG_DATA_H_
