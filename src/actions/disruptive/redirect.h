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
#include "modsecurity/rule_message.h"
#include "src/run_time_string.h"

#ifndef SRC_ACTIONS_DISRUPTIVE_REDIRECT_H_
#define SRC_ACTIONS_DISRUPTIVE_REDIRECT_H_

#ifdef __cplusplus
class Transaction;

namespace modsecurity {
class Transaction;

namespace actions {
namespace disruptive {


class Redirect : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Disruptive

    \verbatim
    Intercepts transaction by issuing an external (client-visible) redirection
    to the given location.

    If the status action is present on the same rule, and its value can be used
    for a redirection (i.e., is one of the following: 301, 302, 303, or 307),
    the value will be used for the redirection status code. Otherwise, status
    code 302 will be used.
    \endverbatim


    Example

    \verbatim
    = SecRule REQUEST_HEADERS:User-Agent "Test" "phase:1,id:130,log,redirect:http://www.example.com/failed.html"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Redirect(const std::string &action)
        : Action(action, RunTimeOnlyIfMatchKind),
        m_status(0) { }

    explicit Redirect(std::unique_ptr<RunTimeString> z)
        : Action("redirert", RunTimeOnlyIfMatchKind),
            m_string(std::move(z)) { }

    bool evaluate(Rule *rule, Transaction *transaction,
        std::shared_ptr<RuleMessage> rm) override;
    bool init(std::string *error) override;
    bool isDisruptive() override { return true; }

 private:
    int m_status;
    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace disruptive
}  // namespace actions
}  // namespace modsecurity
#endif

#endif  // SRC_ACTIONS_DISRUPTIVE_REDIRECT_H_
