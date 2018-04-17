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

#ifndef SRC_ACTIONS_SKIP_H_
#define SRC_ACTIONS_SKIP_H_

class Transaction;

namespace modsecurity {
class Transaction;
namespace actions {


class Skip : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Flow

    \verbatim
    Skips one or more rules (or chains) on successful match.

    The skip action works only within the current processing phase and not
    necessarily in the order in which the rules appear in the configuration
    file. If you place a phase 2 rule after a phase 1 rule that uses skip, it
    will not skip over the phase 2 rule. It will skip over the next phase 1
    rule that follows it in the phase.
    \endverbatim


    Example

    \verbatim
    # Require Accept header, but not from access from the localhost 
    = SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,skip:1,id:141" 

    # This rule will be skipped over when REMOTE_ADDR is 127.0.0.1 
    = SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,id:142,deny,msg:'Request Missing an Accept Header'"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Skip(std::string action)
        : Action(action, RunTimeOnlyIfMatchKind),
        m_skip_next(0) { }

    bool init(std::string *error) override;
    bool evaluate(Rule *rule, Transaction *transaction) override;

    int m_skip_next;
};


}  // namespace actions
}  // namespace modsecurity

#endif  // SRC_ACTIONS_SKIP_H_
