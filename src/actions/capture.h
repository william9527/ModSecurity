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

#ifndef SRC_ACTIONS_CAPTURE_H_
#define SRC_ACTIONS_CAPTURE_H_


namespace modsecurity {
class Rule;
namespace actions {


class Capture : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Non-disruptive

    \verbatim
    When used together with the regular expression operator (@rx), the capture
    action will create copies of the regular expression captures and place
    them into the transaction variable collection.

    Up to 10 captures will be copied on a successful pattern match, each with a
    name consisting of a digit from 0 to 9. The TX.0 variable always contains
    the entire area that the regular expression matched. All the other
    variables contain the captured values, in the order in which the capturing
    parentheses appear in the regular expression.
    \endverbatim

    Example

    \verbatim
    = SecRule REQUEST_BODY "^username=(\w{25,})" phase:2,capture,t:none,chain,id:105
  SecRule TX:1 "(?:(?:a(dmin|nonymous)))"
    \endverbatim

    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Capture(std::string action)
        : Action(action, RunTimeOnlyIfMatchKind) { }

    bool evaluate(Rule *rule, Transaction *transaction) override;
};


}  // namespace actions
}  // namespace modsecurity

#endif  // SRC_ACTIONS_CAPTURE_H_
