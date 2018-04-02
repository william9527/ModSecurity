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

#ifndef SRC_OPERATORS_CONTAINS_WORD_H_
#define SRC_OPERATORS_CONTAINS_WORD_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"
#include "modsecurity/rule_message.h"

namespace modsecurity {
namespace operators {

class ContainsWord : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Returns true if the parameter string (with word boundaries) is found
    anywhere in the input. Macro expansion is performed on the parameter
    string before comparison.
    \endverbatim


    Syntax

    \verbatim
    @containsWord string
    \endverbatim


    Examples

    \verbatim
    Detect "select" anywhere in ARGS
    = SecRule ARGS "@containsWord select" "id:151"
    \endverbatim


    Details

    \verbatim
    The example would match on: -1 union *select* BENCHMARK(2142500,MD5(CHAR(115,113,108,109,97,112))) FROM wp_users WHERE ID=1 and (ascii(substr(user_login,1,1))&0x01=0) from wp_users where ID=1--
    But not on:
    Your site has a wide *select*ion of computers.
    \endverbatim

    */
 public:
    explicit ContainsWord(std::unique_ptr<RunTimeString> param)
        : Operator("ContainsWord", std::move(param)) { }

    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string &str,
        std::shared_ptr<RuleMessage> ruleMessage) override;

    bool acceptableChar(const std::string& a, size_t pos);
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_CONTAINS_WORD_H_
