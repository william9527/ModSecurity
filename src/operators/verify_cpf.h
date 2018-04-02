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

#ifndef SRC_OPERATORS_VERIFY_CPF_H_
#define SRC_OPERATORS_VERIFY_CPF_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"
#include "src/utils/regex.h"


namespace modsecurity {
using Utils::SMatch;
using Utils::regex_search;
using Utils::Regex;

namespace operators {

class VerifyCPF : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Detects CPF numbers (Brazilian social number) in input. This operator
    will first use the supplied regular expression to perform an initial
    match, following up with an algorithm calculation to minimize false
    positives.
    \endverbatim


    Syntax

    \verbatim
    @verifyCPF regex
    \endverbatim


    Examples

    \verbatim
    Detect CPF numbers in parameters and prevent them from being logged to audit log
    = SecRule ARGS "@verifyCPF /^([0-9]{3}\.){2}[0-9]{3}-[0-9]{2}$/" "phase:2,id:195,nolog,pass,msg:'Potential CPF number',sanitiseMatched"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit VerifyCPF(std::unique_ptr<RunTimeString> param)
        : Operator("VerifyCPF", std::move(param)) {
        m_re = new Regex(m_param);
    }

    ~VerifyCPF() {
        delete m_re;
    }
    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string &input) override {
        return evaluate(transaction, NULL, input, NULL);
    }
    bool evaluate(Transaction *transaction,
        const std::string &input) override {
        return evaluate(transaction, NULL, input);
    }
    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string& input,
        std::shared_ptr<RuleMessage> ruleMessage) override;

    int convert_to_int(const char c);
    bool verify(const char *ssnumber, int len);

 private:
    Regex *m_re;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_VERIFY_CPF_H_
