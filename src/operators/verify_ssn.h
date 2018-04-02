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

#ifndef SRC_OPERATORS_VERIFY_SSN_H_
#define SRC_OPERATORS_VERIFY_SSN_H_

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

class VerifySSN : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Detects US social security numbers (SSN) in input. This operator will
    first use the supplied regular expression to perform an initial match,
    following up with an SSN algorithm calculation to minimize false
    positives.
    \endverbatim


    Syntax

    \verbatim
    @verifySSN regex
    \endverbatim


    Examples

    \verbatim
    Detect social security numbers in parameters and
    prevent them from being logged to audit log
    = SecRule ARGS "@verifySSN \d{3}-?\d{2}-?\d{4}" "phase:2,id:196,nolog,pass,msg:'Potential social security number',sanitiseMatched"
    \endverbatim


    Details

    \verbatim
    A Social Security number is broken up into 3 sections:

    - Area (3 digits)
    - Group (2 digits)
    - Serial (4 digits)

    verifySSN checks:

    - Must have 9 digits
    - Cannot be a sequence number (ie,, 123456789, 012345678)
    - Cannot be a repetition sequence number ( ie 11111111 , 222222222)
    - Cannot have area and/or group and/or serial zeroed sequences
    - Area code must be less than 740
    - Area code must be different then 666
    \endverbatim


    Notes

    */
 public:
    explicit VerifySSN(std::unique_ptr<RunTimeString> param)
        : Operator("VerifySSN", std::move(param)) {
        m_re = new Regex(m_param);
    }

    ~VerifySSN() {
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


#endif  // SRC_OPERATORS_VERIFY_SSN_H_
