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

#ifndef SRC_OPERATORS_RX_H_
#define SRC_OPERATORS_RX_H_

#include <string>
#include <list>
#include <memory>
#include <utility>

#include "src/operators/operator.h"
#include "src/utils/regex.h"


namespace modsecurity {
using Utils::SMatch;
using Utils::regex_search;
using Utils::Regex;

namespace operators {


class Rx : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a regular expression match of the pattern provided
    as parameter. This is the default operator; the rules that do not
    explicitly specify an operator default to @rx.
    \endverbatim


    Syntax

    \verbatim
    @rx regular_expression
    \endverbatim


    Examples

    \verbatim
    Detect Nikto
    = SecRule REQUEST_HEADERS:User-Agent "@rx nikto" phase:1,id:173,t:lowercase

    Detect Nikto with a case-insensitive pattern
    = SecRule REQUEST_HEADERS:User-Agent "@rx (?i)nikto" phase:1,id:174,t:none

    Detect Nikto with a case-insensitive pattern
    = SecRule REQUEST_HEADERS:User-Agent "(?i)nikto" "id:175"
    \endverbatim


    Details

    \verbatim
    Regular expressions are handled by the PCRE library
    http://www.pcre.org. ModSecurity compiles its regular expressions with
    the following settings:

    - The entire input is treated as a single line, even when there are
    newline characters present.
    - All matches are case-sensitive. If you wish to perform
    case-insensitive matching, you can either use the lowercase
    transformation function or force case-insensitive matching by
    prefixing the regular expression pattern with the (?i) modifier (a
    PCRE feature; you will find many similar features in the PCRE
    documentation).
    - The PCRE_DOTALL and PCRE_DOLLAR_ENDONLY flags are set during
    compilation, meaning that a single dot will match any character,
    including the newlines, and a $ end anchor will not match a trailing
    newline character.
    - Regular expressions are a very powerful tool. You are strongly advised
    to read the PCRE documentation to get acquainted with its features.
    \endverbatim


    Notes

    \verbatim
    - This operator supports the "capture" action.
    \endverbatim

    */
 public:
    explicit Rx(std::unique_ptr<RunTimeString> param)
        : Operator("Rx", std::move(param)) {
            m_couldContainsMacro = true;
        }

    ~Rx() {
        if (m_string->m_containsMacro == false && m_re != NULL) {
            delete m_re;
            m_re = NULL;
        }
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

    bool init(const std::string &arg, std::string *error) override;

 private:
    Regex *m_re;
};


}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_RX_H_
