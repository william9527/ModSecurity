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

#ifndef SRC_OPERATORS_VALIDATE_UTF8_ENCODING_H_
#define SRC_OPERATORS_VALIDATE_UTF8_ENCODING_H_

#include <string>
#include <memory>

#include "src/operators/operator.h"


#define UNICODE_ERROR_CHARACTERS_MISSING    -1
#define UNICODE_ERROR_INVALID_ENCODING      -2
#define UNICODE_ERROR_OVERLONG_CHARACTER    -3
#define UNICODE_ERROR_RESTRICTED_CHARACTER  -4
#define UNICODE_ERROR_DECODING_ERROR        -5


namespace modsecurity {
namespace operators {

class ValidateUtf8Encoding : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Check whether the input is a valid UTF-8 string.
    \endverbatim


    Syntax

    \verbatim
    @validateUtf8Encoding
    \endverbatim


    Examples

    \verbatim
    Make sure all request parameters contain only valid UTF-8
    = SecRule ARGS "@validateUtf8Encoding" "id:193"
    \endverbatim


    Details

    \verbatim
    The @validateUtf8Encoding operator detects the following problems:

    - Not enough bytes : UTF-8 supports two-, three-, four-, five-, and
    six-byte encodings. ModSecurity will locate cases when one or more
    bytes is/are missing from a character.
    - Invalid characters : The two most significant bits in most characters
    should be fixed to 0x80. Some attack techniques use different values
    as an evasion technique.
    - Overlong characters : ASCII characters are mapped directly into UTF-8,
    which means that an ASCII character is one UTF-8 character at the same
    time. However, in UTF-8 many ASCII characters can also be encoded with
    two, three, four, five, and six bytes. This is no longer legal in the
    newer versions of Unicode, but many older implementations still
    support it. The use of overlong UTF-8 characters is common for
    evasion.
    \endverbatim


    Notes

    \verbatim
    - Most, but not all applications use UTF-8. If you are dealing with an
    application that does, validating that all request parameters are
    valid UTF-8 strings is a great way to prevent a number of evasion
    techniques that use the assorted UTF-8 weaknesses. False positives
    are likely if you use this operator in an application that does not
    use UTF-8.
    - Many web servers will also allow UTF-8 in request URIs. If yours does,
    you can verify the request URI using @validateUtf8Encoding.
    \endverbatim

    */
 public:
    ValidateUtf8Encoding()
        : Operator("ValidateUtf8Encoding") { }

    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string &str,
        std::shared_ptr<RuleMessage> ruleMessage) override;

    int detect_utf8_character(const unsigned char *p_read,
        unsigned int length);
};

}  // namespace operators
}  // namespace modsecurity



#endif  // SRC_OPERATORS_VALIDATE_UTF8_ENCODING_H_
