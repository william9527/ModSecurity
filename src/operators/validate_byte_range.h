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

#ifndef SRC_OPERATORS_VALIDATE_BYTE_RANGE_H_
#define SRC_OPERATORS_VALIDATE_BYTE_RANGE_H_

#include <string>
#include <vector>
#include <cstring>
#include <memory>
#include <utility>

#include "src/operators/operator.h"


namespace modsecurity {
namespace operators {

class ValidateByteRange : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Validates that the byte values used in input fall into the range
    specified by the operator parameter. This operator matches on an
    input value that contains bytes that are not in the specified
    range.

    The validateByteRange is most useful when used to detect the presence
    of NUL bytes, which don’t have a legitimate use, but which are often
    used as an evasion technique.
    \endverbatim


    Syntax

    \verbatim
    @le integer
    \endverbatim


    Examples

    \verbatim
    Enforce very strict byte range for request parameters (only
    works for the applications that do not use the languages other
    than English).
    = SecRule ARGS "@validateByteRange 10, 13, 32-126" "id:178"

    Do not allow NULL bytes
    = SecRule ARGS "@validateByteRange 1-255" "id:179"
    \endverbatim


    Details

    \verbatim
    \endverbatim


    Notes

    \verbatim
    - You can force requests to consist only of bytes from a certain byte
    range. This can be useful to avoid stack overflow attacks (since they
    usually contain "random" binary content). Default range values are 0
    and 255, i.e. all byte values are allowed. This directive does not check
    byte range in a POST payload when multipart/form-data encoding (file
    upload) is used. Doing so would prevent binary files from being
    uploaded. However, after the parameters are extracted from such request
    they are checked for a valid range.
    \endverbatim

    */
 public:
    explicit ValidateByteRange(std::unique_ptr<RunTimeString> param)
        : Operator("ValidadeByteRange", std::move(param)) {
            std::memset(table, '\0', sizeof(char) * 32);
        }
    ~ValidateByteRange() override { }

    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string &input,
        std::shared_ptr<RuleMessage> ruleMessage) override;
    bool getRange(const std::string &rangeRepresentation, std::string *error);
    bool init(const std::string& file, std::string *error) override;
 private:
    std::vector<std::string> ranges;
    char table[32];
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_VALIDATE_BYTE_RANGE_H_
