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
#include "src/actions/transformations/transformation.h"

#ifndef SRC_ACTIONS_TRANSFORMATIONS_CMD_LINE_H_
#define SRC_ACTIONS_TRANSFORMATIONS_CMD_LINE_H_

#ifdef __cplusplus
namespace modsecurity {
class Transaction;

namespace actions {
namespace transformations {

class CmdLine : public Transformation {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Transformation

    \verbatim
    In Windows and Unix, commands may be escaped by different means, such as:

    - c^ommand /c ...
    - "command" /c ...
    - command,/c ...
    - backslash in the middle of a Unix command

    The cmdLine transformation function avoids this problem by manipulating the
    variable contend in the following ways:

    - deleting all backslashes [\]
    - deleting all double quotes ["]
    - deleting all sigle quotes [']
    - deleting all carets [^]
    - deleting spaces before a slash /
    - deleting spaces before an open parentesis [(]
    - replacing all commas [,] and semicolon [;] into a space
    - replacing all multiple spaces (including tab, newline, etc.) into one space
    - transform all characters to lowercase

    = SecRule ARGS "(?:command(?:.com)?|cmd(?:.exe)?)(?:/.*)?/[ck]" "phase:2,id:94,t:none, t:cmdLine"

    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit CmdLine(std::string action)
        : Transformation(action) { }

    std::string evaluate(std::string exp,
        Transaction *transaction) override;
};

}  // namespace transformations
}  // namespace actions
}  // namespace modsecurity

#endif

#endif  // SRC_ACTIONS_TRANSFORMATIONS_CMD_LINE_H_

