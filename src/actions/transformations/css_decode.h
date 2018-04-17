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

#ifndef SRC_ACTIONS_TRANSFORMATIONS_CSS_DECODE_H_
#define SRC_ACTIONS_TRANSFORMATIONS_CSS_DECODE_H_

#ifdef __cplusplus
namespace modsecurity {
class Transaction;

namespace actions {
namespace transformations {


class CssDecode : public Transformation {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Transformation

    \verbatim
    Decodes characters encoded using the CSS 2.x escape rules
    syndata.html#characters. This function uses only up to two bytes in the
    decoding process, meaning that it is useful to uncover ASCII characters
    encoded using CSS encoding (that wouldn’t normally be encoded), or to
    counter evasion, which is a combination of a backslash and non-hexadecimal
    characters (e.g., ja\vascript is equivalent to javascript).
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit CssDecode(std::string action)
        : Transformation(action) { }
    std::string evaluate(std::string exp,
        Transaction *transaction) override;

    static int css_decode_inplace(unsigned char *input, int64_t input_len);
};


}  // namespace transformations
}  // namespace actions
}  // namespace modsecurity

#endif

#endif  // SRC_ACTIONS_TRANSFORMATIONS_CSS_DECODE_H_
