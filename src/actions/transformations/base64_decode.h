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

#ifndef SRC_ACTIONS_TRANSFORMATIONS_BASE64_DECODE_H_
#define SRC_ACTIONS_TRANSFORMATIONS_BASE64_DECODE_H_

#ifdef __cplusplus
namespace modsecurity {
class Transaction;

namespace actions {
namespace transformations {

class Base64Decode : public Transformation {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Transformation

    \verbatim
    Decodes a Base64-encoded string.

    Note: Be careful when applying base64Decode with other transformations. The order of your transformation matters in this case as certain transformations may change or invalidate the base64 encoded string prior to being decoded (i.e t:lowercase, etc). This of course means that it is also very difficult to write a single rule that checks for a base64decoded value OR an unencoded value with transformations, it is best to write two rules in this situation.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Base64Decode(std::string action) : Transformation(action) { }

    std::string evaluate(std::string exp,
        Transaction *transaction) override;
};

}  // namespace transformations
}  // namespace actions
}  // namespace modsecurity

#endif

#endif  // SRC_ACTIONS_TRANSFORMATIONS_BASE64_DECODE_H_
