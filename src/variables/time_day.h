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

#include <vector>
#include <string>
#include <list>
#include <utility>

#ifndef SRC_VARIABLES_TIME_DAY_H_
#define SRC_VARIABLES_TIME_DAY_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class TimeDay : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: TIME_DAY

    \verbatim
    This variable holds the current date (1–31). The following rule triggers
    on a transaction that’s happening anytime between the 10th and 20th in a
    month:

    = SecRule TIME_DAY "^(([1](0|1|2|3|4|5|6|7|8|9))|20)$" "id:75"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit TimeDay(std::string _name)
        : Variable(_name),
        m_retName("TIME_DAY") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override;
    std::string m_retName;
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_TIME_DAY_H_
