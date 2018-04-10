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

#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <utility>

#ifndef SRC_VARIABLES_TIME_H_
#define SRC_VARIABLES_TIME_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class Time : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: TIME

    \verbatim
    This variable holds a formatted string representing the time (hour:minute:second).

    = SecRule TIME "^(([1](8|9))|([2](0|1|2|3))):\d{2}:\d{2}$" "id:74"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Time(std::string _name)
        : Variable(_name),
        m_retName("TIME") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override;
    std::string m_retName;
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_TIME_H_
