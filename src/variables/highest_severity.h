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

#ifndef SRC_VARIABLES_HIGHEST_SEVERITY_H_
#define SRC_VARIABLES_HIGHEST_SEVERITY_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class HighestSeverity : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: HIGHEST_SEVERITY

    \verbatim
    This variable holds the highest severity of any rules that have matched so
    far. Severities are numeric values and thus can be used with comparison
    operators such as @lt, and so on. A value of 255 indicates that no severity
    has been set.

    = SecRule HIGHEST_SEVERITY "@le 2" "phase:2,id:23,deny,status:500,msg:'severity %{HIGHEST_SEVERITY}'"

    Note: Higher severities have a lower numeric value.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit HighestSeverity(std::string _name)
        : Variable(_name),
        m_retName("HIGHEST_SEVERITY") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override;
    std::string m_retName;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_HIGHEST_SEVERITY_H_
