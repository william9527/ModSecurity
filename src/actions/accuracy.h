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

#ifndef SRC_ACTIONS_ACCURACY_H_
#define SRC_ACTIONS_ACCURACY_H_

class Transaction;

namespace modsecurity {
class Transaction;
namespace actions {


class Accuracy : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Meta-data

    \verbatim
    Specifies the relative accuracy level of the rule related to false
    positives/negatives. The value is a string based on a numeric scale (1-9
    where 9 is very strong and 1 has many false positives).
    \endverbatim

    Example

    \verbatim
    = SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
	"phase:2,ver:'CRS/2.2.4,accuracy:'9',maturity:'9',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
    \endverbatim

    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Accuracy(std::string action)
        : Action(action, ConfigurationKind),
        m_accuracy(0) { }

    bool evaluate(Rule *rule, Transaction *transaction) override;
    bool init(std::string *error) override;

 private:
    int m_accuracy;
};


}  // namespace actions
}  // namespace modsecurity

#endif  // SRC_ACTIONS_ACCURACY_H_
