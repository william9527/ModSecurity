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

#ifndef SRC_ACTIONS_RULE_ID_H_
#define SRC_ACTIONS_RULE_ID_H_

#ifdef __cplusplus
class Transaction;

namespace modsecurity {
class Transaction;
class Rule;

namespace actions {


class RuleId : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Meta-data

    \verbatim
    Assigns a unique ID to the rule or chain in which it appears

    These are the reserved ranges:

    - 1–99,999: reserved for local (internal) use. Use as you see fit, but do not use this range for rules that are distributed to others
    - 100,000–199,999: reserved for rules published by Oracle
    - 200,000–299,999: reserved for rules published Comodo
    - 300,000–399,999: reserved for rules published at gotroot.com
    - 400,000–419,999: unused (available for reservation)
    - 420,000–429,999: reserved for ScallyWhack http://projects.otaku42.de/wiki/Scally-Whack
    - 430,000–439,999: reserved for rules published by Flameeyes http://www.flameeyes.eu/projects/modsec
    - 440.000-599,999: unused (available for reservation)
    - 600,000-699,999: reserved for use by Akamai http://www.akamai.com/html/solutions/waf.html
    - 700,000–799,999: reserved for Ivan Ristic
    - 900,000–999,999: reserved for the OWASP ModSecurity Core Rule Set http://www.owasp.org/index.php/    - Category:OWASP_ModSecurity_Core_Rule_Set_Project project
    - 1,000,000-1,009,999: reserved for rules published by Redhat Security Team
    - 1,010,000-1,999,999: unused (available for reservation)
    - 2,000,000-2,999,999: reserved for rules from Trustwave's SpiderLabs Research team
    - 3,000,000-3,999,999: reserved for use by Akamai http://www.akamai.com/html/solutions/waf.html
    - 4,000,000-4,099,999 reserved: in use by AviNetworks https://kb.avinetworks.com/docs/latest/vantage-web-app-firewall-beta/
    - 4,100,000-4,199,999 reserved: in use by Fastly https://www.fastly.com/products/cloud-security/#products-cloud-security-web-application-firewall
    - 4,200,000-19,999,999: unused (available for reservation)
    - 20,000,000-21,999,999: reserved for rules from Trustwave's SpiderLabs Research team
    - 22,000,000 and above: unused (available for reservation)
    \endverbatim


    Example

    \verbatim
    = SecRule &REQUEST_HEADERS:Host "@eq 0" "log,id:60008,severity:2,msg:'Request Missing a Host Header'"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit RuleId(std::string action)
        : Action(action, ConfigurationKind),
        m_ruleId(0) { }

    bool init(std::string *error) override;
    bool evaluate(Rule *rule, Transaction *transaction) override;

 private:
    double m_ruleId;
};

}  // namespace actions
}  // namespace modsecurity
#endif

#endif  // SRC_ACTIONS_RULE_ID_H_
