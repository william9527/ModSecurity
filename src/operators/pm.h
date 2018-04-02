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

#ifndef SRC_OPERATORS_PM_H_
#define SRC_OPERATORS_PM_H_

#include <string>
#include <list>
#include <memory>
#include <utility>

#include "src/operators/operator.h"
#include "src/utils/acmp.h"


namespace modsecurity {
namespace operators {


class Pm : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a case-insensitive match of the provided phrases against the
    desired input value. The operator uses a set-based matching algorithm
    (Aho-Corasick), which means that it will match any number of keywords
    in parallel. When matching of a large number of keywords is needed,
    this operator performs much better than a regular expression.
    \endverbatim


    Syntax

    \verbatim
    @pm string
    \endverbatim


    Examples

    \verbatim
    Detect suspicious client by looking at the user agent identification
    = SecRule REQUEST_HEADERS:User-Agent "@pm WebZIP WebCopier Webster WebStripper ... SiteSnagger ProWebWalker CheeseBot" "id:166"
    \endverbatim


    Details

    \verbatim
    \endverbatim


    Notes

    \verbatim
    - Starting on ModSecurity v2.6.0 this operator supports a snort/suricata
    content style. ie: "@pm A|42|C|44|F".
    - This operator does not support macro expansion (as of ModSecurity v2.9.1).
    - This operator supports the "capture" action.
    \endverbatim

    */
 public:
    /** @ingroup ModSecurity_Operator */
    explicit Pm(std::unique_ptr<RunTimeString> param)
        : Operator("Pm", std::move(param)) {
        m_p = acmp_create(0);
    }
    explicit Pm(std::string n, std::unique_ptr<RunTimeString> param)
        : Operator(n, std::move(param)) {
        m_p = acmp_create(0);
    }
    ~Pm();
    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string &str,
        std::shared_ptr<RuleMessage> ruleMessage) override;


    bool init(const std::string &file, std::string *error) override;
    void postOrderTraversal(acmp_btree_node_t *node);
    void cleanup(acmp_node_t *n);

 protected:
    ACMP *m_p;

#ifdef MODSEC_MUTEX_ON_PM

 private:
    pthread_mutex_t m_lock;
#endif
};


}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_PM_H_
