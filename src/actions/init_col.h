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
#include <utility>
#include <memory>

#include "modsecurity/actions/action.h"
#include "src/run_time_string.h"

#ifndef SRC_ACTIONS_INIT_COL_H_
#define SRC_ACTIONS_INIT_COL_H_

class Transaction;

namespace modsecurity {
class Transaction;
namespace actions {


class InitCol : public Action {
    /** @ingroup  ModSecurity_RefManual */
    /**

    Description

    Group: Non-disruptive

    \verbatim
    Initializes a named persistent collection, either by loading data from
    storage or by creating a new collection in memory.

    Collections are loaded into memory on-demand, when the initcol action is
    executed. A collection will be persisted only if a change was made to it
    in the course of transaction processing.
    \endverbatim


    Example

    \verbatim
    The following example initiates IP address tracking, which is best done in phase 1:
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit InitCol(std::string action) : Action(action) { }

    InitCol(std::string action, std::unique_ptr<RunTimeString> z)
        : Action(action, RunTimeOnlyIfMatchKind),
            m_string(std::move(z)) { }

    bool evaluate(Rule *rule, Transaction *transaction) override;
    bool init(std::string *error) override;
 private:
    std::string m_collection_key;
    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace actions
}  // namespace modsecurity

#endif  // SRC_ACTIONS_INIT_COL_H_
