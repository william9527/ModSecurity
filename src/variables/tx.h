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

#ifndef SRC_VARIABLES_TX_H_
#define SRC_VARIABLES_TX_H_

#include "src/variables/variable.h"
#include "src/run_time_string.h"

namespace modsecurity {

class Transaction;
namespace Variables {


class Tx_DictElement : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: TX

    \verbatim
    This is the transient transaction collection, which is used to store pieces
    of data, create a transaction anomaly score, and so on. The variables
    placed into this collection are available only until the transaction is
    complete.

    = # Increment transaction attack score on attack
    = SecRule ARGS attack "phase:2,id:82,nolog,pass,setvar:TX.score=+5"

    = # Block the transactions whose scores are too high
    = SecRule TX:SCORE "@gt 20" "phase:2,id:83,log,deny"

    Some variable names in the TX collection are reserved and cannot be used:

    - TX:0: the matching value when using the @rx or @pm operator with the capture action
    - TX:1-TX:9: the captured subexpression value when using the @rx operator with capturing parens and the capture action
    - TX:MSC_.*: ModSecurity processing flags
    - MSC_PCRE_LIMITS_EXCEEDED: Set to nonzero if PCRE match limits are exceeded. See SecPcreMatchLimit and SecPcreMatchLimitRecursion for more information.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Tx_DictElement(std::string dictElement)
        : Variable("TX:" + dictElement),
        m_dictElement(dictElement) { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        t->m_collections.m_tx_collection->resolveMultiMatches(
            m_dictElement, l);
    }

    std::string m_dictElement;
};


class Tx_NoDictElement : public Variable {
 public:
    Tx_NoDictElement()
        : Variable("TX") { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        t->m_collections.m_tx_collection->resolveMultiMatches("", l);
    }
};


class Tx_DictElementRegexp : public Variable {
 public:
    explicit Tx_DictElementRegexp(std::string dictElement)
        : Variable("TX:regex(" + dictElement + ")"),
        m_r(dictElement),
        m_dictElement(dictElement) { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        t->m_collections.m_tx_collection->resolveRegularExpression(
            m_dictElement, l);
    }

    Utils::Regex m_r;
    std::string m_dictElement;
};


class Tx_DynamicElement : public Variable {
 public:
    explicit Tx_DynamicElement(std::unique_ptr<RunTimeString> dictElement)
        : Variable("TX:dynamic"),
        m_string(std::move(dictElement)) { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        std::string string = m_string->evaluate(t);
        t->m_collections.m_tx_collection->resolveMultiMatches(string, l);
    }

    void del(Transaction *t, std::string k) {
        t->m_collections.m_tx_collection->del(k);
    }

    void storeOrUpdateFirst(Transaction *t, std::string var,
        std::string value) {
        t->m_collections.m_tx_collection->storeOrUpdateFirst(var, value);
    }

    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_TX_H_
