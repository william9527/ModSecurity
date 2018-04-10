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

#ifndef SRC_VARIABLES_GEO_H_
#define SRC_VARIABLES_GEO_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class Geo_DictElement : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: GEO

    \verbatim
    GEO is a collection populated by the results of the last @geoLookup
    operator. The collection can be used to match geographical fields
    looked from an IP address or hostname.

    Fields:

    - COUNTRY_CODE: Two character country code. EX: US, GB, etc.
    - COUNTRY_CODE3: Up to three character country code.
    - COUNTRY_NAME: The full country name.
    - COUNTRY_CONTINENT: The two character continent that the country is located. EX: EU
    - REGION: The two character region. For US, this is state. For Canada, providence, etc.
    - CITY: The city name if supported by the database.
    - POSTAL_CODE: The postal code if supported by the database.
    - LATITUDE: The latitude if supported by the database.
    - LONGITUDE: The longitude if supported by the database.
    - DMA_CODE: The metropolitan area code if supported by the database. (US only)
    - AREA_CODE: The phone system area code. (US only)

    = SecGeoLookupDb /usr/local/geo/data/GeoLiteCity.dat
    = SecRule REMOTE_ADDR "@geoLookup" "chain,id:22,drop,msg:'Non-GB IP address'"
    = SecRule GEO:COUNTRY_CODE "!@streq GB"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Geo_DictElement(std::string dictElement)
        : Variable("GEO" + std::string(":") +
            std::string(dictElement)),
        m_dictElement(dictElement) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableGeo.resolve(m_dictElement, l);
    }

    std::string m_dictElement;
};


class Geo_NoDictElement : public Variable {
 public:
    Geo_NoDictElement()
        : Variable("GEO") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableGeo.resolve(l);
    }
};


class Geo_DictElementRegexp : public Variable {
 public:
    explicit Geo_DictElementRegexp(std::string dictElement)
        : Variable("GEO:regex(" + dictElement + ")"),
        m_r(dictElement) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableGeo.resolveRegularExpression(
            &m_r, l);
    }

    Utils::Regex m_r;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_GEO_H_

