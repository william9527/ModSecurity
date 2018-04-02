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

#ifndef SRC_OPERATORS_GEO_LOOKUP_H_
#define SRC_OPERATORS_GEO_LOOKUP_H_

#include <string>

#include "src/operators/operator.h"


namespace modsecurity {
namespace operators {

class GeoLookup : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a geolocation lookup using the IP address in input against the
    geolocation database previously configured using SecGeoLookupDb. If the
    lookup is successful, the obtained information is captured in the GEO
    collection.
    \endverbatim

    Syntax


    \verbatim
    SecGeoLookupDb /path/to/GeoLiteCity.dat
    @geoLookup
    \endverbatim


    Examples

    \verbatim
    Configure geolocation database
    = SecGeoLookupDb /path/to/GeoLiteCity.dat

    Lookup IP address
    = SecRule REMOTE_ADDR "@geoLookup" "phase:1,id:155,nolog,pass"

    Block IP address for which geolocation failed
    = SecRule &GEO "@eq 0" "phase:1,id:156,deny,msg:'Failed to lookup IP'"
    \endverbatim


    Details

    \verbatim
    See the GEO variable for an example and more information on various
    fields available.
    \endverbatim

    */
 public:
    GeoLookup()
        : Operator("GeoLookup") { }
    bool evaluate(Transaction *transaction, const std::string &exp) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_GEO_LOOKUP_H_
