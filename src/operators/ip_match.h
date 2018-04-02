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

#ifndef SRC_OPERATORS_IP_MATCH_H_
#define SRC_OPERATORS_IP_MATCH_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"
#include "src/utils/ip_tree.h"

namespace modsecurity {
namespace operators {

class IpMatch : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a fast ipv4 or ipv6 match of REMOTE_ADDR variable data. Can
    handle the following formats:

    - Full IPv4 Address - 192.168.1.100
    - Network Block/CIDR Address - 192.168.1.0/24
    - Full IPv6 Address - 2001:db8:85a3:8d3:1319:8a2e:370:7348
    - Network Block/CIDR Address - 2001:db8:85a3:8d3:1319:8a2e:370:0/24
    \endverbatim


    Syntax

    \verbatim
    @ipMatch ips separated by comma
    \endverbatim


    Examples

    \verbatim
    Individual Address:
    = SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:161"

    Multiple Addresses w/network block:
    = SecRule REMOTE_ADDR "@ipMatch 192.168.1.100,192.168.1.50,10.10.50.0/24" "id:162"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit IpMatch(std::unique_ptr<RunTimeString> param)
        : Operator("IpMatch", std::move(param)) { }
    IpMatch(std::string n, std::unique_ptr<RunTimeString> param)
        : Operator(n, std::move(param)) { }

    bool evaluate(Transaction *transaction, const std::string &input) override;

    bool init(const std::string &file, std::string *error) override;

 protected:
    Utils::IpTree m_tree;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_IP_MATCH_H_
