// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/extract.h>

#include <script/script.h>

namespace roster {

bool ExtractOpReturnPayload(const CScript& script, std::vector<unsigned char>& out)
{
    if (script.empty() || script[0] != OP_RETURN) return false;

    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, out)) return false;

    // Must be a data push rather than an opcode, and must be the last thing in
    // the script. Anything looser would give one record several valid script
    // encodings, reintroducing at this layer the malleability the record
    // parser refuses at its own.
    if (opcode > OP_PUSHDATA4) return false;
    return pc == script.end();
}

} // namespace roster
