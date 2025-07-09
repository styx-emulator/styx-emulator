#!/bin/bash

# Source this file  to define the functions below


tjson_functions() {
    cat rust/testdata/connect_message.json | jq .program.functions | jq .[] | jq -c .[] | grep last_insn | jq '
        {name: .name,
         address: .address,
         data_size: .data_size,
         last_insn: .function_symbol.last_insn
         }' -c

}



tjson_symbols() {
  cat rust/testdata/connect_message.json | \
  jq '.symbols | .[] | {id,name,address,datatype_name,data_size}' -c
}

tjson_datatypes() {
  cat rust/testdata/connect_message.json | jq -c '
    .data_types | .[]' -c
}

typeset -f | grep "^tjson_"

cat << EOF
Hints:
  Symbols with size: tjson_symbols  | jq 'select(.data_size > 0)' -c
EOF
