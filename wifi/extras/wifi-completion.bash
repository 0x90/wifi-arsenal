#!/bin/bash

_wifi()
{
  local cur opts
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"

  opts=$( COMP_CWORD=$COMP_CWORD \
          COMP_WORDS="${COMP_WORDS[*]}" \
          WIFI_AUTOCOMPLETE=1 \
          $1 )

  COMPREPLY=($(compgen -W "$opts" -- ${cur}))

  return 0
}

complete -F _wifi wifi
