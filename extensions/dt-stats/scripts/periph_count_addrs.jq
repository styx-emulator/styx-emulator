.peripherals
| [.[] | select(.name | contains($PKIND))]
| sort_by(.occurrences)
